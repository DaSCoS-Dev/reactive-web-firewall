#!/usr/bin/env perl
# Copyright (C) 2026 Daniele Stefano Continenza <daniele@dascos.info>
# SPDX-License-Identifier: AGPL-3.0-or-later

use strict;
use warnings;
use Getopt::Long qw(GetOptions);
use Socket qw(AF_INET AF_INET6 inet_pton);
use Time::HiRes qw(time clock_gettime CLOCK_MONOTONIC CLOCK_REALTIME);
use File::Path qw(make_path);
use File::Basename qw(dirname);
use Fcntl qw(:flock);

my $BUILD = 'reactive-web-firewall-0.3.0-modular-rules';

my $config_file = $ENV{RWF_CONFIG} || '/etc/reactive-web-firewall/reactive-web-firewall.conf';
my $core_file = '/usr/local/lib/reactive-web-firewall/core.pm';

my $test_file = '';
my $test_line = '';
my $dry_run = 0;
my $show_help = 0;
my $show_version = 0;
my $show_config = 0;
my $validate_config = 0;
my $list_rules = 0;
my $list_state = 0;
my $forget_ip = '';
my $unban_ip = '';

GetOptions(
    'config=s' => \$config_file,
    'core=s' => \$core_file,
    'test-file=s' => \$test_file,
    'test-line=s' => \$test_line,
    'dry-run' => \$dry_run,
    'show-config' => \$show_config,
    'validate-config' => \$validate_config,
    'list-rules' => \$list_rules,
    'list-state' => \$list_state,
    'forget=s' => \$forget_ip,
    'unban=s' => \$unban_ip,
    'version' => \$show_version,
    'help' => \$show_help,
) or die "Parametri non validi. Usa --help\n";

if ($show_version) { print "$BUILD\n"; exit 0; }

if ($show_help) {
    print <<'HELP';
Uso:
  reactive-web-ban.pl
  reactive-web-ban.pl --validate-config
  reactive-web-ban.pl --list-rules
  reactive-web-ban.pl --test-line 'riga Apache completa'
  reactive-web-ban.pl --test-file /percorso/log
  reactive-web-ban.pl --show-config
  reactive-web-ban.pl --list-state
  reactive-web-ban.pl --forget IP
  reactive-web-ban.pl --unban IP

Configurazione centrale:
  /etc/reactive-web-firewall/reactive-web-firewall.conf

Moduli delle firme:
  /etc/reactive-web-firewall/rules.d/*.pm

Validazione completa dopo una modifica:
  sudo reactive-web-validate

Le policy e i moduli delle regole vengono ricaricati automaticamente quando
cambiano. Per modifiche a percorsi, SSH, packet ring o porte eseguire anche:
  sudo reactive-web-apply
HELP
    exit 0;
}

-f $core_file or die "Core non trovato: $core_file\n";
require $core_file;
for my $name (qw(parse_apache_line normalize_request_uri decode_uri_for_detection)) {
    no strict 'refs';
    defined &{$name} or die "Funzione $name non trovata in $core_file\n";
}

# Runtime settings. Values are replaced atomically only after successful validation.
my $log_file = '/var/log/apache2/reactive_web_access.log';
my $rules_directory = '/etc/reactive-web-firewall/rules.d';
my $allow_file = '/etc/reactive-web-firewall/allowlist';
my $state_file = '/var/lib/reactive-web-firewall/active.tsv';
my $active_dir = '/run/reactive-web-firewall/active';
my $tail_sleep = '0.1';
my $logger_tag = 'reactive-web-ban';
my $ssh_key = '/etc/reactive-web-firewall/keys/firewall_ed25519';
my $known_hosts = '/etc/reactive-web-firewall/keys/known_hosts';
my $firewall = 'root@192.0.2.1';
my $firewall_port = 22;
my $ssh_connect_timeout = 2;
my $ssh_control_persist = 600;
my $ssh_control_path = '/run/reactive-web-firewall/ssh-%C';
my $remote_host_label = 'proxy';
my $duplicate_suppress_seconds = 90;
my $local_fastban_enabled = 1;
my $local_fastban_timeout_seconds = 300;
my $local_fastban_nft = '/usr/sbin/nft';
my $local_fastban_table = 'reactive_web_fastban';
my $local_fastban_helper = '/usr/local/sbin/reactive-web-fastban';
my $local_socket_kill = 1;
my $local_socket_post_sweep = 1;
my @local_socket_ports = (80, 443);

my @rule_modules;
my %rule_by_name;
my %policy;
my $runtime_fingerprint = '';
my $last_reload_error = '';
my %allow;
my $allow_mtime = -1;
my $last_cleanup = 0;

sub logmsg {
    my ($level, $message) = @_;
    $level ||= 'notice';
    $message ||= '';
    system('logger', '-p', "user.$level", '-t', $logger_tag, '--', $message);
    if ($test_file ne '' || $test_line ne '' || $dry_run || $show_config || $validate_config || $list_rules || $list_state) {
        print STDERR "$logger_tag\[$level\]: $message\n";
    }
}

sub valid_ip {
    my ($ip) = @_;
    return 0 unless defined $ip && $ip ne '';
    return 1 if inet_pton(AF_INET, $ip);
    return 1 if inet_pton(AF_INET6, $ip);
    return 0;
}

sub parse_duration {
    my ($raw) = @_;
    $raw = '' unless defined $raw;
    $raw =~ s/^\s+|\s+$//g;
    my $v = lc($raw);
    return { enabled=>0, permanent=>0, seconds=>0, label=>'off' }
        if $v eq '' || $v eq '0' || $v eq 'off' || $v eq 'disabled' || $v eq 'no';
    return { enabled=>1, permanent=>1, seconds=>0, label=>'permanent' }
        if $v eq '1' || $v eq 'permanent' || $v eq 'perm' || $v eq 'forever';
    if ($v =~ /^(\d+)([smhdw]?)$/) {
        my ($n,$unit)=($1,$2);
        die "Durata non valida: $raw\n" if $n <= 0;
        my %mult=(''=>1,s=>1,m=>60,h=>3600,d=>86400,w=>604800);
        return { enabled=>1, permanent=>0, seconds=>$n*$mult{$unit}, label=>$v };
    }
    die "Durata non valida: $raw\n";
}

sub parse_bool {
    my ($raw,$name)=@_;
    $raw='' unless defined $raw;
    $raw =~ s/^\s+|\s+$//g;
    my $v=lc($raw);
    return 1 if $v =~ /^(?:1|yes|true|on|enabled)$/;
    return 0 if $v =~ /^(?:0|no|false|off|disabled)$/;
    die "$name non valido: $raw\n";
}

sub parse_port_list {
    my ($raw,$name)=@_;
    $name ||= 'ports';
    my @ports;
    for my $part (split(/[,\s]+/, $raw // '')) {
        next if $part eq '';
        die "$name: porta non valida $part\n" unless $part =~ /^\d+$/ && $part >= 1 && $part <= 65535;
        push @ports, 0+$part;
    }
    die "$name non può essere vuoto\n" unless @ports;
    my %seen; return grep { !$seen{$_}++ } @ports;
}

sub read_config_raw {
    my ($path)=@_;
    -r $path or die "Configurazione non leggibile: $path\n";
    open(my $fh,'<',$path) or die "Impossibile leggere $path: $!\n";
    my %raw; my $line_no=0;
    while (my $line=<$fh>) {
        $line_no++;
        chomp($line); $line =~ s/\r$//;
        next if $line =~ /^\s*(?:#|$)/;
        my ($key,$value) = $line =~ /^\s*([A-Za-z][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$/;
        die "$path:$line_no: sintassi non valida\n" unless defined $key;
        $key=lc($key);
        die "$path:$line_no: chiave duplicata $key\n" if exists $raw{$key};
        $raw{$key}=$value;
    }
    close($fh);
    return \%raw;
}

sub cfg_value {
    my ($raw,$key,$default)=@_;
    return exists $raw->{$key} ? $raw->{$key} : $default;
}

sub rule_files {
    my ($dir)=@_;
    -d $dir or die "Directory regole non trovata: $dir\n";
    opendir(my $dh,$dir) or die "Impossibile aprire $dir: $!\n";
    my @files = sort map { "$dir/$_" } grep { /\.pm$/ && -f "$dir/$_" } readdir($dh);
    closedir($dh);
    die "Nessun modulo .pm trovato in $dir\n" unless @files;
    return @files;
}

sub module_fingerprint {
    my ($config,$dir)=@_;
    my @paths=($config,rule_files($dir));
    return join('|', map { my @s=stat($_); $_ . ':' . ($s[1]||0) . ':' . ($s[9]||0) . ':' . ($s[7]||0) } @paths);
}

sub load_rule_modules {
    my ($dir)=@_;
    my @loaded; my %names;
    for my $file (rule_files($dir)) {
        my $def = do $file;
        die "Errore caricando $file: $@\n" if $@;
        die "Errore leggendo $file: $!\n" unless defined $def;
        die "$file deve restituire un hash reference\n" unless ref($def) eq 'HASH';
        for my $field (qw(name description priority default_policy detect)) {
            die "$file: campo obbligatorio mancante: $field\n" unless exists $def->{$field};
        }
        die "$file: name non valido\n" unless $def->{name} =~ /^[a-z][a-z0-9_]*$/;
        die "$file: name duplicato $def->{name}\n" if $names{$def->{name}}++;
        die "$file: priority deve essere intera\n" unless $def->{priority} =~ /^-?\d+$/;
        die "$file: detect deve essere una funzione\n" unless ref($def->{detect}) eq 'CODE';
        parse_duration($def->{default_policy});
        $def->{source_file}=$file;
        push @loaded,$def;
    }
    @loaded = sort { $a->{priority} <=> $b->{priority} || $a->{name} cmp $b->{name} } @loaded;
    return @loaded;
}

sub build_runtime {
    my ($raw,$rules)=@_;
    my %known = map { $_=>1 } qw(
        apache_log_file apache_log_rotate_frequency apache_log_rotate_count rules_directory allowlist_file state_file active_directory
        tail_sleep logger_tag firewall_host firewall_port firewall_user ssh_key
        known_hosts ssh_connect_timeout ssh_control_persist ssh_control_path remote_host_label
        local_fastban_enabled local_fastban_timeout local_fastban_ports
        local_fastban_table local_fastban_priority local_socket_kill
        local_socket_post_sweep local_socket_ports duplicate_suppress
        packet_ring_enabled packet_ring_interface packet_ring_snaplen
        packet_ring_buffer_kb packet_ring_file_size_mb packet_ring_file_count
        packet_ring_directory packet_ring_basename packet_ring_filter report_output_directory
    );
    $known{'policy_'.$_->{name}}=1 for @$rules;
    for my $key (keys %$raw) { die "Chiave di configurazione sconosciuta: $key\n" unless $known{$key}; }

    my %r;
    $r{log_file}=cfg_value($raw,'apache_log_file','/var/log/apache2/reactive_web_access.log');
    $r{rules_directory}=cfg_value($raw,'rules_directory','/etc/reactive-web-firewall/rules.d');
    $r{allow_file}=cfg_value($raw,'allowlist_file','/etc/reactive-web-firewall/allowlist');
    $r{state_file}=cfg_value($raw,'state_file','/var/lib/reactive-web-firewall/active.tsv');
    $r{active_dir}=cfg_value($raw,'active_directory','/run/reactive-web-firewall/active');
    $r{tail_sleep}=cfg_value($raw,'tail_sleep','0.1');
    die "tail_sleep non valido\n" unless $r{tail_sleep} =~ /^\d+(?:\.\d+)?$/ && $r{tail_sleep} > 0 && $r{tail_sleep} <= 5;
    $r{logger_tag}=cfg_value($raw,'logger_tag','reactive-web-ban');
    die "logger_tag non valido\n" unless $r{logger_tag} =~ /^[A-Za-z0-9_.-]+$/;

    my $host=cfg_value($raw,'firewall_host','192.0.2.1');
    my $user=cfg_value($raw,'firewall_user','root');
    die "firewall_host non valido\n" unless $host =~ /^[A-Za-z0-9_.:-]+$/;
    die "firewall_user non valido\n" unless $user =~ /^[A-Za-z_][A-Za-z0-9_-]*$/;
    $r{firewall}=($host =~ /:/) ? "$user\@[$host]" : "$user\@$host";
    $r{firewall_port}=0+cfg_value($raw,'firewall_port',22);
    die "firewall_port non valida\n" unless $r{firewall_port}>=1 && $r{firewall_port}<=65535;
    $r{ssh_key}=cfg_value($raw,'ssh_key','/etc/reactive-web-firewall/keys/firewall_ed25519');
    $r{known_hosts}=cfg_value($raw,'known_hosts','/etc/reactive-web-firewall/keys/known_hosts');
    $r{ssh_connect_timeout}=0+cfg_value($raw,'ssh_connect_timeout',2);
    $r{ssh_control_persist}=0+cfg_value($raw,'ssh_control_persist',600);
    $r{ssh_control_path}=cfg_value($raw,'ssh_control_path','/run/reactive-web-firewall/ssh-%C');
    $r{remote_host_label}=cfg_value($raw,'remote_host_label','proxy');
    die "remote_host_label non valido\n" unless $r{remote_host_label} =~ /^[A-Za-z0-9_.-]+$/;
    die "ssh_connect_timeout non valido\n" unless $r{ssh_connect_timeout}>=1 && $r{ssh_connect_timeout}<=30;
    die "ssh_control_persist non valido\n" unless $r{ssh_control_persist}>=0 && $r{ssh_control_persist}<=86400;

    my $dup=parse_duration(cfg_value($raw,'duplicate_suppress','90s'));
    die "duplicate_suppress deve essere temporaneo\n" if !$dup->{enabled} || $dup->{permanent};
    die "duplicate_suppress deve essere tra 10 e 600 secondi\n" if $dup->{seconds}<10 || $dup->{seconds}>600;
    $r{duplicate_suppress_seconds}=$dup->{seconds};

    $r{local_fastban_enabled}=parse_bool(cfg_value($raw,'local_fastban_enabled','on'),'local_fastban_enabled');
    my $fb=parse_duration(cfg_value($raw,'local_fastban_timeout','5m'));
    die "local_fastban_timeout deve essere temporaneo\n" if !$fb->{enabled} || $fb->{permanent};
    die "local_fastban_timeout deve essere tra 10 e 3600 secondi\n" if $fb->{seconds}<10 || $fb->{seconds}>3600;
    $r{local_fastban_timeout_seconds}=$fb->{seconds};
    $r{local_fastban_table}=cfg_value($raw,'local_fastban_table','reactive_web_fastban');
    die "local_fastban_table non valido\n" unless $r{local_fastban_table}=~/^[A-Za-z_][A-Za-z0-9_]*$/;
    $r{local_socket_kill}=parse_bool(cfg_value($raw,'local_socket_kill','on'),'local_socket_kill');
    $r{local_socket_post_sweep}=parse_bool(cfg_value($raw,'local_socket_post_sweep','on'),'local_socket_post_sweep');
    my @ports=parse_port_list(cfg_value($raw,'local_socket_ports','80,443'),'local_socket_ports');
    $r{local_socket_ports}=\@ports;

    my %p;
    for my $def (@$rules) {
        my $raw_policy=cfg_value($raw,'policy_'.$def->{name},$def->{default_policy});
        my $parsed=parse_duration($raw_policy); $parsed->{raw}=$raw_policy; $p{$def->{name}}=$parsed;
    }
    $r{policy}=\%p;
    return \%r;
}

sub install_runtime {
    my ($r,$rules,$fingerprint)=@_;
    $log_file=$r->{log_file}; $rules_directory=$r->{rules_directory};
    my $old_allow_file=$allow_file;
    $allow_file=$r->{allow_file}; $state_file=$r->{state_file}; $active_dir=$r->{active_dir};
    $allow_mtime=-1 if $allow_file ne $old_allow_file;
    $tail_sleep=$r->{tail_sleep}; $logger_tag=$r->{logger_tag};
    $firewall=$r->{firewall}; $firewall_port=$r->{firewall_port};
    $ssh_key=$r->{ssh_key}; $known_hosts=$r->{known_hosts};
    $ssh_connect_timeout=$r->{ssh_connect_timeout}; $ssh_control_persist=$r->{ssh_control_persist};
    $ssh_control_path=$r->{ssh_control_path}; $remote_host_label=$r->{remote_host_label};
    $duplicate_suppress_seconds=$r->{duplicate_suppress_seconds};
    $local_fastban_enabled=$r->{local_fastban_enabled};
    $local_fastban_timeout_seconds=$r->{local_fastban_timeout_seconds};
    $local_fastban_table=$r->{local_fastban_table};
    $local_socket_kill=$r->{local_socket_kill};
    $local_socket_post_sweep=$r->{local_socket_post_sweep};
    @local_socket_ports=@{$r->{local_socket_ports}};
    @rule_modules=@$rules; %rule_by_name=map { $_->{name}=>$_ } @rule_modules;
    %policy=%{$r->{policy}}; $runtime_fingerprint=$fingerprint;
}

sub reload_runtime {
    my ($force)=@_;
    my $changed = 0;
    my $ok=eval {
        my $raw=read_config_raw($config_file);
        my $dir=cfg_value($raw,'rules_directory','/etc/reactive-web-firewall/rules.d');
        my $fingerprint=module_fingerprint($config_file,$dir);
        if ($force || $fingerprint ne $runtime_fingerprint) {
            my @rules=load_rule_modules($dir);
            my $runtime=build_runtime($raw,\@rules);
            install_runtime($runtime,\@rules,$fingerprint);
            $changed = 1;
        }
        1;
    };
    if (!$ok) {
        my $err=$@ || 'errore sconosciuto'; chomp($err);
        die "$err\n" if $force || $runtime_fingerprint eq '';
        if ($err ne $last_reload_error) {
            logmsg('err',"runtime-reload-failed error=[$err]");
            $last_reload_error=$err;
        }
        return 0;
    }
    if ($changed) {
        $last_reload_error='';
        logmsg('notice','runtime-reloaded config='.$config_file.' rules='.scalar(@rule_modules)
            .' firewall='.$firewall.' local_fastban='.($local_fastban_enabled?'on':'off'));
    }
    return 1;
}

sub policy_for {
    my ($rule)=@_;
    return $policy{$rule};
}


sub load_allowlist {
    my $mtime = (-e $allow_file) ? ((stat($allow_file))[9] || 0) : 0;
    return if $mtime == $allow_mtime;

    my %new;
    if (-e $allow_file) {
        open(my $fh, '<', $allow_file) or die "Impossibile leggere $allow_file: $!\n";
        while (my $line = <$fh>) {
            chomp($line);
            $line =~ s/#.*$//;
            $line =~ s/^\s+|\s+$//g;
            next if $line eq '';
            my ($ip) = split(/\s+/, $line, 2);
            next unless valid_ip($ip);
            $new{$ip} = 1;
        }
        close($fh);
    }

    %allow = %new;
    $allow_mtime = $mtime;
    logmsg('notice', 'allowlist-reloaded entries=' . scalar(keys %allow));
}

sub ensure_dirs {
    make_path(dirname($state_file), { mode => 0700 }) unless -d dirname($state_file);
    make_path($active_dir, { mode => 0700 }) unless -d $active_dir;
    chmod 0700, dirname($state_file);
    chmod 0700, $active_dir;
}

sub marker_path {
    my ($ip) = @_;
    die "IP non valido per marker\n" unless valid_ip($ip);
    return "$active_dir/$ip";
}

sub write_marker {
    my ($ip, $expires, $rule, $mode, $signature) = @_;
    ensure_dirs();
    my $path = marker_path($ip);
    my $tmp = "$path.tmp.$$";
    open(my $fh, '>', $tmp) or die "Impossibile scrivere marker $tmp: $!\n";
    print {$fh} join("\t", $expires, $rule, $mode, int(time()), $signature), "\n";
    close($fh) or die "Errore chiusura marker $tmp: $!\n";
    chmod 0600, $tmp;
    rename($tmp, $path) or die "Impossibile rinominare marker $tmp: $!\n";
}

sub remove_marker {
    my ($ip) = @_;
    return unless valid_ip($ip);
    unlink(marker_path($ip));
}

sub marker_active {
    my ($ip) = @_;
    return 0 unless valid_ip($ip);
    my $path = marker_path($ip);
    return 0 unless -f $path;
    open(my $fh, '<', $path) or return 0;
    my $line = <$fh>;
    close($fh);
    $line = '' unless defined $line;
    chomp($line);
    my ($expires) = split(/\t/, $line, 2);
    return 1 if defined $expires && $expires eq '0';
    return 1 if defined $expires && $expires =~ /^\d+$/ && $expires > time();
    unlink($path);
    return 0;
}

sub read_state_locked {
    my ($fh) = @_;
    seek($fh, 0, 0);
    my %state;
    while (my $line = <$fh>) {
        chomp($line);
        next if $line eq '';
        my ($ip, $expires, $rule, $mode, $applied, $signature) = split(/\t/, $line, 6);
        next unless valid_ip($ip);
        next unless defined $expires && $expires =~ /^\d+$/;
        $state{$ip} = {
            expires => 0 + $expires,
            rule => $rule || '-',
            mode => $mode || '-',
            applied => ($applied && $applied =~ /^\d+$/) ? 0 + $applied : 0,
            signature => $signature || '-',
        };
    }
    return %state;
}

sub write_state_locked {
    my ($fh, $state_ref) = @_;
    seek($fh, 0, 0);
    truncate($fh, 0) or die "Impossibile troncare $state_file: $!\n";
    for my $ip (sort keys %{$state_ref}) {
        my $r = $state_ref->{$ip};
        print {$fh} join("\t", $ip, $r->{expires}, $r->{rule}, $r->{mode}, $r->{applied}, $r->{signature}), "\n";
    }
}

sub state_transaction {
    my ($callback) = @_;
    ensure_dirs();
    open(my $fh, '+>>', $state_file) or die "Impossibile aprire $state_file: $!\n";
    chmod 0600, $state_file;
    flock($fh, LOCK_EX) or die "Impossibile bloccare $state_file: $!\n";
    my %state = read_state_locked($fh);
    my $result = $callback->(\%state);
    write_state_locked($fh, \%state);
    close($fh);
    return $result;
}

sub cleanup_state_and_markers {
    my $now = int(time());
    state_transaction(sub {
        my ($state) = @_;
        for my $ip (keys %{$state}) {
            my $r = $state->{$ip};
            if ($r->{expires} != 0 && $r->{expires} <= $now) {
                delete $state->{$ip};
            }
        }
        return 1;
    });

    if (-d $active_dir) {
        opendir(my $dh, $active_dir);
        while (my $name = readdir($dh)) {
            next if $name eq '.' || $name eq '..';
            marker_active($name);
        }
        closedir($dh);
    }
    $last_cleanup = $now;
}

sub maybe_cleanup {
    my $now = int(time());
    return if ($now - $last_cleanup) < 60;
    cleanup_state_and_markers();
}


sub classify_line {
    my ($line)=@_;
    reload_runtime(0);
    my $r=parse_apache_line($line);
    return unless $r;

    my $ip=$r->{ip}||''; my $method=uc($r->{method}||'');
    return unless valid_ip($ip);
    return unless $method =~ /^(?:GET|POST|HEAD)$/;

    my $raw_uri=$r->{uri}||'';
    my ($uri,$uri_path,$had_repeated_slash)=normalize_request_uri($raw_uri);
    my $decoded_uri=decode_uri_for_detection($uri);
    my $decoded_path=$decoded_uri; $decoded_path =~ s/[?#].*$//;

    my $ctx={
        ip=>$ip, vhost=>$r->{vhost}||'-', method=>$method,
        raw_uri=>$raw_uri, uri=>$uri, uri_path=>$uri_path,
        decoded_uri=>$decoded_uri, decoded_path=>$decoded_path,
        had_repeated_slash=>$had_repeated_slash,
        status=>$r->{status}||'-', ref=>$r->{ref}||'-', ua=>$r->{ua}||'-',
    };

    for my $def (@rule_modules) {
        my $active_policy = $policy{$def->{name}};
        next unless $active_policy && $active_policy->{enabled};
        my $signature=$def->{detect}->($ctx);
        next unless defined $signature && $signature ne '';
        return {
            ip=>$ip, rule=>$def->{name}, signature=>$signature,
            vhost=>$ctx->{vhost}, method=>$method, raw_uri=>$raw_uri,
            uri=>$uri, status=>$ctx->{status},
        };
    }
    return;
}

sub remote_command_for {
    my ($ip, $rule, $p) = @_;
    if ($p->{permanent}) {
        # Massima compatibilità con il comando BanIp già usato manualmente.
        return "sync-add $ip";
    }
    my $source = 'CUSTOM_IMMEDIATE_' . $rule;
    $source =~ s/[^A-Za-z0-9_]/_/g;
    return "temp-add $ip $p->{seconds} $remote_host_label $source";
}

sub run_quiet_command {
    my (@command) = @_;
    my $pid = fork();
    return 255 unless defined $pid;
    if ($pid == 0) {
        open(STDOUT, '>', '/dev/null');
        open(STDERR, '>', '/dev/null');
        exec @command;
        exit 127;
    }
    waitpid($pid, 0);
    return ($? == -1) ? 255 : ($? >> 8);
}

sub local_fastban_set_for_ip {
    my ($ip) = @_;
    return ($ip =~ /:/) ? 'fastban_v6' : 'fastban_v4';
}

sub local_fastban_add {
    my ($ip) = @_;
    my $started = clock_gettime(CLOCK_MONOTONIC);

    return {
        rc              => 0,
        active          => 0,
        elapsed_ms      => 0,
        already_present => 0,
    } unless $local_fastban_enabled;

    my $setname = local_fastban_set_for_ip($ip);
    my $already_present = 0;

    my $rc = run_quiet_command(
        $local_fastban_nft,
        'add', 'element',
        'inet', $local_fastban_table, $setname,
        '{', $ip, 'timeout',
        $local_fastban_timeout_seconds . 's',
        '}',
    );

    if ($rc != 0) {
        my $get_rc = run_quiet_command(
            $local_fastban_nft,
            'get', 'element',
            'inet', $local_fastban_table, $setname,
            '{', $ip, '}',
        );

        if ($get_rc == 0) {
            $rc = 0;
            $already_present = 1;
        }
        else {
            my $table_rc = run_quiet_command(
                $local_fastban_nft,
                'list', 'table',
                'inet', $local_fastban_table,
            );

            if ($table_rc != 0) {
                my $load_rc = run_quiet_command($local_fastban_helper, 'reload');

                if ($load_rc == 0) {
                    $rc = run_quiet_command(
                        $local_fastban_nft,
                        'add', 'element',
                        'inet', $local_fastban_table, $setname,
                        '{', $ip, 'timeout',
                        $local_fastban_timeout_seconds . 's',
                        '}',
                    );

                    if ($rc != 0) {
                        my $retry_get_rc = run_quiet_command(
                            $local_fastban_nft,
                            'get', 'element',
                            'inet', $local_fastban_table, $setname,
                            '{', $ip, '}',
                        );

                        if ($retry_get_rc == 0) {
                            $rc = 0;
                            $already_present = 1;
                        }
                    }
                }
            }
        }
    }

    my $elapsed_ms = int(
        (clock_gettime(CLOCK_MONOTONIC) - $started) * 1000 + 0.5
    );

    my $active = ($rc == 0) ? 1 : 0;
    my $level  = $active ? 'notice' : 'warning';

    logmsg(
        $level,
        'local-fastban-add'
        . " ip=$ip"
        . " set=$setname"
        . " timeout=$local_fastban_timeout_seconds"
        . " active=$active"
        . " already_present=$already_present"
        . " rc=$rc"
        . " elapsed_ms=$elapsed_ms"
    );

    return {
        rc              => $rc,
        active          => $active,
        elapsed_ms      => $elapsed_ms,
        already_present => $already_present,
    };
}

sub local_fastban_del {
    my ($ip, $reason) = @_;
    my $started = clock_gettime(CLOCK_MONOTONIC);

    $reason ||= 'unspecified';

    return {
        rc             => 0,
        removed        => 0,
        elapsed_ms     => 0,
        already_absent => 0,
    } unless $local_fastban_enabled;

    my $setname = local_fastban_set_for_ip($ip);
    my $removed = 0;
    my $already_absent = 0;

    my $rc = run_quiet_command(
        $local_fastban_nft,
        'delete', 'element',
        'inet', $local_fastban_table, $setname,
        '{', $ip, '}',
    );

    if ($rc == 0) {
        $removed = 1;
    }
    else {
        my $get_rc = run_quiet_command(
            $local_fastban_nft,
            'get', 'element',
            'inet', $local_fastban_table, $setname,
            '{', $ip, '}',
        );

        if ($get_rc != 0) {
            $rc = 0;
            $already_absent = 1;
        }
    }

    my $elapsed_ms = int(
        (clock_gettime(CLOCK_MONOTONIC) - $started) * 1000 + 0.5
    );

    my $level = ($rc == 0) ? 'notice' : 'warning';

    logmsg(
        $level,
        'local-fastban-del'
        . " ip=$ip"
        . " set=$setname"
        . " reason=$reason"
        . " removed=$removed"
        . " already_absent=$already_absent"
        . " rc=$rc"
        . " elapsed_ms=$elapsed_ms"
    );

    return {
        rc             => $rc,
        removed        => $removed,
        elapsed_ms     => $elapsed_ms,
        already_absent => $already_absent,
    };
}


sub kill_local_sockets {
    my ($ip, $phase) = @_;
    my $started = clock_gettime(CLOCK_MONOTONIC);

    return {
        rc         => 0,
        failures   => 0,
        elapsed_ms => 0,
        attempts   => 0,
    } unless $local_socket_kill;

    my $failures = 0;
    my $attempts = 0;
    my @failed_ports;

    for my $port (@local_socket_ports) {
        $attempts++;

        #
        # Non forziamo -4 o -6.
        #
        # Apache ascolta tramite socket IPv6 dual-stack e il kernel
        # rappresenta le connessioni IPv4 come IPv4-mapped IPv6:
        #
        #   [::ffff:SERVER_IPV4]:443
        #   [::ffff:IP_CLIENT]:porta
        #
        # ss riesce comunque a selezionarle passando l'IPv4 normale
        # a "dst", purché la famiglia non venga forzata.
        #
        my $rc = run_quiet_command(
            'ss',
            '-K',
            '-H',
            '-n',
            '-t',
            'state',
            'connected',
            'dst',
            $ip,
            'sport',
            '=',
            ':' . $port,
        );

        if ($rc != 0) {
            $failures++;
            push @failed_ports, "$port:$rc";
        }
    }

    my $elapsed_ms = int(
        (
            (
                clock_gettime(CLOCK_MONOTONIC)
                - $started
            ) * 1000
        ) + 0.5
    );

    my $rc = $failures ? 1 : 0;

    my $failed = @failed_ports
        ? join(',', @failed_ports)
        : '-';

    my $level = $failures
        ? 'warning'
        : 'notice';

    logmsg(
        $level,
        'socket-kill'
        . " ip=$ip"
        . " phase=$phase"
        . " target=auto-family"
        . ' ports=' . join(',', @local_socket_ports)
        . " attempts=$attempts"
        . " failures=$failures"
        . " failed=[$failed]"
        . " rc=$rc"
        . " elapsed_ms=$elapsed_ms"
    );

    return {
        rc         => $rc,
        failures   => $failures,
        elapsed_ms => $elapsed_ms,
        attempts   => $attempts,
    };
}

sub run_remote {
    my ($command) = @_;
    my @ssh = (
        'ssh',
        '-p', $firewall_port,
        '-i', $ssh_key,
        '-o', 'BatchMode=yes',
        '-o', 'IdentitiesOnly=yes',
        '-o', 'StrictHostKeyChecking=yes',
        '-o', "UserKnownHostsFile=$known_hosts",
        '-o', "ConnectTimeout=$ssh_connect_timeout",
        '-o', 'ConnectionAttempts=1',
        '-o', 'ServerAliveInterval=2',
        '-o', 'ServerAliveCountMax=1',
        '-o', 'ControlMaster=auto',
        '-o', "ControlPersist=$ssh_control_persist",
        '-o', "ControlPath=$ssh_control_path",
        $firewall,
        $command,
    );
    my $rc = system(@ssh);
    return ($rc == -1) ? 255 : ($rc >> 8);
}

sub active_state_record {
    my ($record) = @_;
    return 0 unless $record;
    return 1 if $record->{expires} == 0;
    return $record->{expires} > time() ? 1 : 0;
}

sub stronger_target {
    my ($current, $new_rule, $new_signature, $new_policy, $now) = @_;

    my $new = {
        rule => $new_rule,
        signature => $new_signature,
        permanent => $new_policy->{permanent} ? 1 : 0,
        expires => $new_policy->{permanent} ? 0 : ($now + $new_policy->{seconds}),
        seconds => $new_policy->{seconds},
    };

    return $new unless active_state_record($current);

    if ($current->{expires} == 0) {
        return {
            rule => $current->{rule}, signature => $current->{signature},
            permanent => 1, expires => 0, seconds => 0,
        };
    }

    return $new if $new->{permanent};
    return $new if $new->{expires} > $current->{expires};

    return {
        rule => $current->{rule}, signature => $current->{signature},
        permanent => 0, expires => $current->{expires},
        seconds => $current->{expires} - $now,
    };
}

sub extract_apache_end_us {
    my ($line) = @_;
    return undef unless defined $line;
    return 0 + $1 if $line =~ /(?:^|\s)apache_end_us=(\d{10,20})(?:\s|$)/;
    return undef;
}

sub capture_clock_pair {
    # Associa CLOCK_REALTIME a CLOCK_MONOTONIC riducendo al minimo l'errore
    # introdotto dal tempo impiegato per leggere i due clock.
    my $mono_before = clock_gettime(CLOCK_MONOTONIC);
    my $real_us = int((clock_gettime(CLOCK_REALTIME) * 1_000_000) + 0.5);
    my $mono_after = clock_gettime(CLOCK_MONOTONIC);
    return (($mono_before + $mono_after) / 2, $real_us);
}

sub apply_ban {
    my ($m, $line_seen_at, $match_at, $line_seen_real_us, $apache_end_us) = @_;

    if (!defined $line_seen_at || !defined $line_seen_real_us) {
        ($line_seen_at, $line_seen_real_us) = capture_clock_pair();
    }
    $match_at = clock_gettime(CLOCK_MONOTONIC) unless defined $match_at;
    load_allowlist();
    maybe_cleanup();

    my $new_policy = policy_for($m->{rule});
    return unless $new_policy && $new_policy->{enabled};

    if ($allow{$m->{ip}}) {
        logmsg('notice', "skip-allowlisted ip=$m->{ip} rule=$m->{rule} signature=$m->{signature}");
        return;
    }

    my $now = int(time());
    my $previous;
    my $target;
    my $marker_was_active = marker_active($m->{ip});

    my $should_apply = state_transaction(sub {
        my ($state) = @_;
        $previous = $state->{$m->{ip}} ? { %{$state->{$m->{ip}}} } : undef;
        $target = stronger_target($previous, $m->{rule}, $m->{signature}, $new_policy, $now);

        # Durante la finestra di soppressione, ripeti il comando soltanto se
        # la nuova firma richiede un ban realmente più forte.
        if ($marker_was_active && active_state_record($previous)) {
            my $same_or_weaker = 0;
            if ($previous->{expires} == 0) {
                $same_or_weaker = 1;
            }
            elsif (!$target->{permanent} && $target->{expires} <= $previous->{expires}) {
                $same_or_weaker = 1;
            }
            return 0 if $same_or_weaker;
        }

        # Pending marker before SSH: queued lines for the same source are suppressed.
        my $pending_expires = $now + 30;
        $state->{$m->{ip}} = {
            expires => $pending_expires,
            rule => $target->{rule},
            mode => 'pending',
            applied => $now,
            signature => $target->{signature},
        };
        write_marker($m->{ip}, $pending_expires, $target->{rule}, 'pending', $target->{signature});
        return 1;
    });

    return unless $should_apply;

    my $safe_uri = $m->{raw_uri};
    $safe_uri =~ s/[\x00-\x1f\x7f]/?/g;
    $safe_uri = substr($safe_uri, 0, 500) if length($safe_uri) > 500;

    my $mode = $target->{permanent} ? 'permanent' : 'temporary';
    my $duration = $target->{permanent} ? 'permanent' : $target->{seconds};
    my $remote_policy = {
        permanent => $target->{permanent},
        seconds => $target->{seconds},
    };
    my $remote = remote_command_for($m->{ip}, $target->{rule}, $remote_policy);

    logmsg('warning', "match ip=$m->{ip} rule=$m->{rule} signature=$m->{signature} applied_rule=$target->{rule} mode=$mode duration=$duration vhost=$m->{vhost} method=$m->{method} status=$m->{status} uri=[$safe_uri]");

    if ($dry_run) {
        state_transaction(sub {
            my ($state) = @_;
            if ($previous) { $state->{$m->{ip}} = $previous; }
            else { delete $state->{$m->{ip}}; }
            remove_marker($m->{ip});
            return 1;
        });
        return;
    }

        #
    # 1. Blocco locale immediato.
    #
    # Appena la firma è stata classificata come attacco reale, inseriamo
    # l'indirizzo nel set nftables locale. Da questo momento nessun nuovo
    # pacchetto TCP diretto alle porte 80/443 può raggiungere Apache.
    #
    my $local_fastban_started_at = clock_gettime(CLOCK_MONOTONIC);
    my $local_fastban = local_fastban_add($m->{ip});
    my $local_fastban_completed_at = clock_gettime(CLOCK_MONOTONIC);

    #
    # 2. Distruzione delle connessioni già presenti sul proxy.
    #
    my $socket_pre = kill_local_sockets($m->{ip}, 'pre');

    #
    # 3. Applicazione del ban definitivo su OpenWrt.
    #
    my $remote_started_at = clock_gettime(CLOCK_MONOTONIC);
    my $exit = run_remote($remote);
    my $ban_completed_at = clock_gettime(CLOCK_MONOTONIC);

    #
    # 4. Secondo sweep locale.
    #
    # Serve come ulteriore pulizia delle connessioni nate nell'intervallo
    # immediatamente precedente all'attivazione del fast-ban locale.
    #
    my $socket_post = {
        rc         => 0,
        failures   => 0,
        elapsed_ms => 0,
        attempts   => 0,
    };

    if (
        $exit == 0
        && $local_socket_kill
        && $local_socket_post_sweep
    ) {
        $socket_post = kill_local_sockets($m->{ip}, 'post');
    }

    #
    # 5. Rimozione del fast-ban locale.
    #
    # Il proxy è soltanto una protezione transitoria. Se OpenWrt conferma
    # correttamente il ban, rimuoviamo subito l'elemento locale.
    #
    # Se il comando remoto fallisce, non lo rimuoviamo: l'elemento scadrà
    # automaticamente dopo local_fastban_timeout_seconds.
    #
    my $local_fastban_remove = {
        attempted      => 0,
        rc             => 'na',
        removed        => 0,
        elapsed_ms     => 0,
        already_absent => 0,
    };

    if (
        $exit == 0
        && $local_fastban->{active}
    ) {
        $local_fastban_remove =
            local_fastban_del(
                $m->{ip},
                'remote-confirmed',
            );

        $local_fastban_remove->{attempted} = 1;
    }

    my $shutdown_completed_at = clock_gettime(CLOCK_MONOTONIC);

    #
    # Tempi del percorso interno al watcher.
    #
    my $line_to_match_ms =
        int((($match_at - $line_seen_at) * 1000) + 0.5);

    my $preban_ms =
        int((($remote_started_at - $match_at) * 1000) + 0.5);

    my $remote_ms =
        int((($ban_completed_at - $remote_started_at) * 1000) + 0.5);

    my $reaction_seconds =
        $ban_completed_at - $line_seen_at;

    my $reaction_ms =
        int(($reaction_seconds * 1000) + 0.5);

    my $full_shutdown_seconds =
        $shutdown_completed_at - $line_seen_at;

    my $full_shutdown_ms =
        int(($full_shutdown_seconds * 1000) + 0.5);

    #
    # Il tempo più importante con il nuovo sistema:
    #
    # quanto passa dal riconoscimento dell'attacco all'attivazione del
    # blocco locale sul proxy.
    #
    my $match_to_local_block_ms = 'na';
    my $line_to_local_block_ms  = 'na';

    if ($local_fastban->{active}) {
        $match_to_local_block_ms = int(
            (
                $local_fastban_completed_at
                - $match_at
            ) * 1000 + 0.5
        );

        $line_to_local_block_ms = int(
            (
                $local_fastban_completed_at
                - $line_seen_at
            ) * 1000 + 0.5
        );
    }

    #
    # Tempi confrontati con apache_end_us.
    #
    my $apache_log_delivery_ms       = 'na';
    my $apache_end_to_local_block_ms = 'na';
    my $apache_end_to_ban_ms         = 'na';
    my $apache_end_to_shutdown_ms    = 'na';

    if (
        defined $apache_end_us
        && $apache_end_us > 0
        && defined $line_seen_real_us
    ) {
        my $delivery_us =
            $line_seen_real_us - $apache_end_us;

        my $total_us =
            $delivery_us
            + int(($reaction_seconds * 1_000_000) + 0.5);

        my $shutdown_total_us =
            $delivery_us
            + int(($full_shutdown_seconds * 1_000_000) + 0.5);

        $apache_log_delivery_ms =
            sprintf('%.3f', $delivery_us / 1000);

        $apache_end_to_ban_ms =
            sprintf('%.3f', $total_us / 1000);

        $apache_end_to_shutdown_ms =
            sprintf('%.3f', $shutdown_total_us / 1000);

        if ($local_fastban->{active}) {
            my $local_block_seconds =
                $local_fastban_completed_at
                - $line_seen_at;

            my $local_block_total_us =
                $delivery_us
                + int(
                    ($local_block_seconds * 1_000_000)
                    + 0.5
                );

            $apache_end_to_local_block_ms =
                sprintf(
                    '%.3f',
                    $local_block_total_us / 1000,
                );
        }
    }

    my $local_fastban_retained =
        (
            $local_fastban->{active}
            && $exit != 0
        )
        ? 1
        : 0;

    if ($exit == 0) {
        my $final_expires =
            $target->{permanent}
            ? 0
            : int(time()) + $target->{seconds};

        my $marker_expires =
            int(time()) + $duplicate_suppress_seconds;

        state_transaction(sub {
            my ($state) = @_;

            $state->{$m->{ip}} = {
                expires   => $final_expires,
                rule      => $target->{rule},
                mode      => $mode,
                applied   => int(time()),
                signature => $target->{signature},
            };

            write_marker(
                $m->{ip},
                $marker_expires,
                $target->{rule},
                $mode,
                $target->{signature},
            );

            return 1;
        });

        logmsg(
            'notice',
            "ban-applied"
            . " ip=$m->{ip}"
            . " rule=$target->{rule}"
            . " mode=$mode"
            . " duration=$duration"
            . " duplicate_suppress=$duplicate_suppress_seconds"
            . " rc=0"
            . " apache_end_to_local_block_ms=$apache_end_to_local_block_ms"
            . " apache_end_to_ban_ms=$apache_end_to_ban_ms"
            . " apache_end_to_shutdown_ms=$apache_end_to_shutdown_ms"
            . " apache_log_delivery_ms=$apache_log_delivery_ms"
            . " match_to_local_block_ms=$match_to_local_block_ms"
            . " line_to_local_block_ms=$line_to_local_block_ms"
            . " local_fastban_ms=$local_fastban->{elapsed_ms}"
            . " local_fastban_rc=$local_fastban->{rc}"
            . " local_fastban_active=$local_fastban->{active}"
            . " local_fastban_already_present=$local_fastban->{already_present}"
            . " local_fastban_remove_attempted=$local_fastban_remove->{attempted}"
            . " local_fastban_remove_ms=$local_fastban_remove->{elapsed_ms}"
            . " local_fastban_remove_rc=$local_fastban_remove->{rc}"
            . " local_fastban_removed=$local_fastban_remove->{removed}"
            . " local_fastban_remove_already_absent=$local_fastban_remove->{already_absent}"
            . " reaction_ms=$reaction_ms"
            . " full_shutdown_ms=$full_shutdown_ms"
            . " line_to_match_ms=$line_to_match_ms"
            . " preban_ms=$preban_ms"
            . " socket_pre_ms=$socket_pre->{elapsed_ms}"
            . " socket_pre_rc=$socket_pre->{rc}"
            . " remote_ms=$remote_ms"
            . " socket_post_ms=$socket_post->{elapsed_ms}"
            . " socket_post_rc=$socket_post->{rc}"
            . " elapsed_ms=$remote_ms"
        );
    }
    else {
        state_transaction(sub {
            my ($state) = @_;

            if ($previous) {
                $state->{$m->{ip}} = $previous;
            }
            else {
                delete $state->{$m->{ip}};
            }

            remove_marker($m->{ip});
            return 1;
        });

        logmsg(
            'err',
            "ban-failed"
            . " ip=$m->{ip}"
            . " rule=$target->{rule}"
            . " rc=$exit"
            . " apache_end_to_local_block_ms=$apache_end_to_local_block_ms"
            . " apache_end_to_ban_ms=$apache_end_to_ban_ms"
            . " apache_end_to_shutdown_ms=$apache_end_to_shutdown_ms"
            . " apache_log_delivery_ms=$apache_log_delivery_ms"
            . " match_to_local_block_ms=$match_to_local_block_ms"
            . " line_to_local_block_ms=$line_to_local_block_ms"
            . " local_fastban_ms=$local_fastban->{elapsed_ms}"
            . " local_fastban_rc=$local_fastban->{rc}"
            . " local_fastban_active=$local_fastban->{active}"
            . " local_fastban_retained=$local_fastban_retained"
            . " local_fastban_timeout=$local_fastban_timeout_seconds"
            . " reaction_ms=$reaction_ms"
            . " full_shutdown_ms=$full_shutdown_ms"
            . " line_to_match_ms=$line_to_match_ms"
            . " preban_ms=$preban_ms"
            . " socket_pre_ms=$socket_pre->{elapsed_ms}"
            . " socket_pre_rc=$socket_pre->{rc}"
            . " remote_ms=$remote_ms"
            . " socket_post_ms=$socket_post->{elapsed_ms}"
            . " socket_post_rc=$socket_post->{rc}"
            . " elapsed_ms=$remote_ms"
        );
    }
}

sub print_match {
    my ($m) = @_;
    my $p = policy_for($m->{rule});
    my $mode = !$p->{enabled} ? 'disabled' : ($p->{permanent} ? 'permanent' : 'temporary');
    my $seconds = $p->{permanent} ? 0 : $p->{seconds};
    print join("\t", $m->{ip}, $m->{rule}, $m->{signature}, $mode, $seconds,
        $m->{vhost}, $m->{method}, $m->{raw_uri}, $m->{uri}, $m->{status}), "\n";
}

sub process_line {
    my ($line, $print_only, $line_seen_at, $line_seen_real_us) = @_;
    if (!defined $line_seen_at || !defined $line_seen_real_us) {
        ($line_seen_at, $line_seen_real_us) = capture_clock_pair();
    }
    my $apache_end_us = extract_apache_end_us($line);
    chomp($line);
    return if $line eq '';
    my $m = classify_line($line);
    return unless $m;
    my $match_at = clock_gettime(CLOCK_MONOTONIC);
    if ($print_only) { print_match($m); return; }
    apply_ban($m, $line_seen_at, $match_at, $line_seen_real_us, $apache_end_us);
}


reload_runtime(1);
ensure_dirs();

if ($validate_config) {
    print "Configurazione valida: $config_file\n";
    print "Moduli caricati: ".scalar(@rule_modules)."\n";
    print "Firewall: $firewall:$firewall_port\n";
    exit 0;
}

if ($show_config) {
    print "config_file=$config_file\n";
    print "apache_log_file=$log_file\n";
    print "rules_directory=$rules_directory\n";
    print "allowlist_file=$allow_file\n";
    print "firewall=$firewall\n";
    print "firewall_port=$firewall_port\n";
    print "duplicate_suppress=${duplicate_suppress_seconds}s\n";
    print "local_fastban_enabled=".($local_fastban_enabled?'on':'off')."\n";
    print "local_fastban_timeout=${local_fastban_timeout_seconds}s\n";
    print "local_socket_kill=".($local_socket_kill?'on':'off')."\n";
    print "local_socket_post_sweep=".($local_socket_post_sweep?'on':'off')."\n";
    print "local_socket_ports=".join(',',@local_socket_ports)."\n";
    for my $def (@rule_modules) {
        my $p=$policy{$def->{name}};
        my $value=!$p->{enabled}?'off':($p->{permanent}?'permanent':$p->{seconds}.'s');
        print "policy_$def->{name}=$value\n";
    }
    exit 0;
}

if ($list_rules) {
    for my $def (@rule_modules) {
        my $p=$policy{$def->{name}};
        my $value=!$p->{enabled}?'off':($p->{permanent}?'permanent':$p->{seconds}.'s');
        print join("\t",$def->{priority},$def->{name},$value,$def->{description},$def->{source_file}),"\n";
    }
    exit 0;
}

if ($list_state) {
    cleanup_state_and_markers();
    open(my $fh,'<',$state_file) or exit 0; print while <$fh>; close($fh); exit 0;
}

if ($forget_ip ne '') {
    die "IP non valido: $forget_ip\n" unless valid_ip($forget_ip);
    state_transaction(sub { my ($state)=@_; delete $state->{$forget_ip}; remove_marker($forget_ip); return 1; });
    print "Dimenticato stato locale per $forget_ip\n"; exit 0;
}

if ($unban_ip ne '') {
    die "IP non valido: $unban_ip\n" unless valid_ip($unban_ip);
    -f $ssh_key or die "Chiave SSH non trovata: $ssh_key\n";
    -f $known_hosts or die "known_hosts non trovato: $known_hosts\n";
    my $rc=run_remote("unban-all $unban_ip"); die "Unban remoto fallito rc=$rc\n" if $rc!=0;
    local_fastban_del($unban_ip,'manual-unban');
    state_transaction(sub { my ($state)=@_; delete $state->{$unban_ip}; remove_marker($unban_ip); return 1; });
    print "Unban remoto e stato locale rimossi per $unban_ip\n"; exit 0;
}

if ($test_line ne '') { process_line($test_line,1); exit 0; }
if ($test_file ne '') {
    open(my $fh,'<',$test_file) or die "Impossibile leggere $test_file: $!\n";
    while (my $line=<$fh>) { process_line($line,1); }
    close($fh); exit 0;
}

-f $log_file or die "Log non trovato: $log_file\n";
-f $ssh_key or die "Chiave SSH non trovata: $ssh_key\n";
-f $known_hosts or die "known_hosts non trovato: $known_hosts\n";
load_allowlist(); cleanup_state_and_markers();
logmsg('notice',"start build=$BUILD log=$log_file rules=$rules_directory config=$config_file firewall=$firewall firewall_port=$firewall_port tail_sleep=$tail_sleep");

open(my $tail,'-|','tail','-n','0','-F','-s',$tail_sleep,'--',$log_file)
    or die "Impossibile avviare tail: $!\n";
while (1) {
    my $line=<$tail>; last unless defined $line;
    my ($line_seen_at,$line_seen_real_us)=capture_clock_pair();
    process_line($line,0,$line_seen_at,$line_seen_real_us);
}
close($tail); die "tail terminato inaspettatamente\n";
