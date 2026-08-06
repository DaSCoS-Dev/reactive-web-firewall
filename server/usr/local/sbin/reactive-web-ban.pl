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

my $BUILD = 'reactive-web-firewall-0.2.1-production-aligned';

my $log_file     = '/var/log/apache2/reactive_web_access.log';
my $regex_file   = '/usr/local/lib/reactive-web-firewall/detector.pm';
my $config_file  = '/etc/reactive-web-firewall/rules.conf';
my $allow_file   = '/etc/reactive-web-firewall/allowlist';
my $state_file   = '/var/lib/reactive-web-firewall/active.tsv';
my $active_dir   = '/run/reactive-web-firewall/active';
my $ssh_key      = '/etc/reactive-web-firewall/keys/firewall_ed25519';
my $known_hosts  = '/etc/reactive-web-firewall/keys/known_hosts';
my $firewall     = 'root@192.0.2.1';
my $firewall_port = 22;
my $tail_sleep   = '0.1';

my $test_file    = '';
my $test_line    = '';
my $dry_run      = 0;
my $show_help    = 0;
my $show_version = 0;
my $show_config  = 0;
my $list_state   = 0;
my $forget_ip    = '';
my $unban_ip     = '';

# Local fast-ban configuration
my $local_fastban_enabled         = 1;
my $local_fastban_timeout_seconds = 300;
my $local_fastban_nft             = '/usr/sbin/nft';
my $local_fastban_ruleset         = '/etc/nftables.d/reactive-web-fastban.nft';
my $local_fastban_table           = 'reactive_web_fastban';

GetOptions(
    'log=s'          => \$log_file,
    'regex=s'        => \$regex_file,
    'config=s'       => \$config_file,
    'allow-file=s'   => \$allow_file,
    'state-file=s'   => \$state_file,
    'active-dir=s'   => \$active_dir,
    'ssh-key=s'      => \$ssh_key,
    'known-hosts=s'  => \$known_hosts,
    'firewall=s'     => \$firewall,
    'firewall-port=i'=> \$firewall_port,
    'tail-sleep=s'   => \$tail_sleep,
    'test-file=s'    => \$test_file,
    'test-line=s'    => \$test_line,
    'dry-run'        => \$dry_run,
    'show-config'    => \$show_config,
    'list-state'     => \$list_state,
    'forget=s'       => \$forget_ip,
    'unban=s'        => \$unban_ip,
    'version'        => \$show_version,
    'help'           => \$show_help,
) or die "Parametri non validi. Usa --help\n";

if ($show_version) {
    print "$BUILD\n";
    exit 0;
}

if ($show_help) {
    print <<'HELP';
Uso:
  reactive-web-ban.pl
  reactive-web-ban.pl --test-line 'riga Apache completa'
  reactive-web-ban.pl --test-file /percorso/log
  reactive-web-ban.pl --show-config
  reactive-web-ban.pl --list-state
  reactive-web-ban.pl --forget IP
  reactive-web-ban.pl --unban IP

Il servizio segue in tempo quasi reale reactive_web_access.log e applica ban
sul firewall OpenWrt con durata configurabile per famiglia di attacco.

Sintassi durata nel file di configurazione:
  0, off, disabled       regola disabilitata
  1, permanent, perm     ban permanente tramite sync-add
  3600                   secondi
  30m, 4h, 3d, 2w        minuti, ore, giorni, settimane

Il watcher crea un marker in /run/reactive-web-firewall/active.
Il marker evita di ripetere lo stesso ban durante la finestra di soppressione
e può essere consultato anche da integrazioni esterne opzionali.

Se local_socket_kill è attivo, il watcher usa ss -K sul proxy per chiudere
i socket TCP già stabiliti verso l'IP aggressore. Può eseguire un primo sweep
prima del ban OpenWrt e un secondo sweep dopo il ritorno positivo del firewall.
HELP
    exit 0;
}

-f $regex_file or die "Detector non trovato: $regex_file\n";

our %globlogs;
require $regex_file;

for my $name (qw(parse_apache_line normalize_request_uri decode_uri_for_detection sql_injection_signature is_bad_ua)) {
    no strict 'refs';
    defined &{$name} or die "Funzione $name non trovata in $regex_file\n";
}

my %KNOWN_RULES = map { $_ => 1 } qw(
    git_exploit
    env_exploit
    framework_exploit
    xmlrpc
    wp_batch
    sql_injection
    known_webshell
    php_probe
    wp_login
);

my %DEFAULT_POLICY = (
    git_exploit       => 'permanent',
    env_exploit       => 'permanent',
    framework_exploit => 'permanent',
    xmlrpc             => '3d',
    wp_batch           => '3d',
    sql_injection      => '2w',
    known_webshell     => 'permanent',
    php_probe          => '1h',
    wp_login           => '4h',
);

my $DEFAULT_DUPLICATE_SUPPRESS = '90s';
my $duplicate_suppress_seconds = 90;
my $local_socket_kill = 1;
my $local_socket_post_sweep = 1;
my @local_socket_ports = (80, 443);

my %policy = ();
my $config_mtime = -1;
my %allow = ();
my $allow_mtime = -1;
my $last_cleanup = 0;

sub logmsg {
    my ($level, $message) = @_;
    $level ||= 'notice';
    $message ||= '';
    system('logger', '-p', "user.$level", '-t', 'reactive-web-ban', '--', $message);
    if ($test_file ne '' || $test_line ne '' || $dry_run || $show_config || $list_state) {
        print STDERR "reactive-web-ban[$level]: $message\n";
    }
}

sub valid_ip {
    my ($ip) = @_;
    return 0 unless defined $ip && $ip ne '';
    return 1 if inet_pton(AF_INET,  $ip);
    return 1 if inet_pton(AF_INET6, $ip);
    return 0;
}

sub parse_duration {
    my ($raw) = @_;
    $raw = '' unless defined $raw;
    $raw =~ s/^\s+|\s+$//g;
    my $v = lc($raw);

    return { enabled => 0, permanent => 0, seconds => 0, label => 'off' }
        if $v eq '' || $v eq '0' || $v eq 'off' || $v eq 'disabled' || $v eq 'no';

    return { enabled => 1, permanent => 1, seconds => 0, label => 'permanent' }
        if $v eq '1' || $v eq 'permanent' || $v eq 'perm' || $v eq 'forever';

    if ($v =~ /^(\d+)([smhdw]?)$/) {
        my ($n, $unit) = ($1, $2);
        die "Durata non valida: $raw\n" if $n <= 0;
        my %mult = ('' => 1, s => 1, m => 60, h => 3600, d => 86400, w => 604800);
        my $seconds = $n * $mult{$unit};
        return { enabled => 1, permanent => 0, seconds => $seconds, label => $v };
    }

    die "Durata non valida: $raw\n";
}

sub parse_bool {
    my ($raw, $name) = @_;
    $raw = '' unless defined $raw;
    $raw =~ s/^\s+|\s+$//g;
    my $v = lc($raw);
    return 1 if $v =~ /^(?:1|yes|true|on|enabled)$/;
    return 0 if $v =~ /^(?:0|no|false|off|disabled)$/;
    die "$name non valido: $raw\n";
}

sub parse_port_list {
    my ($raw) = @_;
    $raw = '' unless defined $raw;
    my @ports;
    for my $part (split(/[,\s]+/, $raw)) {
        next if $part eq '';
        die "Porta locale non valida: $part\n" unless $part =~ /^\d+$/ && $part >= 1 && $part <= 65535;
        push @ports, 0 + $part;
    }
    die "local_socket_ports non può essere vuoto\n" unless @ports;
    my %seen;
    @ports = grep { !$seen{$_}++ } @ports;
    return @ports;
}

sub parse_config_file {
    my %raw = %DEFAULT_POLICY;
    my $raw_duplicate_suppress = $DEFAULT_DUPLICATE_SUPPRESS;
    my $raw_local_fastban_enabled = 'on';
    my $raw_local_fastban_timeout = '300s';
    my $raw_local_socket_kill = 'on';
    my $raw_local_socket_post_sweep = 'on';
    my $raw_local_socket_ports = '80,443';

    if (-e $config_file) {
        open(my $fh, '<', $config_file) or die "Impossibile leggere $config_file: $!\n";
        while (my $line = <$fh>) {
            chomp($line);
            $line =~ s/#.*$//;
            $line =~ s/^\s+|\s+$//g;
            next if $line eq '';

            my ($key, $value) = $line =~ /^([A-Za-z0-9_]+)\s*(?:=|:)\s*(.*?)\s*$/;
            die "Riga configurazione non valida: $line\n" unless defined $key;
            $key = lc($key);
            if ($key eq 'duplicate_suppress' || $key eq 'lfd_suppress') {
                $raw_duplicate_suppress = $value;
                next;
            }
            if ($key eq 'local_fastban_enabled') {
                $raw_local_fastban_enabled = $value;
                next;
            }
            if ($key eq 'local_fastban_timeout') {
                $raw_local_fastban_timeout = $value;
                next;
            }
            if ($key eq 'local_socket_kill') {
                $raw_local_socket_kill = $value;
                next;
            }
            if ($key eq 'local_socket_post_sweep') {
                $raw_local_socket_post_sweep = $value;
                next;
            }
            if ($key eq 'local_socket_ports') {
                $raw_local_socket_ports = $value;
                next;
            }
            die "Regola sconosciuta nel file di configurazione: $key\n" unless $KNOWN_RULES{$key};
            $raw{$key} = $value;
        }
        close($fh);
    }

    my %new_policy;
    for my $rule (sort keys %KNOWN_RULES) {
        my $parsed = parse_duration($raw{$rule});
        $parsed->{raw} = $raw{$rule};
        $new_policy{$rule} = $parsed;
    }

    my $suppress = lc($raw_duplicate_suppress // '');
    $suppress =~ s/^\s+|\s+$//g;
    die "duplicate_suppress non valido: $raw_duplicate_suppress\n"
        unless $suppress =~ /^(\d+)([smhdw]?)$/;
    my ($n, $unit) = ($1, $2);
    my %mult = ('' => 1, s => 1, m => 60, h => 3600, d => 86400, w => 604800);
    my $suppress_seconds = $n * $mult{$unit};
    die "duplicate_suppress deve essere tra 10 e 600 secondi\n"
        if $suppress_seconds < 10 || $suppress_seconds > 600;

    my $fastban_enabled = parse_bool($raw_local_fastban_enabled, 'local_fastban_enabled');
    my $fastban_timeout_parsed = parse_duration($raw_local_fastban_timeout);
    die "local_fastban_timeout deve essere temporaneo\n"
        if !$fastban_timeout_parsed->{enabled} || $fastban_timeout_parsed->{permanent};
    my $fastban_timeout = $fastban_timeout_parsed->{seconds};
    die "local_fastban_timeout deve essere tra 10 e 3600 secondi\n"
        if $fastban_timeout < 10 || $fastban_timeout > 3600;

    my $socket_kill = parse_bool($raw_local_socket_kill, 'local_socket_kill');
    my $post_sweep = parse_bool($raw_local_socket_post_sweep, 'local_socket_post_sweep');
    my @socket_ports = parse_port_list($raw_local_socket_ports);

    return (\%new_policy, $suppress_seconds, $fastban_enabled, $fastban_timeout, $socket_kill, $post_sweep, \@socket_ports);
}

sub load_config {
    my ($force) = @_;
    my $mtime = (-e $config_file) ? ((stat($config_file))[9] || 0) : 0;
    return if !$force && $mtime == $config_mtime;

    my ($new_ref, $new_suppress, $new_fastban_enabled, $new_fastban_timeout, $new_socket_kill, $new_post_sweep, $new_ports_ref);
    my $ok = eval {
        ($new_ref, $new_suppress, $new_fastban_enabled, $new_fastban_timeout, $new_socket_kill, $new_post_sweep, $new_ports_ref) = parse_config_file();
        1;
    };
    if (!$ok) {
        my $err = $@ || 'errore sconosciuto';
        chomp($err);
        die "$err\n" if $force;
        logmsg('err', "config-reload-failed error=[$err]");
        return;
    }

    %policy = %{$new_ref};
    $duplicate_suppress_seconds = $new_suppress;
    $local_fastban_enabled = $new_fastban_enabled;
    $local_fastban_timeout_seconds = $new_fastban_timeout;
    $local_socket_kill = $new_socket_kill;
    $local_socket_post_sweep = $new_post_sweep;
    @local_socket_ports = @{$new_ports_ref};
    $config_mtime = $mtime;
    logmsg('notice', 'config-reloaded file=' . $config_file
        . ' duplicate_suppress=' . $duplicate_suppress_seconds
        . ' local_fastban_enabled=' . ($local_fastban_enabled ? 'on' : 'off')
        . ' local_fastban_timeout=' . $local_fastban_timeout_seconds
        . ' local_socket_kill=' . ($local_socket_kill ? 'on' : 'off')
        . ' local_socket_post_sweep=' . ($local_socket_post_sweep ? 'on' : 'off')
        . ' local_socket_ports=' . join(',', @local_socket_ports));
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

sub policy_for {
    my ($rule) = @_;
    load_config(0);
    return $policy{$rule};
}

sub classify_line {
    my ($line) = @_;
    my $r = parse_apache_line($line);
    return unless $r;

    my $ip      = $r->{ip} || '';
    my $method  = uc($r->{method} || '');
    my $raw_uri = $r->{uri} || '';
    my $vhost   = $r->{vhost} || '-';
    my $status  = $r->{status} || '-';
    my $ref     = $r->{ref} || '-';
    my $ua      = $r->{ua} || '-';

    return unless valid_ip($ip);
    return unless $method =~ /^(?:GET|POST|HEAD)$/;

    my ($uri, $uri_path, $had_repeated_slash) = normalize_request_uri($raw_uri);
    my $hard_uri = decode_uri_for_detection($uri);
    my $hard_path = $hard_uri;
    $hard_path =~ s/[?#].*$//;

    my $sqli = sql_injection_signature($uri);
    if ($sqli ne '') {
        return {
            ip=>$ip, rule=>'sql_injection', signature=>$sqli, vhost=>$vhost,
            method=>$method, raw_uri=>$raw_uri, uri=>$uri, status=>$status,
        };
    }

    if ($hard_uri =~ m{^/wp-json/batch/v1(?:/|$|[?#])}
        || $hard_uri =~ m{(?:\?|[&;])rest_route=/batch/v1(?:/|$|[&#;])}) {
        return {
            ip=>$ip, rule=>'wp_batch', signature=>'wordpress-batch-v1', vhost=>$vhost,
            method=>$method, raw_uri=>$raw_uri, uri=>$uri, status=>$status,
        };
    }

    if ($hard_uri =~ m{(?:^|/)\.git(?:/|$|[?#])}) {
        return {
            ip=>$ip, rule=>'git_exploit', signature=>'git-repository-probe', vhost=>$vhost,
            method=>$method, raw_uri=>$raw_uri, uri=>$uri, status=>$status,
        };
    }

    if ($hard_uri =~ m{(?:^|/)\.env(?:[._-][^/?#]*)?(?:$|[/?#])}
        || $hard_uri =~ m{(?:^|/)\.aws/credentials(?:$|[?#])}
        || $hard_uri =~ m{(?:^|/)\.vscode/sftp\.json(?:$|[?#])}
        || $hard_uri =~ m{(?:^|/)\.ds_store(?:$|[?#])}
        || $hard_uri =~ m{(?:^|/)wp-config\.php(?:$|[?#])}) {
        return {
            ip=>$ip, rule=>'env_exploit', signature=>'secret-credential-probe', vhost=>$vhost,
            method=>$method, raw_uri=>$raw_uri, uri=>$uri, status=>$status,
        };
    }

    if ($hard_uri =~ m{/vendor/(?:[^/?#]+/)*phpunit(?:/|$|[?#])}
        || $hard_uri =~ m{/phpunit(?:/|$|[?#])}) {
        return {
            ip=>$ip, rule=>'framework_exploit', signature=>'phpunit-probe', vhost=>$vhost,
            method=>$method, raw_uri=>$raw_uri, uri=>$uri, status=>$status,
        };
    }

    if ($hard_path eq '/xmlrpc.php') {
        return {
            ip=>$ip, rule=>'xmlrpc', signature=>'xmlrpc', vhost=>$vhost,
            method=>$method, raw_uri=>$raw_uri, uri=>$uri, status=>$status,
        };
    }

    if ($hard_uri =~ m{/(?:zwso|mah|shoha|alpha|alpa|alfa|chosen|goods|wp_filemanager|shelp|ms-themes|gifclass|txets|wp_mna|lock360|o-simple|this_is_a_new_hello_world)\.php(?:$|[?#])}i
        || $hard_uri =~ m{^/\.wp/wso\.php(?:$|[?#])}i
        || $hard_uri =~ m{^/wp-content/plugins/hellopress/[^?#]*\.php(?:$|[?#])}i) {
        return {
            ip=>$ip, rule=>'known_webshell', signature=>'known-webshell-probe', vhost=>$vhost,
            method=>$method, raw_uri=>$raw_uri, uri=>$uri, status=>$status,
        };
    }

    if ($hard_path =~ m{(?:^|/)wp-login\.php$}i
        && $status =~ /^(?:301|302|403|404|503)$/
        && ($ref eq '-' || $ref eq '' || $ref =~ m{/wp-login\.php(?:$|[?#])}i)) {
        return {
            ip=>$ip, rule=>'wp_login', signature=>'wp-login-probe', vhost=>$vhost,
            method=>$method, raw_uri=>$raw_uri, uri=>$uri, status=>$status,
        };
    }

    my $is_ert = ($hard_path eq '/wp-content/plugins/easy-responsive-tabs/assets/css/ert_css.php'
        || $hard_path eq '/wp-content/plugins/easy-responsive-tabs/assets/js/ert_js.php') ? 1 : 0;

    my %safe_php = map { $_ => 1 } qw(
        index.php admin.php login.php wp-login.php xmlrpc.php wp-cron.php
        wp-comments-post.php wp-trackback.php wp-signup.php wp-activate.php
        admin-ajax.php
    );
    my ($basename) = $hard_path =~ m{/([^/]+)$};
    $basename ||= '';

    if (!$is_ert
        && $hard_path =~ m{^/[a-z0-9][a-z0-9_.-]{0,50}\.php$}i
        && !$safe_php{lc($basename)}
        && $status =~ /^(?:301|302|403|404|410|503)$/
        && ($ref eq '-' || $ref eq '')
        && ($ua eq '-' || $ua eq '' || is_bad_ua($ua))) {
        return {
            ip=>$ip, rule=>'php_probe', signature=>'generic-php-probe', vhost=>$vhost,
            method=>$method, raw_uri=>$raw_uri, uri=>$uri, status=>$status,
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
    return "temp-add $ip $p->{seconds} proxy $source";
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
                my $load_rc = run_quiet_command(
                    $local_fastban_nft,
                    '-f',
                    $local_fastban_ruleset,
                );

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
        '-o', 'ConnectTimeout=2',
        '-o', 'ConnectionAttempts=1',
        '-o', 'ServerAliveInterval=2',
        '-o', 'ServerAliveCountMax=1',
        '-o', 'ControlMaster=auto',
        '-o', 'ControlPersist=600',
        '-o', 'ControlPath=/run/reactive-web-firewall/ssh-%C',
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

die "Porta firewall non valida: $firewall_port\n" unless $firewall_port >= 1 && $firewall_port <= 65535;
load_config(1);
ensure_dirs();

if ($show_config) {
    print "duplicate_suppress=${duplicate_suppress_seconds}s\n";
    print "local_fastban_enabled=" . ($local_fastban_enabled ? 'on' : 'off') . "\n";
    print "local_fastban_timeout=${local_fastban_timeout_seconds}s\n";
    print "local_socket_kill=" . ($local_socket_kill ? 'on' : 'off') . "\n";
    print "local_socket_post_sweep=" . ($local_socket_post_sweep ? 'on' : 'off') . "\n";
    print "local_socket_ports=" . join(',', @local_socket_ports) . "\n";
    for my $rule (sort keys %KNOWN_RULES) {
        my $p = $policy{$rule};
        my $value = !$p->{enabled} ? 'off' : ($p->{permanent} ? 'permanent' : $p->{seconds} . 's');
        print "$rule=$value\n";
    }
    exit 0;
}

if ($list_state) {
    cleanup_state_and_markers();
    open(my $fh, '<', $state_file) or exit 0;
    print while <$fh>;
    close($fh);
    exit 0;
}

if ($forget_ip ne '') {
    die "IP non valido: $forget_ip\n" unless valid_ip($forget_ip);
    state_transaction(sub { my ($state)=@_; delete $state->{$forget_ip}; remove_marker($forget_ip); return 1; });
    print "Dimenticato stato locale per $forget_ip\n";
    exit 0;
}

if ($unban_ip ne '') {
    die "IP non valido: $unban_ip\n" unless valid_ip($unban_ip);
    -f $ssh_key or die "Chiave SSH non trovata: $ssh_key\n";
    -f $known_hosts or die "known_hosts non trovato: $known_hosts\n";
    my $rc = run_remote("unban-all $unban_ip");
    die "Unban remoto fallito rc=$rc\n" if $rc != 0;
    local_fastban_del($unban_ip, 'manual-unban');
    state_transaction(sub { my ($state)=@_; delete $state->{$unban_ip}; remove_marker($unban_ip); return 1; });
    print "Unban remoto e stato locale rimossi per $unban_ip\n";
    exit 0;
}

if ($test_line ne '') {
    process_line($test_line, 1);
    exit 0;
}

if ($test_file ne '') {
    open(my $fh, '<', $test_file) or die "Impossibile leggere $test_file: $!\n";
    while (my $line = <$fh>) { process_line($line, 1); }
    close($fh);
    exit 0;
}

-f $log_file or die "Log non trovato: $log_file\n";
-f $ssh_key or die "Chiave SSH non trovata: $ssh_key\n";
-f $known_hosts or die "known_hosts non trovato: $known_hosts\n";

load_allowlist();
cleanup_state_and_markers();
logmsg('notice', "start build=$BUILD log=$log_file detector=$regex_file config=$config_file firewall=$firewall firewall_port=$firewall_port tail_sleep=$tail_sleep");

open(my $tail, '-|', 'tail', '-n', '0', '-F', '-s', $tail_sleep, '--', $log_file)
    or die "Impossibile avviare tail: $!\n";

while (1) {
    my $line = <$tail>;
    last unless defined $line;

    # Inizio del tempo di reazione: la riga è stata consegnata dal processo
    # tail al watcher ed è disponibile per essere analizzata.
    my ($line_seen_at, $line_seen_real_us) = capture_clock_pair();
    process_line($line, 0, $line_seen_at, $line_seen_real_us);
}

close($tail);
die "tail terminato inaspettatamente\n";
