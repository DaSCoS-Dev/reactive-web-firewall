#!/usr/bin/perl
# Copyright (C) 2026 Daniele Stefano Continenza <daniele@dascos.info>
# SPDX-License-Identifier: AGPL-3.0-or-later
use strict;
use warnings;
use Getopt::Long qw(GetOptions);
use Socket qw(PF_UNIX SOCK_DGRAM sockaddr_un AF_INET AF_INET6 inet_pton);
use Time::HiRes qw(time);
use FindBin qw($Bin);
use lib $Bin, '/usr/local/lib/reactive-web-firewall';
use RwfLogRules qw(parse_apache_line classify_line);

my $BUILD = '2026.08.14-log-reader-07.0';
my $config_file = '/etc/reactive-web-firewall/log-reader.conf';
my $log_override = '';
my $test_line = '';
my $test_file = '';
my $check_format = '';
my $show_config = 0;
my $show_version = 0;
my $show_help = 0;

GetOptions(
    'config=s'      => \$config_file,
    'log=s'         => \$log_override,
    'test-line=s'   => \$test_line,
    'test-file=s'   => \$test_file,
    'check-format=s'=> \$check_format,
    'show-config'   => \$show_config,
    'version'       => \$show_version,
    'help'          => \$show_help,
) or die "Parametri non validi. Usa --help\n";

if ($show_version) { print "$BUILD\n"; exit 0; }
if ($show_help) {
    print <<'HELP';
Uso:
  rwf-log-reader.pl
  rwf-log-reader.pl --test-line 'riga Apache completa'
  rwf-log-reader.pl --test-file /path/file
  rwf-log-reader.pl --check-format /path/access.log
  rwf-log-reader.pl --show-config

Il motore Log Reader segue in tempo quasi reale un access log Apache, classifica
le firme e invia eventi al comune rwf-helper tramite datagram Unix. Non esegue
nftables, SSH o ss -K direttamente.

Formati supportati:
  IP (vhost:port) ... "METHOD URI HTTP/x" STATUS ... "REF" "UA"
  vhost:port IP ... "METHOD URI HTTP/x" STATUS ... "REF" "UA"
HELP
    exit 0;
}

sub valid_ip {
    my ($ip) = @_;
    my $packed;
    return 0 unless defined $ip && $ip ne '';
    return 1 if inet_pton(AF_INET, $ip);
    return 1 if inet_pton(AF_INET6, $ip);
    return 0;
}

sub logmsg {
    my ($level, $msg) = @_;
    $level ||= 'notice'; $msg ||= '';
    system('logger','-p',"user.$level",'-t','rwf-log-reader','--',$msg);
    if ($test_line ne '' || $test_file ne '' || $check_format ne '' || $show_config) {
        print STDERR "rwf-log-reader[$level]: $msg\n";
    }
}

sub load_config {
    my ($path) = @_;
    open(my $fh,'<',$path) or die "Impossibile leggere $path: $!\n";
    my %cfg; my %rules;
    while (my $line = <$fh>) {
        chomp $line; $line =~ s/\r$//; $line =~ s/^\s+|\s+$//g;
        next if $line eq '' || $line =~ /^#/;
        my ($k,$v) = $line =~ /^([^=]+?)\s*=\s*(.*?)\s*$/;
        die "Riga non valida in $path: $line\n" unless defined $k;
        if ($k =~ /^rule[.](.+)$/) { $rules{$1} = $v; } else { $cfg{$k} = $v; }
    }
    close $fh;
    $cfg{log_file} = $log_override if $log_override ne '';
    $cfg{helper_socket} ||= '/run/reactive-web-firewall/helper.sock';
    $cfg{active_dir} ||= '/run/custom-web-ban/active';
    $cfg{tail_sleep} ||= '0.1';
    $cfg{debounce_seconds} ||= '2';
    die "log_file mancante\n" unless $cfg{log_file};
    die "tail_sleep non valido\n" unless $cfg{tail_sleep} =~ /^(?:0[.][0-9]+|[1-9][0-9]*(?:[.][0-9]+)?)$/;
    die "debounce_seconds non valido\n" unless $cfg{debounce_seconds} =~ /^\d+(?:[.]\d+)?$/;
    for my $rule (keys %rules) {
        my $p = lc($rules{$rule});
        die "Policy non valida per $rule: $rules{$rule}\n"
            unless $p =~ /^(?:off|disabled|0|permanent|perm|1|[1-9][0-9]*(?:[smhdw])?)$/;
    }
    return (\%cfg, \%rules);
}

my ($cfg,$rules) = load_config($config_file);

if ($show_config) {
    print "log_file=$cfg->{log_file}\nhelper_socket=$cfg->{helper_socket}\nactive_dir=$cfg->{active_dir}\n";
    for my $r (sort keys %$rules) { print "rule.$r=$rules->{$r}\n"; }
    exit 0;
}

sub policy_for {
    my ($rule) = @_;
    return $rules->{$rule} // 'off';
}

sub print_match {
    my ($m) = @_;
    my $p = policy_for($m->{rule});
    print join("\t", $m->{ip},$m->{rule},$m->{signature},$p,$m->{vhost},$m->{method},$m->{raw_uri},$m->{status},$m->{proto}),"\n";
}

if ($test_line ne '') {
    my $m = classify_line($test_line); print_match($m) if $m; exit 0;
}
if ($test_file ne '') {
    open(my $fh,'<',$test_file) or die "Impossibile leggere $test_file: $!\n";
    while (my $line=<$fh>) { my $m=classify_line($line); print_match($m) if $m; }
    close $fh; exit 0;
}
if ($check_format ne '') {
    open(my $fh,'<',$check_format) or die "Impossibile leggere $check_format: $!\n";
    my ($total,$parsed)=(0,0); my @buf;
    while (my $line=<$fh>) { push @buf,$line; shift @buf if @buf>200; }
    close $fh;
    for my $line (@buf) { next if $line =~ /^\s*$/; $total++; $parsed++ if parse_apache_line($line); }
    print "total=$total parsed=$parsed\n";
    exit 4 if $total == 0;
    exit($parsed > 0 ? 0 : 3);
}

-f $cfg->{log_file} or die "Log non trovato: $cfg->{log_file}\n";
-S $cfg->{helper_socket} or die "Socket helper non disponibile: $cfg->{helper_socket}\n";

my %recent;
sub marker_active {
    my ($ip) = @_;
    return 0 unless valid_ip($ip);
    my $path = "$cfg->{active_dir}/$ip";
    return 0 unless -f $path;
    open(my $fh,'<',$path) or return 0; my $line=<$fh>; close $fh;
    return 0 unless defined $line;
    my ($expires)=split(/\t/,$line,2);
    return 1 if defined $expires && $expires eq '0';
    return 1 if defined $expires && $expires =~ /^\d+$/ && $expires > time();
    return 0;
}

sub clean_field {
    my ($s) = @_;
    $s //= '-'; $s =~ s/[\t\r\n]/ /g; return $s;
}

sub send_event {
    my ($m,$policy,$ts_us) = @_;
    socket(my $sock, PF_UNIX, SOCK_DGRAM, 0) or return 0;
    my $addr = sockaddr_un($cfg->{helper_socket});
    my $event = join("\t",
        'v=1',
        'ip='.clean_field($m->{ip}),
        'host='.clean_field($m->{vhost}),
        'method='.clean_field($m->{method}),
        'uri='.clean_field($m->{uri}),
        'rule='.clean_field($m->{rule}),
        'policy='.clean_field($policy),
        'ts_us='.$ts_us,
    );
    my $sent = send($sock,$event,0,$addr);
    close $sock;
    return defined($sent) ? $sent : 0;
}

sub process_line {
    my ($line) = @_;
    my $m = classify_line($line) or return;
    my $policy = policy_for($m->{rule});
    return if lc($policy) =~ /^(?:off|disabled|0)$/;
    return if marker_active($m->{ip});
    my $now=time();
    return if exists $recent{$m->{ip}} && $recent{$m->{ip}} > $now;
    my $ts_us = ($m->{apache_end_us} && $m->{apache_end_us}>0) ? $m->{apache_end_us} : int($now*1_000_000);
    my $sent=send_event($m,$policy,$ts_us);
    if ($sent) {
        $recent{$m->{ip}}=$now+$cfg->{debounce_seconds};
        logmsg('notice',"event-sent ip=$m->{ip} rule=$m->{rule} policy=$policy bytes=$sent host=$m->{vhost} method=$m->{method} uri=[$m->{uri}] status=$m->{status} proto=$m->{proto} ts_us=$ts_us");
    } else {
        logmsg('warning',"event-send-failed ip=$m->{ip} rule=$m->{rule} socket=$cfg->{helper_socket}");
    }
    if (keys(%recent)>4096) { for my $ip (keys %recent) { delete $recent{$ip} if $recent{$ip} <= $now; } }
}

logmsg('notice',"start build=$BUILD log=$cfg->{log_file} helper=$cfg->{helper_socket}");
open(my $tail,'-|','tail','-n','0','-F','-s',$cfg->{tail_sleep},'--',$cfg->{log_file})
    or die "Impossibile avviare tail: $!\n";
while (my $line=<$tail>) { process_line($line); }
close $tail;
die "tail terminato inaspettatamente\n";
