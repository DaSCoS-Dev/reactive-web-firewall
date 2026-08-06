#!/usr/bin/env perl
# Copyright (C) 2026 Daniele Stefano Continenza <daniele@dascos.info>
# SPDX-License-Identifier: AGPL-3.0-or-later

use strict;
use warnings;

# Reactive Web Firewall standalone detector.
# Loaded with require() by reactive-web-ban.pl, therefore functions are kept
# in the caller's namespace instead of a Perl package.

my $RWF_BAD_UA_RE = qr/(?:
    bytespider|babbar|barkrowler|ahrefs|semrush|mj12|l9scan|leakix|
    zgrab|masscan|sqlmap|nikto|dirbuster|gobuster|acunetix|netsparker|
    python-requests|go-http-client|curl|wget|okhttp|libwww-perl|perl
)/ix;

sub is_bad_ua {
    my ($ua) = @_;
    $ua = '' unless defined $ua;
    return $ua =~ $RWF_BAD_UA_RE ? 1 : 0;
}

sub normalize_request_uri {
    my ($raw) = @_;
    $raw = '' unless defined $raw;

    my $path = $raw;
    my $suffix = '';
    if ($path =~ s/([?#].*)$//) {
        $suffix = $1;
    }

    my $had_repeated_slash = ($path =~ m{//}) ? 1 : 0;
    $path =~ s{/+}{/}g;
    $path = '/' if $path eq '';

    return ($path . $suffix, $path, $had_repeated_slash);
}

sub decode_uri_for_detection {
    my ($value) = @_;
    $value = '' unless defined $value;

    for (1 .. 3) {
        my $before = $value;
        $value =~ s/%([0-9A-Fa-f]{2})/chr(hex($1))/eg;
        last if $value eq $before;
    }

    $value =~ tr/+/ /;
    $value =~ s/[\x00-\x20\x7f]+/ /g;
    $value =~ s/\s+/ /g;
    return lc($value);
}

sub sql_injection_signature {
    my ($raw) = @_;
    my $s = decode_uri_for_detection($raw);

    return 'union-select'
        if $s =~ /\bunion\s+(?:(?:all|distinct)\s+)?select\b/;

    return 'order-by-probe'
        if $s =~ /\border\s+by\s+\d{1,5}\b/
        && $s =~ /(?:--(?:\s|$)|#|\/\*)/;

    return 'boolean-tautology'
        if $s =~ /\b(?:and|or)\s*\(?\s*(\d{6,})\s*=\s*\1\s*['"`]/;

    return 'boolean-tautology'
        if $s =~ /\b(?:and|or)\s*\(?\s*(['"])([a-z0-9_]{6,})\1\s*=\s*\1\2\1\s*['"]/i;

    return 'mysql-error-based'
        if $s =~ /\b(?:updatexml|extractvalue)\s*\(/
        && $s =~ /\b(?:or|and|select|concat|elt)\b/;

    return 'nested-select'
        if $s =~ /\b(?:and|or)\s*\(?\s*select\b/;

    return 'information-schema'
        if $s =~ /\binformation_schema\s*\./
        && $s =~ /\b(?:select|from|group\s+by)\b/;

    return 'time-based'
        if $s =~ /\b(?:sleep|benchmark|pg_sleep)\s*\(/;

    return 'mssql-delay'
        if $s =~ /\bwaitfor\s+delay\b/;

    return 'file-read-write'
        if $s =~ /\bload_file\s*\(/
        || $s =~ /\binto\s+(?:out|dump)file\b/;

    return 'stacked-query'
        if $s =~ /;\s*(?:select|insert|update|delete|drop|alter|create|truncate)\b/;

    return '';
}

sub parse_apache_line {
    my ($line) = @_;
    return undef unless defined $line;

    # Expected format:
    # IP (vhost:port) ident user [timestamp] "METHOD URI PROTO" STATUS BYTES "REF" "UA"
    if ($line =~ /^(\S+)\s+\(([^)]+)\)\s+.*\[[^\]]+\]\s+"(\S+)\s+(\S+)\s+([^"]+)"\s+(\d{3})\s+\S+\s+"([^"]*)"\s+"([^"]*)"/) {
        my ($ip, $vhost, $method, $uri, $proto, $status, $ref, $ua) =
            ($1, $2, $3, $4, $5, $6, $7, $8);
        $vhost = lc($vhost);
        $vhost =~ s/:\d+$//;
        return {
            ip => $ip, vhost => $vhost, method => $method, uri => $uri,
            proto => $proto, status => $status, ref => $ref, ua => $ua,
        };
    }

    return undef;
}

1;
