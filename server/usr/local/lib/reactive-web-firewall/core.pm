#!/usr/bin/env perl
# Copyright (C) 2026 Daniele Stefano Continenza <daniele@dascos.info>
# SPDX-License-Identifier: AGPL-3.0-or-later

use strict;
use warnings;

# Funzioni comuni usate dal watcher. Il file viene caricato con require(),
# quindi le funzioni restano nel namespace del chiamante.
# Common watcher functions. Loaded with require(), therefore functions remain
# in the caller namespace.

sub parse_apache_line {
    my ($line) = @_;
    return undef unless defined $line;

    # Formato atteso / expected format:
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

sub normalize_request_uri {
    my ($raw) = @_;
    $raw = '' unless defined $raw;

    my $path = $raw;
    my $suffix = '';
    if ($path =~ s/([?#].*)$//) { $suffix = $1; }

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

1;
