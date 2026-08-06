# Copyright (C) 2026 Daniele Stefano Continenza <daniele@dascos.info>
# SPDX-License-Identifier: AGPL-3.0-or-later

# Optional CSF/LFD integration for Reactive Web Firewall.
# Merge this helper into an existing /usr/local/csf/bin/regex.custom.pm.
# After extracting the client IP, skip the current line with:
#
#     return 0 if rwf_immediate_ban_active($ip);
#
# This prevents queued Apache lines already handled by the millisecond watcher
# from triggering a second, weaker LFD ban.

my $RWF_ACTIVE_DIR = $ENV{REACTIVE_WEB_FIREWALL_ACTIVE_DIR}
    || '/run/reactive-web-firewall/active';

sub rwf_immediate_ban_active {
    my ($ip) = @_;
    return 0 unless defined $ip && $ip ne '';
    return 0 if $ip =~ m{/};

    my $marker = $RWF_ACTIVE_DIR . '/' . $ip;
    return 0 unless -f $marker;

    if (open(my $fh, '<', $marker)) {
        my $line = <$fh>;
        close($fh);
        $line = '' unless defined $line;
        chomp($line);
        my ($expires) = split(/\t/, $line, 2);
        return 1 if defined $expires && $expires eq '0';
        return 1 if defined $expires && $expires =~ /^\d+$/ && $expires > time();
    }

    unlink($marker);
    return 0;
}
