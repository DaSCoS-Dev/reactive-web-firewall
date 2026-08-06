#!/usr/bin/env perl
# Copyright (C) 2026 Daniele Stefano Continenza <daniele@dascos.info>
# SPDX-License-Identifier: AGPL-3.0-or-later

# SCOPO / PURPOSE
#   Rileva probe generici verso file PHP radice, con esclusioni e condizioni restrittive.
#   Detects generic root-level PHP probes with exclusions and restrictive conditions.
#
# CONFIGURAZIONE / CONFIGURATION
#   Abilitazione e durata del ban non si modificano qui. Usare:
#     policy_php_probe = off | permanent | 30m | 4h | 3d | 2w ...
#   nel file /etc/reactive-web-firewall/reactive-web-firewall.conf.
#   Enable/disable and ban duration belong in the central configuration file.
#
# MODIFICA / EDITING
#   Modificare soltanto la logica dentro detect e mantenere firme ad alta
#   confidenza. detect riceve un hash con decoded_uri, decoded_path, status,
#   ref, ua, method, vhost e ip. Deve restituire una breve firma oppure undef.
#   Edit only the logic inside detect and keep signatures high-confidence.
#
# VALIDAZIONE / VALIDATION
#   perl -c /etc/reactive-web-firewall/rules.d/090-generic-php-probes.pm
#   sudo reactive-web-validate
#   sudo reactive-web-ban.pl --test-line 'RIGA APACHE COMPLETA'
#
# Le modifiche valide vengono ricaricate automaticamente. In caso di errore
# il watcher conserva l’ultima versione valida già in memoria.
# Valid edits are hot-reloaded. Invalid edits leave the last valid rules active.

use strict;
use warnings;

return {
    name => 'php_probe',
    description => 'Suspicious root-level PHP filename probe',
    priority => 90,
    default_policy => '1h',
    detect => sub {
        my ($c) = @_;

        my $is_bad_ua = sub {
            my ($ua) = @_;
            $ua = '' unless defined $ua;
            return $ua =~ /(?:bytespider|babbar|barkrowler|ahrefs|semrush|mj12|l9scan|leakix|zgrab|masscan|sqlmap|nikto|dirbuster|gobuster|acunetix|netsparker|python-requests|go-http-client|curl|wget|okhttp|libwww-perl|perl)/i ? 1 : 0;
        };

        my $path = $c->{decoded_path};
        my $is_ert = ($path eq '/wp-content/plugins/easy-responsive-tabs/assets/css/ert_css.php'
            || $path eq '/wp-content/plugins/easy-responsive-tabs/assets/js/ert_js.php') ? 1 : 0;

        my %safe_php = map { $_ => 1 } qw(
            index.php admin.php login.php wp-login.php xmlrpc.php wp-cron.php
            wp-comments-post.php wp-trackback.php wp-signup.php wp-activate.php
            admin-ajax.php
        );
        my ($basename) = $path =~ m{/([^/]+)$};
        $basename ||= '';

        return 'generic-php-probe'
            if !$is_ert
            && $path =~ m{^/[a-z0-9][a-z0-9_.-]{0,50}\.php$}i
            && !$safe_php{lc($basename)}
            && $c->{status} =~ /^(?:301|302|403|404|410|503)$/
            && ($c->{ref} eq '-' || $c->{ref} eq '')
            && ($c->{ua} eq '-' || $c->{ua} eq '' || $is_bad_ua->($c->{ua}));

        return undef;
    },
};
