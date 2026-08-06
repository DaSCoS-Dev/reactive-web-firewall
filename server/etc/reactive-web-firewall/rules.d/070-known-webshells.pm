#!/usr/bin/env perl
# Copyright (C) 2026 Daniele Stefano Continenza <daniele@dascos.info>
# SPDX-License-Identifier: AGPL-3.0-or-later

# SCOPO / PURPOSE
#   Rileva nomi e percorsi conservativi associati a webshell note.
#   Detects conservative filenames and paths associated with known webshells.
#
# CONFIGURAZIONE / CONFIGURATION
#   Abilitazione e durata del ban non si modificano qui. Usare:
#     policy_known_webshell = off | permanent | 30m | 4h | 3d | 2w ...
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
#   perl -c /etc/reactive-web-firewall/rules.d/070-known-webshells.pm
#   sudo reactive-web-validate
#   sudo reactive-web-ban.pl --test-line 'RIGA APACHE COMPLETA'
#
# Le modifiche valide vengono ricaricate automaticamente. In caso di errore
# il watcher conserva l’ultima versione valida già in memoria.
# Valid edits are hot-reloaded. Invalid edits leave the last valid rules active.

use strict;
use warnings;

return {
    name => 'known_webshell',
    description => 'Known webshell and malicious upload paths',
    priority => 70,
    default_policy => 'permanent',
    detect => sub {
        my ($c) = @_;
        my $u = $c->{decoded_uri};
        return 'known-webshell-probe'
            if $u =~ m{/(?:zwso|mah|shoha|alpha|alpa|alfa|chosen|goods|wp_filemanager|shelp|ms-themes|gifclass|txets|wp_mna|lock360|o-simple|this_is_a_new_hello_world)\.php(?:$|[?#])}i
            || $u =~ m{^/\.wp/wso\.php(?:$|[?#])}i
            || $u =~ m{^/wp-content/plugins/hellopress/[^?#]*\.php(?:$|[?#])}i;
        return undef;
    },
};
