#!/usr/bin/env perl
# Copyright (C) 2026 Daniele Stefano Continenza <daniele@dascos.info>
# SPDX-License-Identifier: AGPL-3.0-or-later

# SCOPO / PURPOSE
#   Rileva accessi diretti a xmlrpc.php di WordPress.
#   Detects direct access to WordPress xmlrpc.php.
#
# CONFIGURAZIONE / CONFIGURATION
#   Abilitazione e durata del ban non si modificano qui. Usare:
#     policy_xmlrpc = off | permanent | 30m | 4h | 3d | 2w ...
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
#   perl -c /etc/reactive-web-firewall/rules.d/060-xmlrpc.pm
#   sudo reactive-web-validate
#   sudo reactive-web-ban.pl --test-line 'RIGA APACHE COMPLETA'
#
# Le modifiche valide vengono ricaricate automaticamente. In caso di errore
# il watcher conserva l’ultima versione valida già in memoria.
# Valid edits are hot-reloaded. Invalid edits leave the last valid rules active.

use strict;
use warnings;

return {
    name => 'xmlrpc',
    description => 'Direct WordPress xmlrpc.php access',
    priority => 60,
    default_policy => '3d',
    detect => sub {
        my ($c) = @_;
        return 'xmlrpc' if $c->{decoded_path} eq '/xmlrpc.php';
        return undef;
    },
};
