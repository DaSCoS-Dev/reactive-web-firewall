#!/usr/bin/env perl
# Copyright (C) 2026 Daniele Stefano Continenza <daniele@dascos.info>
# SPDX-License-Identifier: AGPL-3.0-or-later

# SCOPO / PURPOSE
#   Rileva richieste inequivocabili verso file di segreti, credenziali e configurazione.
#   Detects unambiguous requests for secret, credential and configuration files.
#
# CONFIGURAZIONE / CONFIGURATION
#   Abilitazione e durata del ban non si modificano qui. Usare:
#     policy_env_exploit = off | permanent | 30m | 4h | 3d | 2w ...
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
#   perl -c /etc/reactive-web-firewall/rules.d/040-secret-files.pm
#   sudo reactive-web-validate
#   sudo reactive-web-ban.pl --test-line 'RIGA APACHE COMPLETA'
#
# Le modifiche valide vengono ricaricate automaticamente. In caso di errore
# il watcher conserva l’ultima versione valida già in memoria.
# Valid edits are hot-reloaded. Invalid edits leave the last valid rules active.

use strict;
use warnings;

return {
    name => 'env_exploit',
    description => 'Credential, environment and secret file probes',
    priority => 40,
    default_policy => 'permanent',
    detect => sub {
        my ($c) = @_;
        my $u = $c->{decoded_uri};
        return 'secret-credential-probe'
            if $u =~ m{(?:^|/)\.env(?:[._-][^/?#]*)?(?:$|[/?#])}
            || $u =~ m{(?:^|/)\.aws/credentials(?:$|[?#])}
            || $u =~ m{(?:^|/)\.vscode/sftp\.json(?:$|[?#])}
            || $u =~ m{(?:^|/)\.ds_store(?:$|[?#])}
            || $u =~ m{(?:^|/)wp-config\.php(?:$|[?#])};
        return undef;
    },
};
