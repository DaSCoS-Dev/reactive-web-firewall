#!/usr/bin/env perl
# Copyright (C) 2026 Daniele Stefano Continenza <daniele@dascos.info>
# SPDX-License-Identifier: AGPL-3.0-or-later

# SCOPO / PURPOSE
#   Rileva payload SQL injection ad alta confidenza nella URI decodificata.
#   Detects high-confidence SQL injection payloads in the decoded URI.
#
# CONFIGURAZIONE / CONFIGURATION
#   Abilitazione e durata del ban non si modificano qui. Usare:
#     policy_sql_injection = off | permanent | 30m | 4h | 3d | 2w ...
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
#   perl -c /etc/reactive-web-firewall/rules.d/010-sql-injection.pm
#   sudo reactive-web-validate
#   sudo reactive-web-ban.pl --test-line 'RIGA APACHE COMPLETA'
#
# Le modifiche valide vengono ricaricate automaticamente. In caso di errore
# il watcher conserva l’ultima versione valida già in memoria.
# Valid edits are hot-reloaded. Invalid edits leave the last valid rules active.

use strict;
use warnings;

return {
    name => 'sql_injection',
    description => 'High-confidence SQL injection payloads',
    priority => 10,
    default_policy => '2w',
    detect => sub {
        my ($c) = @_;
        my $s = $c->{decoded_uri};

        return 'union-select' if $s =~ /\bunion\s+(?:(?:all|distinct)\s+)?select\b/;
        return 'order-by-probe' if $s =~ /\border\s+by\s+\d{1,5}\b/ && $s =~ /(?:--(?:\s|$)|#|\/\*)/;
        return 'boolean-tautology' if $s =~ /\b(?:and|or)\s*\(?\s*(\d{6,})\s*=\s*\1\s*['"`]/;
        return 'boolean-tautology' if $s =~ /\b(?:and|or)\s*\(?\s*(['"])([a-z0-9_]{6,})\1\s*=\s*\1\2\1\s*['"]/i;
        return 'mysql-error-based' if $s =~ /\b(?:updatexml|extractvalue)\s*\(/ && $s =~ /\b(?:or|and|select|concat|elt)\b/;
        return 'nested-select' if $s =~ /\b(?:and|or)\s*\(?\s*select\b/;
        return 'information-schema' if $s =~ /\binformation_schema\s*\./ && $s =~ /\b(?:select|from|group\s+by)\b/;
        return 'time-based' if $s =~ /\b(?:sleep|benchmark|pg_sleep)\s*\(/;
        return 'mssql-delay' if $s =~ /\bwaitfor\s+delay\b/;
        return 'file-read-write' if $s =~ /\bload_file\s*\(/ || $s =~ /\binto\s+(?:out|dump)file\b/;
        return 'stacked-query' if $s =~ /;\s*(?:select|insert|update|delete|drop|alter|create|truncate)\b/;
        return undef;
    },
};
