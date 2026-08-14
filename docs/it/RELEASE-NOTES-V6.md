<!--
Copyright (C) 2026 Daniele Stefano Continenza <daniele@dascos.info>
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Reactive Web Firewall V6

[English](../en/RELEASE-NOTES-V6.md) | **Italiano**

Data: 2026-08-13

## Motore di rilevazione

- Aggiunge `RwfRuleTargetRegex`, che valuta un target `path + query` normalizzato usato solo per la detection.
- Le codifiche percentuali stampabili vengono decodificate per due passaggi, coprendo evasione `%2F` e `%252F` senza modificare la URI di Apache.
- Il comportamento Exact/Prefix/Regex esistente resta path-only e retrocompatibile.
- Il self-test HTTP dell'installer valida esplicitamente TargetRegex e il doppio percent-decoding.

## Audit delle regole

- Verifica famiglia per famiglia il watcher Perl immediato legacy.
- Chiude la copertura mancante dei suffissi `.env` e aggiunge `.vscode/sftp.json`, `.DS_Store`, `wp-config.php`.
- Aggiunge copertura completa WordPress batch-v1 per path/query.
- Aggiunge firme SQLi conservative ad alta confidenza sul request target.
- Aggiunge firme note ad alta confidenza per webshell/probe osservate in produzione.
- Lascia alias phpMyAdmin e WordPress XML-RPC disabilitati di default perché possono essere legittimi.
- Non converte le regole response-aware `wp_login` e `php_probe` in blocchi early troppo ampi.
- Vedere `PERL-RULE-AUDIT.md`.

## Merge delle regole sicuro in upgrade

- Le installazioni esistenti possono unire le regole attive preservando regole locali/custom.
- Le regole distribuite mancanti vengono aggiunte per nome.
- Solo le forme legacy esatte e riconosciute di `env-secret` e `wordpress-batch-v1` vengono migrate semanticamente.
- La policy esistente viene mantenuta in tali migrazioni.
- La preservazione della whitelist resta una scelta separata.

## Fast path firewall locale

- Rimuove la validazione Python dal normale percorso add/delete.
- Gli add temporanei tentano prima un singolo `nft add element` diretto.
- Ispezione costosa/ripristino tabella avvengono solo dopo un fallimento.
- Il file lock globale resta riservato alle modifiche persistenti dello stato permanente.
- I ban permanenti restano persistiti e ripristinati al reload del servizio.

Questa modifica ha rimosso una regressione temporanea di sviluppo nel percorso
del firewall locale. L'audit prestazionale pubblico esclude i campioni raccolti
durante quella regressione; vedere `PRODUCTION-REFERENCE.md` per la baseline valida.

## Riferimento di produzione

Aggiunge `PRODUCTION-REFERENCE.md` e `scripts/collect-system-profile.sh` per misure
di produzione sanitizzate e profiling hardware ripetibile.
