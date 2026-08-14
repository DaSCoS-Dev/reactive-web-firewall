<!--
Copyright (C) 2026 Daniele Stefano Continenza <daniele@dascos.info>
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Audit delle regole Perl legacy → Reactive Web Firewall

[English](../en/PERL-RULE-AUDIT.md) | **Italiano**

Data audit: 2026-08-14

Questo documento registra lo stato di migrazione delle famiglie di ban immediato
ad alta confidenza usate dal watcher legacy `custom-web-ban-immediate.pl`. Da V7,
RwF dispone di due motori di rilevazione mutualmente esclusivi: **Inside Apache**,
che lavora prima che esista la risposta finale, e **Log Reader**, che può
mantenere in sicurezza le regole basate sul contesto della risposta. Entrambi
condividono l'enforcement tramite `rwf-helper`.

## Risultato dell'audit

| Famiglia legacy | Policy legacy | Stato V7 | Implementazione V7 / motivo |
|---|---:|---|---|
| `git_exploit` | permanent | Coperta | `.git` più regole per i path dei metadati repository. |
| `env_exploit` | permanent | Coperta ed estesa | Varianti `.env`, `web.config`, rclone, credenziali AWS, `.vscode/sftp.json`, `.DS_Store`, `wp-config.php`, fingerprint scanner. |
| `framework_exploit` | permanent | Coperta | Probe PHPUnit diretti/vendor. |
| `xmlrpc` | 3d | Disponibile, disabilitata di default | `/xmlrpc.php` può essere legittimo su WordPress; il pacchetto generico la lascia commentata. |
| `wp_batch` | 3d | Coperta da V6 | Il nuovo `RwfRuleTargetRegex` copre sia `/wp-json/batch/v1` sia `?rest_route=/batch/v1`. |
| `sql_injection` | 2w | Sottoinsieme conservativo ad alta confidenza | Regole target per `UNION ... SELECT` e probe MySQL `extractvalue()/updatexml()`. V6 non pretende di essere un WAF SQL generalista. |
| `known_webshell` | permanent | Coperta | Nomi shell legacy noti, `/.wp/wso.php`, probe PHP HelloPress. |
| `phpmyadmin_probe` | permanent | Disponibile, disabilitata di default | I path standard phpMyAdmin possono essere legittimi su altre installazioni. |
| `php_probe` | 1h | Solo Log Reader | Conservata come `generic-root-php-context`; intenzionalmente assente dalle regole early di Inside Apache. |
| `wp_login` | 4h | Solo Log Reader | Conservata come `wordpress-wp-login-context`; intenzionalmente assente dalle regole early di Inside Apache. |

## Perché esiste `RwfRuleTargetRegex`

Le regole path precedenti ispezionavano `r->uri` di Apache. Questo esclude
correttamente la query string, ma impediva di riprodurre questa firma legacy:

```text
POST /?rest_route=/batch/v1
```

Il motore Inside Apache aggiunge:

```text
RwfRuleTargetRegex <name> <regex> <policy>
```

Valuta un target usato solo per la detection, costruito come `path + ?query`.
Le codifiche percentuali stampabili vengono decodificate per due passaggi, quindi
sia `%2F` sia `%252F` risultano visibili come `/` al rilevatore. RwF non riscrive
mai la request URI di Apache.

`RwfRuleRegex` resta path-only, preservando la semantica precedente.

## Correzioni di parità per i file segreti

Il watcher legacy intercettava anche valori quali:

```text
.env.local
.env-prod
.vscode/sftp.json
.DS_Store
wp-config.php
```

La regex generica `.env` precedente non copriva tutte le varianti con suffisso.
La migrazione `env-secret` di Inside Apache chiude quel gap e aggiunge gli altri
path segreti espliciti.

## Ambito SQL injection

Il watcher immediato legacy delegava la classificazione SQLi al codice regex
condiviso con CSF. Le evidenze di produzione confermano almeno queste firme ad
alta confidenza:

- `UNION [ALL|DISTINCT] SELECT`
- probe MySQL error-based tramite `extractvalue(...)`
- probe MySQL error-based tramite `updatexml(...)`

Inside Apache le implementa come regole target con policy di 2 settimane. Non
abilita intenzionalmente rilevazione generica basata solo su keyword, nomi di
funzioni time-based o euristiche ampie su quote/parentesi, perché molto più
dipendenti dall'applicazione.

## Nuove firme osservate in produzione

Durante la validazione live sul reverse proxy di produzione sono stati osservati
ulteriori path scanner/backdoor ad alta confidenza, distribuiti da V6 in modo
indipendente dall'audit legacy:

- `/wp-plain.php`
- `/wp-content/themes/seotheme/db.php`
- `/wp-content/plugins/apikey/apikey.php`
- `/wp-content/plugins/apikey/apikey.php.suspected`
- `/(ALFA_DATA/)?alfacgiapi/perl.alfa`
- `/plugins/content/apismtp/apismtp.php`
- `/plugins/content/apismtp/apismtp.php.suspected`

I primi cinque sono trattati come probe permanenti ad alta confidenza; le firme
`apismtp` osservate sul campo usano 2 settimane.

## Scelte di sicurezza del pacchetto generico

Il pacchetto predefinito lascia intenzionalmente commentati:

```text
alias standard phpMyAdmin
WordPress xmlrpc.php
```

Un amministratore può abilitarli quando la conoscenza dell'applicazione locale
li rende inequivocabilmente malevoli.

Il motore Log Reader conserva le due famiglie response-context rappresentabili in
sicurezza dai dati dell'access log:

```text
probe response-context *.php generici a livello root
probe response-context wp-login.php
```

Le famiglie di enumerazione basate su burst/rate restano fuori dal core generico
V7 finché non viene introdotto un design dedicato per lo stato del rate. È una
scelta intenzionale: V7 non trasforma un'euristica di frequenza in un ban per
singola richiesta soltanto per ottenere parità.
