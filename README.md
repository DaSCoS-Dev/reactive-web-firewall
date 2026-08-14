<!--
Copyright (C) 2026 Daniele Stefano Continenza <daniele@dascos.info>
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Reactive Web Firewall

Reactive Web Firewall (RwF) è un sistema di rilevazione e blocco per Apache con
**due motori di detection mutualmente esclusivi** e un unico percorso di
enforcement privilegiato.

Versione pacchetto: **V7.0 / installer `2026.08.14-installer-07.0`**.

## Architettura

```text
                     DETECTION
              ┌──────────┴──────────┐
              │                     │
        Inside Apache           Log Reader
          mod_rwf             rwf-log-reader
              │                     │
              └──────────┬──────────┘
                         │ v=1 event / Unix datagram
                         ▼
                    rwf-helper
                         │
              ┌──────────┴──────────┐
              │                     │
          LOCAL-ONLY              OPENWRT
              │                     │
       nftables + ss -K       nftables bridge
                                    │
                                   SSH
                                    │
                                 OpenWrt
```

I due motori non devono essere attivi contemporaneamente. L'installer verifica
questa invariante dopo ogni installazione o migrazione.

## I quattro profili installabili

| Detection engine | Backend | Comportamento |
|---|---|---|
| Inside Apache | Local-only | blocco precoce in Apache + nftables locale autorevole |
| Inside Apache | OpenWrt | blocco precoce + bridge locale + ban OpenWrt |
| Log Reader | Local-only | lettura access log + nftables locale autorevole |
| Log Reader | OpenWrt | lettura access log + bridge locale + ban OpenWrt |

### Inside Apache

`mod_rwf` lavora nel ciclo della richiesta Apache, prima dell'applicazione. Può
quindi creare la shared cache, bloccare richieste parallele e chiudere/abortire
connessioni prima che nftables o OpenWrt abbiano terminato.

Richiede gli header di sviluppo Apache e APXS sulla macchina di destinazione.

### Log Reader

`rwf-log-reader` segue in tempo quasi reale un access log Apache e classifica le
richieste **dopo** che Apache ha scritto la riga. Non richiede APXS né carica
codice nel processo Apache.

Il motore è self-contained e non dipende da CSF. Mantiene inoltre famiglie che
necessitano del contesto della risposta, fra cui `wp-login` e alcuni probe PHP
root-level che non possono essere trasformati in sicurezza in regole early-path.

Formati di access log supportati:

```text
IP (vhost:port) ... "METHOD URI HTTP/x" STATUS ... "REF" "UA"
vhost:port IP ... "METHOD URI HTTP/x" STATUS ... "REF" "UA"
```

Il campo opzionale `apache_end_us=<microseconds>` viene usato, se presente, come
timestamp sorgente dell'evento per misurare anche la latenza di consegna del log.

## Enforcement comune

Entrambi i motori inviano lo stesso protocollo evento `v=1` a:

```text
/run/reactive-web-firewall/helper.sock
```

`rwf-helper` applica whitelist, marker di compatibilità LFD, firewall locale,
`ss -K` e, quando configurato, OpenWrt. Né `mod_rwf` né `rwf-log-reader` hanno
privilegi per manipolare direttamente il firewall remoto.

### LOCAL-ONLY

La policy della regola è autorevole sul firewall locale:

```text
30s / 30m / 4h / 3d / 2w / permanent
```

I ban permanenti sono persistiti e ripristinati al boot.

### OPENWRT

Il percorso è:

```text
evento
  -> fast-ban locale temporaneo
  -> ss -K pre
  -> SSH OpenWrt temp-add/sync-add
  -> ss -K post
  -> conferma remota
     -> rimozione del bridge locale
```

Se OpenWrt non conferma, il fallback locale resta attivo fino al TTL configurato.

## Backend OpenWrt distribuibile

Il pacchetto contiene anche il lato OpenWrt. Il wizard può installarlo o
aggiornarlo via SSH amministrativo e poi usare una chiave runtime dedicata con
forced-command.

L'IP autorizzato non è hardcoded: durante il bootstrap OpenWrt usa il primo
campo di `SSH_CONNECTION`, cioè l'indirizzo sorgente del server RwF **come viene
realmente visto dal firewall**. Le sorgenti già autorizzate vengono preservate.

Il runtime remoto espone una piccola API versionata, ad esempio:

```text
version
capabilities
temp-add <ip> <seconds> proxy <source>
sync-add <ip>
unban-all <ip>
```

Vedere `docs/OPENWRT-BACKEND-AUDIT.md`.

## Regole

### Inside Apache

File:

```text
/etc/reactive-web-firewall/apache-rules.conf
```

Sintassi:

```apache
RwfRuleExact       <name> <path>  <policy>
RwfRulePrefix      <name> <path>  <policy>
RwfRuleRegex       <name> <regex> <policy>
RwfRuleTargetRegex <name> <regex> <policy>
```

### Log Reader

File:

```text
/etc/reactive-web-firewall/log-reader.conf
```

Esempio:

```ini
log_file=/var/log/apache2/other_vhosts_access.log
rule.git-repository=permanent
rule.wordpress-batch-v1=3d
rule.wordpress-wp-login-context=4h
rule.phpmyadmin-standard=off
```

Le famiglie ad alta confidenza sono mantenute allineate fra i due motori dove
il dato disponibile lo permette. Le regole che richiedono status/referrer/UA
restano intenzionalmente Log Reader-only.

## Whitelist

Unico file condiviso:

```text
/etc/reactive-web-firewall/whitelist.conf
```

Sintassi:

```apache
RwfWhitelistIP 192.0.2.10/32
RwfWhitelistIP 2001:db8::/32
```

Il helper verifica sempre la whitelist. Inside Apache la verifica anche prima
di generare l'evento.

## Installazione

```bash
sha256sum -c SHA256SUMS
./install.sh
```

Il wizard:

1. rileva piattaforma, Apache e un'eventuale installazione RwF precedente;
2. chiede `Inside Apache` oppure `Log Reader`;
3. installa solo le dipendenze necessarie al motore scelto;
4. valida la configurazione Apache esistente;
5. preserva whitelist e configurazioni compatibili;
6. per Log Reader verifica realmente il formato del log scelto;
7. chiede `LOCAL-ONLY` oppure `OPENWRT`;
8. per OpenWrt esegue host-key check, chiave runtime, bootstrap remoto e self-test;
9. compila sempre il helper C e compila `mod_rwf` solo per Inside Apache;
10. prepara il nuovo motore prima di spegnere quello precedente;
11. avvia l'enforcement comune;
12. esegue il cutover e rende i motori mutualmente esclusivi;
13. esegue i self-test specifici;
14. verifica l'invariante finale tramite `rwf-status`.

Se viene trovato il watcher originale `custom-web-ban-immediate.pl`, viene
considerato un predecessore del Log Reader. Se si migra al nuovo Log Reader,
l'installer traduce anche le policy note della vecchia configurazione quando
possibile; il vecchio servizio viene fermato solo durante il cutover.

## Stato e diagnostica

```bash
rwf-status
```

Mostra motore attivo, backend, stato modulo/service/helper/firewall, numero di
regole e un eventuale conflitto fra i due motori.

Per una raccolta forense:

```bash
rwf-fish <IP>
rwf-fish <IP> '2 hours ago'
```

L'output si adatta automaticamente al motore configurato.

## Struttura repository

```text
src/                 mod_rwf + helper C
log-reader/          sensore Perl self-contained
config/              regole/whitelist Inside Apache
apache/              template Apache
local-firewall/      nftables fast-ban comune
openwrt/             backend remoto e bootstrap
systemd/             unit comuni e Log Reader
scripts/             installer helpers, self-test, status, audit
docs/                architettura, audit e release notes
install.sh
uninstall.sh
```

## Dipendenze

Il Log Reader **non richiede** i pacchetti development Apache/APXS. Inside Apache
sì. Entrambi richiedono gli strumenti necessari a compilare il piccolo helper C,
Perl, nftables e `iproute2`/equivalente.

OpenSSH client viene richiesto solo scegliendo OpenWrt.

## Prestazioni

`docs/PRODUCTION-REFERENCE.md` contiene la baseline osservata sul motore Inside
Apache con 10 eventi reali validi. I campioni appartenenti a una regressione di
sviluppo nota e i self-test sintetici sono esclusi. Il report non attribuisce
quelle statistiche al Log Reader, che ha una finestra di rilevazione diversa per
definizione.

## Licenza e copyright

Copyright (C) 2026 Daniele Stefano Continenza <daniele@dascos.info>.

Licenza: **GNU Affero General Public License v3 o successiva**
(`AGPL-3.0-or-later`). Vedere `LICENSE` e `COPYRIGHT.md`.
