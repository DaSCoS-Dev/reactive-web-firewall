<!--
Copyright (C) 2026 Daniele Stefano Continenza <daniele@dascos.info>
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Architettura dei motori di rilevazione

[English](../en/ENGINE-ARCHITECTURE.md) | **Italiano**

## Obiettivo progettuale

RwF V7 separa il punto in cui un attacco viene **rilevato** dal punto in cui il
ban viene **applicato**. Questo evita di mantenere due implementazioni parallele
di nftables, `ss -K`, SSH/OpenWrt, whitelist e marker LFD.

```text
Inside Apache ─┐
               ├─ event v=1 ─> rwf-helper ─> local-only / OpenWrt
Log Reader ────┘
```

## Mutua esclusione

I due motori di rilevazione sono mutualmente esclusivi:

- `inside-apache`: `rwf_module` caricato, `rwf-log-reader.service` inattivo;
- `log-reader`: `rwf_module` non caricato, `rwf-log-reader.service` attivo.

`rwf-status` segnala un errore se rileva entrambi contemporaneamente.

## Protocollo evento

Entrambi inviano un datagram Unix a:

```text
/run/reactive-web-firewall/helper.sock
```

Formato corrente:

```text
v=1\tip=<ip>\thost=<host>\tmethod=<method>\turi=<target>\trule=<rule>\tpolicy=<policy>\tts_us=<epoch-us>
```

Il helper tratta `rule` e `policy` come input autorevoli dopo la propria
validazione e verifica nuovamente la whitelist prima di applicare qualsiasi ban.

## Inside Apache

Vantaggi:

- decisione prima dell'applicazione;
- shared cache fra processi/thread Apache;
- blocco parallelo mentre nftables/OpenWrt sono ancora in lavorazione;
- chiusura/abort della connessione;
- supporto a path e request target normalizzato.

Limite strutturale: il hook early non conosce ancora lo status HTTP finale e
non può basare una firma sul risultato dell'applicazione.

## Log Reader

Vantaggi:

- non carica codice nel processo Apache;
- non richiede APXS o header di sviluppo Apache;
- può usare status HTTP, referrer, user-agent e protocollo registrati nel log;
- conserva le famiglie response-context del watcher originario.

Limite strutturale: la richiesta è già arrivata al punto in cui Apache scrive la
riga di access log, quindi non offre la stessa finestra preventiva di `mod_rwf`.

Il sensore non contiene funzioni privilegiate di ban. Classifica la richiesta e
invia l'evento al helper comune.

## Migrazione e cutover

Il nuovo motore viene preparato e validato prima di fermare il precedente.
Durante il cutover, quando è sicuro farlo, il nuovo motore viene portato
operativo prima di rimuovere quello precedente. Nel passaggio Inside Apache →
Log Reader può esistere una brevissima sovrapposizione controllata: il marker
comune del helper impedisce al Log Reader di duplicare un evento già gestito da
`mod_rwf`.

Il watcher Perl originario possedeva invece un enforcement autonomo e viene
quindi fermato prima di avviare il nuovo Log Reader.

Al termine:

1. Apache viene sottoposto a `configtest` e reload quando necessario;
2. viene verificato che esattamente un motore di rilevazione sia operativo;
3. in caso di errore la trap dell'installer ripristina i file di detection dal
   backup e tenta di riattivare il motore rilevato prima del cutover.

## Backend di enforcement

### Local-only

Il firewall locale è autorevole e usa la policy completa della regola.

### OpenWrt

Il firewall locale agisce come bridge/fallback rapido. Il helper esegue poi il
comando remoto versionato e, dopo la conferma, rimuove il fallback locale.

La procedura OpenWrt è identica per entrambi i motori di rilevazione.
