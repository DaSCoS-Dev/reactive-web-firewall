<!--
Copyright (C) 2026 Daniele Stefano Continenza <daniele@dascos.info>
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Detection-engine architecture

## Design goal

RwF V7 separa il punto in cui un attacco viene **rilevato** dal punto in cui il
ban viene **applicato**. Questo evita due implementazioni parallele di nftables,
`ss -K`, SSH/OpenWrt, whitelist e marker LFD.

```text
Inside Apache ─┐
               ├─ event v=1 ─> rwf-helper ─> local-only / OpenWrt
Log Reader ────┘
```

## Mutua esclusione

I due motori di detection sono mutualmente esclusivi:

- `inside-apache`: `rwf_module` caricato, `rwf-log-reader.service` inactive;
- `log-reader`: `rwf_module` non caricato, `rwf-log-reader.service` active.

`rwf-status` segnala errore se rileva entrambi contemporaneamente.

## Event protocol

Entrambi inviano un Unix datagram a:

```text
/run/reactive-web-firewall/helper.sock
```

Formato corrente:

```text
v=1\tip=<ip>\thost=<host>\tmethod=<method>\turi=<target>\trule=<rule>\tpolicy=<policy>\tts_us=<epoch-us>
```

Il helper tratta `rule` e `policy` come input autorevoli dopo la propria
validazione e applica nuovamente la whitelist prima di qualunque ban.

## Inside Apache

Vantaggi:

- decisione prima dell'applicazione;
- shared cache fra processi/thread Apache;
- blocco parallelo mentre nftables/OpenWrt sono ancora in lavorazione;
- chiusura/abort della connessione;
- supporto a path e request target normalizzato.

Limite strutturale: il hook early non conosce ancora lo status HTTP finale e
non può basare una firma sul risultato applicativo.

## Log Reader

Vantaggi:

- non carica codice nel processo Apache;
- non richiede APXS/header Apache;
- può usare status HTTP, referrer, UA e protocollo registrati nel log;
- conserva le famiglie response-context del watcher originario.

Limite strutturale: la richiesta è già arrivata al punto in cui Apache scrive la
riga di access log, quindi non offre la stessa finestra preventiva di mod_rwf.

Il sensore non contiene funzioni privilegiate di ban. Classifica e invia eventi
al helper comune.

## Migration/cutover

Il nuovo motore viene preparato e validato prima di fermare il precedente.
Durante il cutover il nuovo motore viene portato operativo prima di rimuovere
quello precedente quando questo è sicuro. Nel passaggio Inside Apache → Log
Reader può esistere una brevissima sovrapposizione controllata: il marker comune
del helper impedisce al Log Reader di duplicare un evento già preso da mod_rwf.
Il watcher Perl originario, che possedeva ancora un enforcement autonomo, viene
invece fermato prima di avviare il nuovo Log Reader.

Al termine:

1. Apache viene sottoposto a `configtest` e reload quando necessario;
2. viene verificato che esattamente un motore sia operativo;
3. in caso di errore la trap dell'installer ripristina i file di detection dal
   backup e tenta di riattivare il motore rilevato prima del cutover.

## Enforcement backend

### Local-only

Il firewall locale è autorevole e usa la policy completa della regola.

### OpenWrt

Il firewall locale è un bridge/fallback rapido. Il helper esegue poi il comando
remoto versionato e, dopo conferma, rimuove il fallback locale.

La procedura OpenWrt è identica per entrambi i motori di detection.
