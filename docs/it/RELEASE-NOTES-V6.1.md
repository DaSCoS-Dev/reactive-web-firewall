<!--
Copyright (C) 2026 Daniele Stefano Continenza <daniele@dascos.info>
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Reactive Web Firewall V6.1

[English](../en/RELEASE-NOTES-V6.1.md) | **Italiano**

Data: 2026-08-14

## Il backend OpenWrt diventa distribuibile

- Aggiunge un payload OpenWrt versionato sotto `openwrt/`.
- L'installer principale può installare/aggiornare il payload tramite una sessione SSH amministrativa temporanea.
- Le nuove installazioni generano di default una chiave SSH runtime dedicata; gli upgrade riusano la chiave runtime configurata quando valida.
- La chiave runtime resta limitata a `f2b-banip-wrapper`; la credenziale amministrativa di bootstrap deve essere distinta.
- `ALLOWED_SOURCES` viene ricavato da `SSH_CONNECTION` come osservato da OpenWrt, non da un indirizzo proxy hardcoded.
- Gli IP sorgente già autorizzati vengono preservati durante la migrazione.
- Aggiunge discovery versione/capability `RWF-OPENWRT-API 1`.
- Supporta sia il percorso package manager OpenWrt `apk` sia quello legacy `opkg`.
- Mantiene `/etc/config/banip` e le authorized keys esistenti invece di sostituire la configurazione del sito.
- Aggiunge backup/rollback remoto per file modificati, config wrapper, authorized keys, config banIP e stato precedente del servizio.

## Correzioni dall'audit OpenWrt

- Rimuove `f2b-portban` dal grafo delle dipendenze core RwF.
- Rende `check` del wrapper compatibile con sistemi senza port-ban.
- Corregge il parser di compatibilità per `temp-del-port`.
- Aggiunge gestione IPv6 a `fw-unban-all`.
- Corregge la propagazione dello stato in `check-fw-ban`.
- Aggiunge `OPENWRT-BACKEND-AUDIT.md`.

## Audit di produzione

- La baseline pubblica usa **10 ban reali non sollecitati di produzione** raccolti su un fast path sano.
- I campioni della regressione temporanea nota del local-fastban vengono esclusi invece di essere simulati o corretti.
- Il traffico installer/self-test è escluso.
- Medie comuni N=10: consegna helper **0.330 ms**, richiesta-a-blocco-locale **47.308 ms**, richiesta-a-conferma-OpenWrt **268.434 ms**, worker completo **339.031 ms**.
- Il sottoinsieme dettagliato mantiene evidenze HTTP/1.1, HTTP/2, shared-cache e FIN/RST a livello pacchetto.

## Helper di audit

Aggiunge `rwf-fish`, installato come `/usr/local/sbin/rwf-fish`, per raccogliere
access log, journal del helper, righe debug Apache RwF ed evidenze PCAP per un IP.

## Igiene della distribuzione pubblica

- Aggiunge note copyright/SPDX a livello progetto dove il formato del file lo consente.
- Aggiunge `LICENSE` con il testo GNU Affero General Public License v3.
- Aggiunge `COPYRIGHT.md` con dichiarazione esplicita di paternità/licenza del progetto.
- Rimuove dal pacchetto pubblico le release notes precedenti alla V6.
