<!--
Copyright (C) 2026 Daniele Stefano Continenza <daniele@dascos.info>
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Reactive Web Firewall V7.0

[English](../en/RELEASE-NOTES-V7.md) | **Italiano**

Data di rilascio: 2026-08-14

V7 unifica le due linee storiche di RwF in un solo prodotto e un solo installer.

## Due motori di rilevazione

Il wizard permette di scegliere, in modo mutualmente esclusivo:

- **Inside Apache**, basato su `mod_rwf`;
- **Log Reader**, basato sul nuovo `rwf-log-reader` self-contained.

I due motori producono lo stesso protocollo evento verso `rwf-helper`.

## Enforcement unico

Entrambi possono lavorare con:

- firewall locale standalone;
- firewall locale + OpenWrt.

Il bootstrap OpenWrt, le chiavi SSH, la forced-command API, whitelist, marker
LFD, nftables e socket-kill non sono duplicati fra i motori.

## Nuovo Log Reader

Il vecchio `custom-web-ban-immediate.pl` conteneva sia detection sia enforcement.
V7 ne conserva il valore come sensore post-response ma rimuove dal nuovo motore
le operazioni privilegiate.

Il nuovo Log Reader:

- non dipende da CSF o `regex.custom.pm`;
- supporta il formato RwF storico e Apache `vhost_combined`;
- mantiene le famiglie comuni ad alta confidenza;
- mantiene regole response-context per `wp-login` e probe PHP root-level;
- può migrare le policy note da `custom-web-ban-immediate.conf`;
- invia l'evento al comune socket Unix del helper.

## Installer e migrazione

Il cambio `Inside Apache <-> Log Reader` è trattato come cutover controllato.
Il nuovo motore viene preparato prima di disattivare quello precedente e viene
verificata l'invariante di mutua esclusione al termine.

È stato aggiunto `rwf-status` per mostrare motore, backend, stato servizi/modulo,
regole, whitelist ed eventuali conflitti.

`rwf-fish` è ora engine-aware.

## Audit prestazionale

La baseline pubblicata a N=10 rimane invariata e riguarda il percorso Inside
Apache validato in produzione. I successivi eventi raccolti solo come conferma
non vengono aggiunti retroattivamente al campione né alle medie.
