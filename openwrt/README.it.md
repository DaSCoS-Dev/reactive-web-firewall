<!--
Copyright (C) 2026 Daniele Stefano Continenza <daniele@dascos.info>
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Backend OpenWrt per Reactive Web Firewall

[English](README.md) | **Italiano**

Il payload OpenWrt viene installato o aggiornato dal wizard principale tramite
una sessione SSH amministrativa.

## Core

- `/usr/bin/f2b-banip`: ban temporanei e permanenti nei set banIP.
- `/usr/bin/f2b-banip-wrapper`: forced-command SSH, API ristretta usata da RwF.
- `/usr/sbin/fw-unban-all`: rimozione amministrativa completa IPv4/IPv6.

## Tools

- `/usr/sbin/check-fw-ban`: diagnostica dello stato di un IP.
- `/usr/bin/banip-aggregate-subnets.sh`: manutenzione/aggregazione della blocklist.

`f2b-portban` non è una dipendenza di Reactive Web Firewall e non viene
installato dal core. Il wrapper mantiene compatibilità con i comandi port-ban
soltanto se `/usr/sbin/f2b-portban` è già presente.

La configurazione banIP esistente viene preservata. L'installer abilita soltanto
le opzioni minime necessarie al backend RwF e non sostituisce integralmente
`/etc/config/banip`.

Vedere anche l'[audit del backend OpenWrt](../docs/it/OPENWRT-BACKEND-AUDIT.md).
