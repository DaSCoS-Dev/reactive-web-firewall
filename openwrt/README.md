<!--
Copyright (C) 2026 Daniele Stefano Continenza <daniele@dascos.info>
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# OpenWrt backend for Reactive Web Firewall

**English** | [Italiano](README.it.md)

The OpenWrt payload is installed or updated by the main wizard through an
administrative SSH session.

## Core

- `/usr/bin/f2b-banip`: temporary and permanent bans in banIP sets.
- `/usr/bin/f2b-banip-wrapper`: restricted SSH forced-command API used by RwF.
- `/usr/sbin/fw-unban-all`: complete administrative IPv4/IPv6 unban.

## Tools

- `/usr/sbin/check-fw-ban`: diagnostic lookup for an IP address.
- `/usr/bin/banip-aggregate-subnets.sh`: blocklist maintenance/aggregation.

`f2b-portban` is not a Reactive Web Firewall dependency and is not installed by
the core. The wrapper keeps compatibility with port-ban commands only when
`/usr/sbin/f2b-portban` is already present.

The existing banIP configuration is preserved. The installer enables only the
minimum options required by the RwF backend and never replaces
`/etc/config/banip` wholesale.

See also the [OpenWrt backend audit](../docs/en/OPENWRT-BACKEND-AUDIT.md).
