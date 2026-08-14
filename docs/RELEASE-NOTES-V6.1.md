<!--
Copyright (C) 2026 Daniele Stefano Continenza <daniele@dascos.info>
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Reactive Web Firewall V6.1

Date: 2026-08-14

## OpenWrt backend becomes distributable

- Adds a versioned OpenWrt payload under `openwrt/`.
- The main installer can install/update that payload through a temporary administrative SSH session.
- Fresh installs generate a dedicated runtime SSH key by default; upgrades reuse the configured runtime key when valid.
- The runtime key remains restricted to `f2b-banip-wrapper`; the bootstrap administrative credential must be distinct.
- `ALLOWED_SOURCES` is derived from `SSH_CONNECTION` as observed by OpenWrt, not from a hardcoded proxy address.
- Existing allowed source IPs are preserved during migration.
- Adds `RWF-OPENWRT-API 1` version/capability discovery.
- Supports both OpenWrt `apk` and legacy `opkg` package-management paths.
- Keeps existing `/etc/config/banip` and authorized keys instead of replacing site configuration.
- Adds remote backup/rollback for modified files, wrapper config, authorized keys, banIP config and prior service state.

## OpenWrt audit fixes

- Removes `f2b-portban` from the RwF core dependency graph.
- Makes wrapper `check` tolerate systems without port-ban.
- Fixes the compatibility parser for `temp-del-port`.
- Adds IPv6 handling to `fw-unban-all`.
- Fixes `check-fw-ban` state propagation.
- Adds `OPENWRT-BACKEND-AUDIT.md`.

## Production audit

- Public baseline uses **10 real unsolicited production bans** collected on a healthy fast path.
- Samples from the temporary known local-fastban regression are excluded rather than simulated or adjusted.
- Installer/self-test traffic is excluded.
- Common N=10 means: helper delivery **0.330 ms**, request-to-local-block **47.308 ms**, request-to-OpenWrt-confirmation **268.434 ms**, complete worker **339.031 ms**.
- Detailed current subset keeps HTTP/1.1, HTTP/2, shared-cache and packet-level FIN/RST evidence.

## Audit helper

Adds `rwf-fish`, installed as `/usr/local/sbin/rwf-fish`, to collect access log, helper journal, Apache RwF debug lines and PCAP evidence for one IP.

## Public distribution hygiene

- Adds project-wide copyright/SPDX notices where the file format permits them.
- Adds `LICENSE` with the GNU Affero General Public License v3 text.
- Adds `COPYRIGHT.md` with explicit project authorship/licensing notice.
- Removes release notes older than V6 from the public package.
