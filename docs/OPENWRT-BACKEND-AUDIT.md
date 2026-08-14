<!--
Copyright (C) 2026 Daniele Stefano Continenza <daniele@dascos.info>
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# OpenWrt backend audit

This document records the dependency audit used to turn the OpenWrt side of Reactive Web Firewall into a distributable component rather than an external prerequisite.

## Runtime dependency map

```text
Apache proxy / rwf-helper
        │
        │ SSH runtime key, forced command
        ▼
/usr/bin/f2b-banip-wrapper
        │
        ├─ temp-add / temp-del
        ├─ sync-add / sync-del
        └─ unban-all
              │
              ├─ /usr/bin/f2b-banip
              │    ├─ nft table inet banIP
              │    ├─ blocklist.v4 / blocklist.v6
              │    ├─ /etc/banip/banip.blocklist
              │    └─ conntrack cleanup
              │
              └─ /usr/sbin/fw-unban-all
```

## Classification

| Component | Classification | Notes |
|---|---|---|
| `/usr/bin/f2b-banip` | CORE | global temporary/permanent ban engine |
| `/usr/bin/f2b-banip-wrapper` | CORE | restricted SSH API / forced command |
| `/usr/sbin/fw-unban-all` | CORE/ADMIN | full rollback/manual unban; IPv4/IPv6 |
| `/usr/sbin/check-fw-ban` | TOOL | diagnostic state lookup |
| `/usr/bin/banip-aggregate-subnets.sh` | TOOL | blocklist maintenance/aggregation |
| `/usr/sbin/f2b-portban` | NOT REQUIRED | separate port-specific Fail2ban subsystem |
| `/etc/config/banip` | SITE CONFIG | never copied wholesale |
| `/etc/dropbear/authorized_keys` | SITE CONFIG | merged, never replaced |

## Installer behavior

When OpenWrt mode is selected, the proxy installer:

1. validates the firewall host key;
2. selects or creates a dedicated runtime SSH key;
3. tests an already-present backend if available;
4. can bootstrap/update the bundled payload through a separate administrative SSH session;
5. derives `ALLOWED_SOURCES` from the first field of `SSH_CONNECTION` **as seen by OpenWrt**;
6. preserves pre-existing allowed source IPs when migrating an older hardcoded wrapper;
7. adds/normalizes the runtime public key with `command="/usr/bin/f2b-banip-wrapper"` and forwarding/PTY restrictions;
8. installs `banip` and `conntrack` only when required;
9. preserves `/etc/config/banip`, changing only the minimum enable/autoblocklist settings;
10. performs a local TEST-NET add/delete and then the normal remote runtime test from the proxy.

The runtime key does not need an unrestricted root shell. Administrative SSH is needed only for install/update of the OpenWrt payload.

## Source-address restriction

`ALLOWED_SOURCES` is not hardcoded in the distribution. The authoritative value is the client address reported in the bootstrap session's `SSH_CONNECTION` variable on OpenWrt.

If the local proxy routing table reports a different source address, the installer warns and requests confirmation rather than silently choosing one.

The authorized-key line deliberately does not depend on OpenSSH-only source restriction options. Source validation is repeated in `f2b-banip-wrapper`, keeping the backend compatible with the Dropbear SSH server normally used by OpenWrt.

## API

The restricted wrapper exposes:

```text
version
capabilities
check
check-ip <IP>
temp-add <IP> <seconds> [host source]
temp-del <IP> [host source]
sync-add <IP> [host source]
sync-del <IP> [host source]
unban-all <IP>
```

Port-specific commands remain available only when the separate `f2b-portban` subsystem is already installed.

`version` currently returns:

```text
RWF-OPENWRT-API 1
```

## Corrections made during audit

- `ALLOWED_SOURCES` moved from hardcoded wrapper data to `/etc/f2b-banip-wrapper.conf`.
- Existing hardcoded source lists are migrated and preserved.
- `check` no longer makes `f2b-portban` an artificial runtime dependency.
- `temp-del-port` argument-count validation was corrected for optional compatibility.
- `fw-unban-all` now handles IPv6 global ban sets as well as IPv4.
- `check-fw-ban` no longer loses its `found` state through a pipeline/subshell.
- The unrelated `f2b-portban` subsystem is intentionally not bundled into the RwF core.
