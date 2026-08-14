<!--
Copyright (C) 2026 Daniele Stefano Continenza <daniele@dascos.info>
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Reactive Web Firewall

**English** | [Italiano](README.it.md)

Reactive Web Firewall (RwF) is an Apache detection and blocking system with
**two mutually exclusive detection engines** and one shared privileged
enforcement pipeline.

Package version: **V7.0 / installer `2026.08.14-installer-07.0`**.

## Architecture

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

The two detection engines must never be active at the same time. The installer
checks this invariant after every installation or migration.

## Four installable profiles

| Detection engine | Backend | Behavior |
|---|---|---|
| Inside Apache | Local-only | early Apache blocking + authoritative local nftables |
| Inside Apache | OpenWrt | early blocking + local bridge + OpenWrt ban |
| Log Reader | Local-only | access-log detection + authoritative local nftables |
| Log Reader | OpenWrt | access-log detection + local bridge + OpenWrt ban |

### Inside Apache

`mod_rwf` runs inside the Apache request lifecycle, before the application. It
can populate the shared cache, block parallel requests, and close/abort
connections before nftables or OpenWrt have completed their work.

It requires Apache development headers and APXS on the target host.

### Log Reader

`rwf-log-reader` follows an Apache access log in near real time and classifies
requests **after** Apache writes the log line. It does not require APXS and does
not load code into the Apache process.

The engine is self-contained and does not depend on CSF. It also keeps rule
families that require response context, including `wp-login` and selected
root-level PHP probes that cannot safely be converted into early path rules.

Supported access-log formats:

```text
IP (vhost:port) ... "METHOD URI HTTP/x" STATUS ... "REF" "UA"
vhost:port IP ... "METHOD URI HTTP/x" STATUS ... "REF" "UA"
```

If present, the optional `apache_end_us=<microseconds>` field is used as the
source timestamp of the event, allowing delivery latency from the access log to
be measured as well.

## Shared enforcement

Both engines send the same `v=1` event protocol to:

```text
/run/reactive-web-firewall/helper.sock
```

`rwf-helper` applies the whitelist, LFD compatibility marker, local firewall,
`ss -K`, and OpenWrt when configured. Neither `mod_rwf` nor `rwf-log-reader`
has privileges to manipulate the remote firewall directly.

### LOCAL-ONLY

The rule policy is authoritative on the local firewall:

```text
30s / 30m / 4h / 3d / 2w / permanent
```

Permanent bans are persisted and restored at boot.

### OPENWRT

The enforcement path is:

```text
event
  -> temporary local fast-ban
  -> ss -K pre
  -> SSH OpenWrt temp-add/sync-add
  -> ss -K post
  -> remote confirmation
     -> local bridge removal
```

If OpenWrt does not confirm the operation, the local fallback remains active
until its configured TTL expires.

## Distributable OpenWrt backend

The package includes the OpenWrt side as well. The wizard can install or update
it through an administrative SSH session, then switch to a dedicated runtime
key restricted by a forced command.

The authorized source IP is not hardcoded. During bootstrap, OpenWrt uses the
first field of `SSH_CONNECTION`, meaning the source address of the RwF server
**as actually seen by the firewall**. Previously authorized sources are
preserved.

The remote runtime exposes a small versioned API, for example:

```text
version
capabilities
temp-add <ip> <seconds> proxy <source>
sync-add <ip>
unban-all <ip>
```

See [`docs/en/OPENWRT-BACKEND-AUDIT.md`](docs/en/OPENWRT-BACKEND-AUDIT.md).

## Rules

### Inside Apache

File:

```text
/etc/reactive-web-firewall/apache-rules.conf
```

Syntax:

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

Example:

```ini
log_file=/var/log/apache2/other_vhosts_access.log
rule.git-repository=permanent
rule.wordpress-batch-v1=3d
rule.wordpress-wp-login-context=4h
rule.phpmyadmin-standard=off
```

High-confidence families are kept aligned between the two engines whenever the
available data permits it. Rules that require HTTP status/referrer/UA remain
intentionally Log Reader-only.

## Whitelist

One shared file:

```text
/etc/reactive-web-firewall/whitelist.conf
```

Syntax:

```apache
RwfWhitelistIP 192.0.2.10/32
RwfWhitelistIP 2001:db8::/32
```

The helper always checks the whitelist. Inside Apache checks it before
emitting the event as well.

## Installation

```bash
sha256sum -c SHA256SUMS
./install.sh
```

The wizard:

1. detects the platform, Apache, and any existing RwF installation;
2. asks for `Inside Apache` or `Log Reader`;
3. installs only the dependencies required by the selected engine;
4. validates the existing Apache configuration;
5. preserves compatible whitelist and configuration data;
6. for Log Reader, validates the selected access-log format against real data;
7. asks for `LOCAL-ONLY` or `OPENWRT`;
8. for OpenWrt, performs host-key checking, runtime-key setup, remote bootstrap, and self-test;
9. always builds the C helper and builds `mod_rwf` only for Inside Apache;
10. prepares the new engine before stopping the previous one;
11. starts the shared enforcement layer;
12. performs the cutover and enforces mutual exclusion;
13. runs engine-specific self-tests;
14. verifies the final invariant through `rwf-status`.

If the original `custom-web-ban-immediate.pl` watcher is found, it is treated as
a predecessor of the Log Reader. When migrating to the new Log Reader, known
policies from the old configuration are translated when possible; the old
service is stopped only during the cutover.

## Status and diagnostics

```bash
rwf-status
```

Shows the active engine, backend, module/service/helper/firewall state, rule
count, and any conflict between the two detection engines.

For forensic collection:

```bash
rwf-fish <IP>
rwf-fish <IP> '2 hours ago'
```

The output adapts automatically to the configured engine.

## Repository layout

```text
src/                 mod_rwf + C helper
log-reader/          self-contained Perl sensor
config/              Inside Apache rules/whitelist
apache/              Apache templates
local-firewall/      shared nftables fast-ban
openwrt/             remote backend and bootstrap
systemd/             shared units and Log Reader unit
scripts/             installer helpers, self-tests, status, audit
docs/en/             English architecture, audits and release notes
docs/it/             Italian architecture, audits and release notes
install.sh
uninstall.sh
```

## Dependencies

The Log Reader does **not** require Apache development packages or APXS. Inside
Apache does. Both require the tools needed to build the small C helper, Perl,
nftables, and `iproute2` or equivalent utilities.

The OpenSSH client is required only when the OpenWrt backend is selected.

## Performance

[`docs/en/PRODUCTION-REFERENCE.md`](docs/en/PRODUCTION-REFERENCE.md) contains the
observed Inside Apache baseline based on 10 valid real production events.
Samples from a known development regression and synthetic self-tests are
excluded. The report does not attribute those statistics to the Log Reader,
which has a different detection window by design.

## Documentation

- [Documentation index](docs/README.md)
- [Detection-engine architecture](docs/en/ENGINE-ARCHITECTURE.md)
- [OpenWrt backend audit](docs/en/OPENWRT-BACKEND-AUDIT.md)
- [Legacy Perl rule audit](docs/en/PERL-RULE-AUDIT.md)
- [Production reference](docs/en/PRODUCTION-REFERENCE.md)
- [V7 release notes](docs/en/RELEASE-NOTES-V7.md)

## License and copyright

Copyright (C) 2026 Daniele Stefano Continenza <daniele@dascos.info>.

License: **GNU Affero General Public License v3 or later**
(`AGPL-3.0-or-later`). See [`LICENSE`](LICENSE) and
[`COPYRIGHT.md`](COPYRIGHT.md).
