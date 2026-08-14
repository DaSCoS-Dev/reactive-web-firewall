<!--
Copyright (C) 2026 Daniele Stefano Continenza <daniele@dascos.info>
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Detection-engine architecture

**English** | [Italiano](../it/ENGINE-ARCHITECTURE.md)

## Design goal

RwF V7 separates the point where an attack is **detected** from the point where
the ban is **enforced**. This avoids maintaining two parallel implementations
of nftables, `ss -K`, SSH/OpenWrt, whitelist handling, and LFD markers.

```text
Inside Apache ─┐
               ├─ event v=1 ─> rwf-helper ─> local-only / OpenWrt
Log Reader ────┘
```

## Mutual exclusion

The two detection engines are mutually exclusive:

- `inside-apache`: `rwf_module` loaded, `rwf-log-reader.service` inactive;
- `log-reader`: `rwf_module` not loaded, `rwf-log-reader.service` active.

`rwf-status` reports an error if both are detected at the same time.

## Event protocol

Both engines send a Unix datagram to:

```text
/run/reactive-web-firewall/helper.sock
```

Current format:

```text
v=1\tip=<ip>\thost=<host>\tmethod=<method>\turi=<target>\trule=<rule>\tpolicy=<policy>\tts_us=<epoch-us>
```

The helper treats `rule` and `policy` as authoritative inputs after its own
validation and checks the whitelist again before applying any ban.

## Inside Apache

Advantages:

- decision before the application;
- shared cache across Apache processes/threads;
- parallel blocking while nftables/OpenWrt are still working;
- connection close/abort;
- support for path and normalized request-target matching.

Structural limitation: the early hook does not yet know the final HTTP status
and cannot base a signature on the application response.

## Log Reader

Advantages:

- does not load code into the Apache process;
- does not require APXS or Apache development headers;
- can use HTTP status, referrer, user-agent, and protocol recorded in the log;
- preserves response-context families from the original watcher.

Structural limitation: the request has already reached the point where Apache
writes the access-log line, so it does not provide the same preventive window
as `mod_rwf`.

The sensor contains no privileged ban functions. It classifies the request and
sends an event to the shared helper.

## Migration and cutover

The new engine is prepared and validated before the previous engine is stopped.
During cutover, the new engine is brought online before the old engine is
removed when that is safe. During an Inside Apache → Log Reader transition, a
very short controlled overlap may exist: the helper's shared marker prevents
the Log Reader from duplicating an event already handled by `mod_rwf`.

The original Perl watcher had its own independent enforcement path and is
therefore stopped before the new Log Reader is started.

At completion:

1. Apache receives `configtest` and reload when required;
2. exactly one detection engine is verified as operational;
3. on error, the installer trap restores detection files from backup and tries
   to reactivate the engine detected before cutover.

## Enforcement backend

### Local-only

The local firewall is authoritative and uses the complete rule policy.

### OpenWrt

The local firewall acts as a fast bridge/fallback. The helper then executes the
versioned remote command and removes the local fallback after confirmation.

The OpenWrt procedure is identical for both detection engines.
