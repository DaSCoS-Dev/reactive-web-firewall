<!--
Copyright (C) 2026 Daniele Stefano Continenza <daniele@dascos.info>
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Production reference and performance audit

**English** | [Italiano](../it/PRODUCTION-REFERENCE.md)

Audit baseline date: 2026-08-14

These measurements come from a real production Apache reverse proxy while the
**Inside Apache** detection engine was being validated against unsolicited
malicious traffic. They are **observed production reference measurements**, not
minimum requirements and not guaranteed performance. Synthetic installer/self-test
traffic is excluded. They must not be presented as a benchmark of the Log Reader
engine, whose detection point is intentionally after Apache writes the access log.

## Reference production hardware

| Component | Reference system |
|---|---|
| System | Lenovo E50-00 / product 90BX005XIX |
| CPU | Intel Pentium J2900 @ 2.41 GHz |
| CPU topology | 4 physical cores, 4 threads, no SMT |
| RAM | 4 GB Samsung DDR3 @ 1333 MT/s |
| Storage | 2 × Crucial BX500 SATA SSD, 240 GB |
| RAID | Linux software RAID1 for `/boot` and `/` |
| NIC | Realtek RTL8111/8168/8411 PCIe Gigabit Ethernet |
| Link during audit | 1 Gbit/s, full duplex |
| OS | Ubuntu 22.04.5 LTS, x86-64 |
| Kernel | Linux 5.15.0-176-generic |
| Apache | 2.4.52 (Ubuntu), MPM event |
| Firewall backend | OpenWrt with local nftables bridge/fallback |

The hardware is intentionally modest. Results must be read in the context of
its concurrent production load, scheduler state and external SSH/OpenWrt latency.

## What is measured

RwF has multiple protection milestones and they must not be collapsed into one
ambiguous “ban time”:

1. **RwF request handling** inside Apache.
2. **Helper socket delivery** from module to privileged helper.
3. **Application-layer connection closure/abort** by Apache/RwF.
4. **Local nftables block** on the reverse proxy.
5. **Perimeter confirmation** from OpenWrt.
6. **Worker completion** after socket sweeps and fallback cleanup.

The shared Apache cache is deliberately active before steps 4 and 5 complete,
so follow-up requests do not need to wait for firewall enforcement.

## Valid production baseline: 10 real unsolicited bans

The public baseline includes **10 real production events collected while the
local fast path was operating normally**. A temporary development regression in
the local firewall path is deliberately excluded because it was identified,
removed, and is not representative of the distributed implementation. No values
from that regression are simulated, adjusted or mixed into these statistics.
Installer/self-test traffic is also excluded.

The first five valid events were retained as exact aggregate statistics; the
next five were retained individually. For that reason an overall N=10 median is
**not fabricated** where the original ten raw values are not all available.

### Metrics available across all 10 valid events

| Metric | N | Mean | Min | Max |
|---|---:|---:|---:|---:|
| module → helper delivery | 10 | **0.330 ms** | 0.142 ms | 0.532 ms |
| request → local nftables block | 10 | **47.308 ms** | 37.446 ms | 55.418 ms |
| request → OpenWrt confirmation | 10 | **268.434 ms** | 199.945 ms | 372.444 ms |
| complete helper worker | 10 | **339.031 ms** | 271.786 ms | 438.281 ms |

### Detailed subset: 5 individually retained current events

These five events add instrumentation that was not retained for every earlier
valid sample. They are reported separately only because the metrics differ, not
because a software-version cohort is being claimed.

| Metric | N | Mean | Median | Min | Max |
|---|---:|---:|---:|---:|---:|
| module → helper delivery | 5 | 0.332 ms | 0.283 ms | 0.224 ms | 0.497 ms |
| `custom-web-fastban` add itself | 5 | **42.819 ms** | 45.405 ms | 35.595 ms | 48.588 ms |
| request → local nftables block | 5 | **44.640 ms** | 47.280 ms | 37.446 ms | 50.497 ms |
| `ss -K` pre sweep | 5 | 10.579 ms | 10.749 ms | 9.512 ms | 11.745 ms |
| remote OpenWrt command | 5 | 201.406 ms | 162.215 ms | 140.686 ms | 281.630 ms |
| request → OpenWrt confirmation | 5 | 256.858 ms | 213.026 ms | 199.945 ms | 330.302 ms |
| local fallback deletion | 5 | 57.815 ms | 56.176 ms | 52.921 ms | 65.396 ms |
| complete helper worker | 5 | 326.003 ms | 289.664 ms | 271.786 ms | 395.423 ms |

The individually retained sample covers different real signatures and both
HTTP/1.1 and HTTP/2 traffic, including shared-cache handling across concurrent
requests/connections.

## Apache/cache measurements from real traffic

Representative observations include:

- ordinary no-match RwF processing in a few tens of microseconds;
- first high-confidence rule matches in a few hundred microseconds inside RwF;
- cached/parallel follow-up blocks around one hundred microseconds inside RwF;
- whole Apache transactions for blocked requests commonly below a few milliseconds;
- HTTP/2 concurrent requests blocked by the shared cache while nftables and
  OpenWrt were still processing the first event.

These observations are why `request → local nftables block` is not the
application exposure window. The application-layer decision happens first.

## Packet-level closure audit

Correlated PCAP and RwF/helper timestamps show application-layer closure before
local/perimeter firewall completion. Representative anonymized observations:

| Scenario | Packet-level observation | Local nftables | OpenWrt |
|---|---:|---:|---:|
| HTTP/2, concurrent streams on the same TCP connection | first proxy RST about **3.886 ms** after the winning RwF source timestamp | 50.497 ms | 328.861 ms |
| HTTP/1.1 WordPress batch target | proxy FIN about **0.663 ms** after the RwF source timestamp | 47.280 ms | 199.945 ms |
| HTTP/2, two simultaneous TCP connections | second request blocked from cache in **0.089 ms** inside RwF before local firewall completion | 49.011 ms | 213.026 ms |
| PHPUnit probe | proxy FIN about **0.844 ms** after the RwF source timestamp | 38.968 ms | 212.154 ms |

The exact TLS application records cannot be mapped to individual encrypted
HTTP/2 streams without decryption; the correlation therefore uses Apache's own
request timestamps together with TCP-level FIN/RST timing and does not overstate
what the packet capture proves.

## Operational interpretation

```text
malicious request
  ↓
RwF rule match / cache-add        sub-ms to a few ms
  ↓
subsequent requests               shared-cache block, typically sub-ms in RwF
  ↓
Apache connection close/abort     observed before firewall completion
  ↓
local nftables                    local admission block
  ↓
OpenWrt                           perimeter block
```

The external enforcement stages can be slower without leaving later requests
free to reach the application, because the Apache cache already owns that gap.

## Reproducing the sanitized hardware profile

Run:

```bash
./scripts/collect-system-profile.sh
```

The script intentionally omits machine IDs, boot IDs, MAC addresses, IP
addresses, storage serials and private mounted-share details.

## Updating this audit

When adding samples:

- use real unsolicited malicious events only;
- keep installer/self-test events separate;
- include only measurements representative of the currently distributed fast path;
- never “correct” or simulate a raw sample to make it comparable;
- report N and only statistics supported by preserved raw/aggregate data;
- where a PCAP exists, correlate RwF, FIN/RST, local block and remote confirmation.
