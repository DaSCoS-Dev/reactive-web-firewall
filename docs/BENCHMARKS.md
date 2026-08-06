# Benchmarks

Observed on one production deployment:

- Apache log delivery after request end: below 1 ms;
- request end to local proxy block: 52.462 ms;
- local nftables insertion itself: 15 ms;
- definitive OpenWrt confirmation in that sample: 359.889 ms after request end;
- complete second sweep and bridge cleanup: 419.960 ms.

The security-relevant web-access cutoff is the local block time, not the later housekeeping completion. Results depend on CPU, logging, SSH latency, storage and kernel behaviour. Measure your own installation with `reactive-web-ban-report`.
