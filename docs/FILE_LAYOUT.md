# File layout

## Server

- `/usr/local/sbin/reactive-web-ban.pl`: production-aligned watcher
- `/usr/local/lib/reactive-web-firewall/detector.pm`: standalone high-confidence detector
- `/usr/local/sbin/reactive-web-fastban`: local nftables set helper
- `/usr/local/sbin/reactive-web-ban-report`: forensic report generator
- `/usr/local/sbin/reactive-web-diagnose`: diagnostic checks
- `/etc/reactive-web-firewall/rules.conf`: durations and local controls
- `/etc/reactive-web-firewall/allowlist`: exact source IP allowlist
- `/etc/reactive-web-firewall/keys/`: dedicated SSH identity and known_hosts
- `/etc/nftables.d/reactive-web-fastban.nft`: local bridge table
- `/var/lib/reactive-web-firewall/active.tsv`: watcher state
- `/run/reactive-web-firewall/active/`: short-lived duplicate-suppression markers
- `/var/log/apache2/reactive_web_access.log`: dedicated Apache GlobalLog
- `/var/log/reactive-web-firewall/pcap/`: optional circular packet ring

## OpenWrt

- `/usr/local/sbin/reactive-fw-dispatch`: forced SSH dispatcher
- `/usr/local/sbin/reactive-fw-ban`: runtime and persistence backend
- `/usr/local/sbin/reactive-fw-common`: validation/configuration helpers
- `/usr/local/sbin/reactive-fw-load`: standalone blocklist loader
- `/etc/reactive-web-firewall/firewall.conf`: backend and allowed server addresses
- `/etc/reactive-web-firewall/firewall.nft`: standalone nftables table
- `/etc/reactive-web-firewall/blocklist`: standalone persistent blocklist

## Optional integrations

- `integrations/csf/`: duplicate-suppression marker helper for existing CSF/LFD installations
