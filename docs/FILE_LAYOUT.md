# File layout

## Server

- `/etc/reactive-web-firewall/reactive-web-firewall.conf`: all server settings and policies.
- `/etc/reactive-web-firewall/rules.d/*.pm`: modular detection rules.
- `/etc/reactive-web-firewall/allowlist`: trusted source IPs.
- `/usr/local/sbin/reactive-web-ban.pl`: stable watcher engine.
- `/usr/local/sbin/reactive-web-validate`: syntax and configuration validation.
- `/usr/local/sbin/reactive-web-apply`: render/reload services after configuration changes.
- `/usr/local/sbin/reactive-web-fastban`: local nftables bridge.
- `/usr/local/sbin/reactive-web-packet-ring`: configurable tcpdump launcher.

## OpenWrt

- `/etc/reactive-web-firewall/firewall.conf`: firewall-side configuration.
- `/usr/local/sbin/reactive-fw-dispatch`: restricted SSH dispatcher.
- `/usr/local/sbin/reactive-fw-ban`: runtime/persistent ban backend.
