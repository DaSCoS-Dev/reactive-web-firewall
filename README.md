# Reactive Web Firewall

A production-aligned, millisecond-oriented reactive defence bridge for Apache reverse proxies and OpenWrt firewalls.

- [Documentazione italiana](README_IT.md)
- [English documentation](README_EN.md)

The server watches a dedicated Apache `GlobalLog`, classifies only high-confidence malicious requests, immediately closes ports 80/443 for the source in a local nftables set, destroys accepted sockets with `ss -K`, and delegates the definitive ban to OpenWrt through a forced SSH command.

Release: **0.3.0**
## Creator and license

Creator and original copyright holder: **Daniele Stefano Continenza**  
Contact: **daniele@dascos.info**

Licensed under the **GNU Affero General Public License v3.0 or later**.
See [LICENSE](LICENSE), [NOTICE](NOTICE) and [AUTHORS.md](AUTHORS.md).


## Central configuration and modular rules

Version 0.3.0 keeps all server settings in `reactive-web-firewall.conf` and separates signatures into documented `rules.d/*.pm` modules. Run `reactive-web-validate` before applying changes with `reactive-web-apply`.
