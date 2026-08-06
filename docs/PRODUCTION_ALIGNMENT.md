# Production alignment

Version 0.3.0 retains the production-aligned engine introduced in 0.2.1 while moving operational settings into one central server configuration and splitting detection signatures into validated rule modules.


Aligned behaviours include:

- sub-100 ms local nftables bridge after Apache classification;
- stateful ban escalation and duplicate suppression;
- first and second `ss -K` sweeps without forcing IPv4 or IPv6;
- OpenSSH ControlMaster reuse;
- direct banIP nftables insertion and verification before conntrack deletion;
- persistent banIP update without service reload;
- local bridge removal only after remote success;
- circular tcpdump recorder and combined forensic report;
- OpenWrt package-manager detection for both `apk` and `opkg`.

The public bundle intentionally excludes:

- application-specific Apache VirtualHosts;
- production domains and network addresses;
- real allowlists, blocklists and nftables dumps;
- private or public deployment keys;
- complete installation-specific CSF/LFD configuration.

The Apache integration uses its own `GlobalLog`, so no application VirtualHost is required in the repository.
