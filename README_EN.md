# Reactive Web Firewall 0.2.1

Reactive Web Firewall links an Apache reverse proxy to an OpenWrt firewall and reacts to high-confidence malicious web signatures within milliseconds.

```text
confirmed malicious request completes
        ↓
Apache GlobalLog line becomes available
        ↓
local nftables fast-ban on the server
        ↓
ss -K destroys already accepted sockets
        ↓
definitive and persistent OpenWrt ban
        ↓
second sweep and local bridge removal
```

The server closes its own gate immediately. OpenWrt remains the authoritative ban store. The local element has a safety timeout and is removed as soon as the firewall confirms the definitive ban.

## Immediate signatures

The watcher acts only on deliberately strong signatures:

- `.git` repositories;
- `.env`, AWS credentials, `.vscode/sftp.json`, `.DS_Store`, `wp-config.php`;
- PHPUnit probes;
- WordPress REST `batch/v1`;
- `xmlrpc.php`;
- known PHP webshell names;
- structured SQL injection signatures;
- generic PHP probes under restrictive conditions;
- `wp-login.php` probes under restrictive conditions.

Durations are configured in `/etc/reactive-web-firewall/rules.conf` and are reloaded automatically.

## Technical requirements

### Server

- Debian 12 or newer, or Ubuntu 22.04/24.04 LTS or newer;
- Apache HTTP Server 2.4.19+;
- systemd;
- nftables;
- `iproute2` with `ss -K` and a kernel providing `CONFIG_INET_DIAG_DESTROY`;
- OpenSSH client;
- root access for installation;
- the real client address must appear in Apache `%h`.

When Apache is behind another proxy or load balancer, configure `mod_remoteip` first. Otherwise the system may ban the intermediary instead of the attacker.

### Firewall

- OpenWrt with root shell access;
- nftables/fw4;
- Dropbear or OpenSSH server;
- `nft` and `conntrack`;
- web traffic to the server must traverse this firewall;
- the server must reach the firewall SSH service;
- either `apk` or `opkg`.

banIP is optional. In `auto` mode it is selected only when both active nftables blocklist sets can be verified. Otherwise the bundled standalone nftables backend is used.

The production alignment was validated against OpenWrt 25.12.2, kernel 6.12, `apk`, banIP 1.8.5 and x86/64, but those exact versions are not mandatory.

## Automatic installation

```bash
unzip reactive-web-firewall-0.2.1.zip
cd reactive-web-firewall-0.2.1
sudo ./install.sh --check-only
sudo ./install.sh --firewall-host 192.0.2.1 --install-firewall
```

Custom SSH port:

```bash
sudo ./install.sh \
    --firewall-host 192.0.2.1 \
    --firewall-port 222 \
    --install-firewall
```

Explicit backend:

```bash
sudo ./install.sh \
    --firewall-host 192.0.2.1 \
    --backend banip \
    --install-firewall
```

The installer checks packages and syntax, installs the Apache GlobalLog, generates a dedicated Ed25519 key, displays the OpenWrt host-key fingerprint, installs a forced command with no shell or forwarding capabilities, verifies the restricted channel and starts the watcher only after OpenWrt responds successfully.

## Manual OpenWrt stage

```bash
sudo ./install.sh --firewall-host 192.0.2.1
```

Run the printed command on OpenWrt, then complete on the server:

```bash
sudo ./finish-server.sh
```

## SSH security model

The private key remains in:

```text
/etc/reactive-web-firewall/keys/firewall_ed25519
```

The firewall key entry forces `/usr/local/sbin/reactive-fw-dispatch`, checks the source address from `SSH_CONNECTION`, accepts only a narrow command grammar and disables agent, port and X11 forwarding as well as PTY allocation.

## Apache

The project installs a standalone configuration at:

```text
/etc/apache2/conf-available/reactive-web-firewall.conf
```

It uses `GlobalLog`, so application VirtualHosts do not need to be copied or changed. Site-specific files collected during production analysis are intentionally excluded from the public release.

## Operations

```bash
sudo reactive-web-diagnose
sudo journalctl -t reactive-web-ban -o short-precise
sudo reactive-web-ban.pl --show-config
sudo reactive-web-ban.pl --list-state
sudo reactive-web-ban.pl --unban 203.0.113.77
```

Classification-only test:

```bash
sudo reactive-web-ban.pl --test-line \
'203.0.113.77 (example.org:443) - - [05/Aug/2026:15:32:57.575 +0200] "GET /.git/config HTTP/1.1" 403 100 "-" "scanner" apache_end_us=1785936777614027'
```

## Forensic report

```bash
sudo reactive-web-ban-report 203.0.113.77
```

The report combines Apache rotations, microsecond journal events and TCP 80/443 packets from the circular PCAP recorder. Packet captures may contain traffic metadata and partial payloads; apply an appropriate privacy and retention policy.

## OpenWrt backends

With banIP, a permanent ban is applied in this order: direct runtime nftables insertion, verification, conntrack deletion, persistent blocklist update, no banIP reload. The standalone backend uses its own `input` and `forward` chains at priority `-200`, permanent sets and timeout sets.

## Limitations

- The first malicious request must complete before Apache writes the triggering log line.
- This is not a WAF and does not replace patching, hardening, authentication or segmentation.
- Immediate signatures must remain conservative to avoid false positives.
- Test `ss -K` on the actual kernel. The local DROP still blocks new web traffic if socket destruction is unavailable.
- Remote protection depends on firewall SSH reachability. On failure, the local bridge remains active until its safety timeout.

## Removal

```bash
sudo ./uninstall-server.sh
```

On OpenWrt:

```sh
sh /tmp/reactive-web-firewall-install/uninstall-firewall.sh
```

Configuration, keys, blocklists and captures are preserved as safety backups.

## Author, copyright and license

Creator and original copyright holder: **Daniele Stefano Continenza**  
Email: **daniele@dascos.info**

Copyright © 2026 Daniele Stefano Continenza.

The project is released under the **GNU Affero General Public License version
3 or, at your option, any later version** (`AGPL-3.0-or-later`). Anyone who
modifies the software and makes it available to users over a network must also
comply with the obligations in section 13 of the AGPL.

See [LICENSE](LICENSE), [NOTICE](NOTICE) and [AUTHORS.md](AUTHORS.md).
