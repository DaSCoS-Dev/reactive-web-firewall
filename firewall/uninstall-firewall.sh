#!/bin/sh
# Copyright (C) 2026 Daniele Stefano Continenza <daniele@dascos.info>
# SPDX-License-Identifier: AGPL-3.0-or-later

set -eu
[ "$(id -u)" -eq 0 ] || { echo 'Run as root' >&2; exit 1; }
/etc/init.d/reactive-web-firewall disable >/dev/null 2>&1 || true
/etc/init.d/reactive-web-firewall stop >/dev/null 2>&1 || true
for f in /etc/dropbear/authorized_keys /root/.ssh/authorized_keys; do
    [ -f "$f" ] || continue
    tmp="${f}.tmp.$$"; grep -v 'reactive-web-firewall$' "$f" > "$tmp" || true; mv "$tmp" "$f"; chmod 0600 "$f"
done
rm -f /usr/local/sbin/reactive-fw-common /usr/local/sbin/reactive-fw-load /usr/local/sbin/reactive-fw-ban /usr/local/sbin/reactive-fw-dispatch /etc/init.d/reactive-web-firewall
rm -f /etc/reactive-web-firewall/firewall.nft
# Keep firewall.conf and blocklist as a safety backup.
echo 'Removed runtime files. Configuration and standalone blocklist were preserved in /etc/reactive-web-firewall.'
