#!/usr/bin/env bash
# Copyright (C) 2026 Daniele Stefano Continenza <daniele@dascos.info>
# SPDX-License-Identifier: AGPL-3.0-or-later

set -euo pipefail
[[ ${EUID:-$(id -u)} -eq 0 ]] || { echo 'Run as root' >&2; exit 1; }
systemctl disable --now reactive-web-ban.service reactive-web-fastban.service reactive-web-packet-ring.service >/dev/null 2>&1 || true
a2disconf reactive-web-firewall >/dev/null 2>&1 || true
apache2ctl configtest >/dev/null 2>&1 && systemctl reload apache2 || true
rm -f /etc/systemd/system/reactive-web-ban.service /etc/systemd/system/reactive-web-fastban.service /etc/systemd/system/reactive-web-packet-ring.service
rm -f /usr/local/sbin/reactive-web-ban.pl /usr/local/sbin/reactive-web-fastban /usr/local/sbin/reactive-web-ban-report /usr/local/sbin/reactive-web-diagnose
rm -rf /usr/local/lib/reactive-web-firewall
rm -f /etc/apache2/conf-available/reactive-web-firewall.conf /etc/logrotate.d/reactive-web-firewall /etc/nftables.d/reactive-web-fastban.nft
nft delete table inet reactive_web_fastban >/dev/null 2>&1 || true
systemctl daemon-reload
echo 'Runtime files removed. /etc/reactive-web-firewall, state, keys and packet captures were preserved.'
