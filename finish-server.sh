#!/usr/bin/env bash
# Copyright (C) 2026 Daniele Stefano Continenza <daniele@dascos.info>
# SPDX-License-Identifier: AGPL-3.0-or-later
set -euo pipefail
[[ ${EUID:-$(id -u)} -eq 0 ]] || { echo 'Run as root' >&2; exit 1; }
source /usr/local/lib/reactive-web-firewall/config.sh
host="$(rwf_cfg firewall_host)"; port="$(rwf_cfg firewall_port 22)"; user="$(rwf_cfg firewall_user root)"
key="$(rwf_cfg ssh_key /etc/reactive-web-firewall/keys/firewall_ed25519)"; known="$(rwf_cfg known_hosts /etc/reactive-web-firewall/keys/known_hosts)"
target="$user@$host"; [[ "$host" == *:* ]] && target="$user@[$host]"
ssh -p "$port" -i "$key" -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$known" "$target" check
/usr/local/sbin/reactive-web-apply
systemctl enable --now reactive-web-ban.service
echo 'Restricted OpenWrt channel and watcher are active.'
