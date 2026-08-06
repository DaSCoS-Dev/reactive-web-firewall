#!/usr/bin/env bash
# Copyright (C) 2026 Daniele Stefano Continenza <daniele@dascos.info>
# SPDX-License-Identifier: AGPL-3.0-or-later

set -euo pipefail
[[ ${EUID:-$(id -u)} -eq 0 ]] || { echo 'Run as root' >&2; exit 1; }
CONF=/etc/reactive-web-firewall/connection.conf
[[ -r "$CONF" ]] || { echo "$CONF missing; rerun install.sh" >&2; exit 1; }
# shellcheck disable=SC1090
source "$CONF"
KEY=/etc/reactive-web-firewall/keys/firewall_ed25519
KNOWN=/etc/reactive-web-firewall/keys/known_hosts
ssh -p "$FIREWALL_PORT" -i "$KEY" -o BatchMode=yes -o IdentitiesOnly=yes \
    -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$KNOWN" -o ConnectTimeout=3 \
    "$FIREWALL_TARGET" check
systemctl daemon-reload
systemctl enable --now reactive-web-fastban.service reactive-web-ban.service
reactive-web-diagnose
