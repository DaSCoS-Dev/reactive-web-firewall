#!/usr/bin/env bash
# Copyright (C) 2026 Daniele Stefano Continenza <daniele@dascos.info>
# SPDX-License-Identifier: AGPL-3.0-or-later

set -euo pipefail
BASE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
perl -c "$BASE/server/usr/local/lib/reactive-web-firewall/detector.pm"
perl -c "$BASE/server/usr/local/sbin/reactive-web-ban.pl"
perl -c "$BASE/integrations/csf/immediate-ban-marker-snippet.pm"
for f in "$BASE/install.sh" "$BASE/finish-server.sh" "$BASE/uninstall-server.sh" "$BASE/server/usr/local/sbin/reactive-web-fastban" "$BASE/server/usr/local/sbin/reactive-web-ban-report" "$BASE/server/usr/local/sbin/reactive-web-diagnose"; do bash -n "$f"; done
for f in "$BASE/firewall/install-firewall.sh" "$BASE/firewall/uninstall-firewall.sh" "$BASE/firewall/usr/local/sbin/"* "$BASE/firewall/etc/init.d/reactive-web-firewall"; do sh -n "$f"; done
if command -v nft >/dev/null 2>&1; then
    nft -c -f "$BASE/server/etc/nftables.d/reactive-web-fastban.nft"
    nft -c -f "$BASE/firewall/etc/reactive-web-firewall/firewall.nft"
fi
echo 'Syntax checks passed.'
