#!/usr/bin/env bash
# Copyright (C) 2026 Daniele Stefano Continenza <daniele@dascos.info>
# SPDX-License-Identifier: AGPL-3.0-or-later
set -euo pipefail
BASE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
perl -c "$BASE/server/usr/local/lib/reactive-web-firewall/core.pm"
perl -c "$BASE/server/usr/local/sbin/reactive-web-ban.pl"
perl -c "$BASE/integrations/csf/immediate-ban-marker-snippet.pm"
for f in "$BASE/server/etc/reactive-web-firewall/rules.d/"*.pm; do perl -c "$f"; done
for f in "$BASE/install.sh" "$BASE/finish-server.sh" "$BASE/uninstall-server.sh" "$BASE/server/usr/local/sbin/reactive-web-fastban" "$BASE/server/usr/local/sbin/reactive-web-ban-report" "$BASE/server/usr/local/sbin/reactive-web-diagnose" "$BASE/server/usr/local/sbin/reactive-web-validate" "$BASE/server/usr/local/sbin/reactive-web-apply" "$BASE/server/usr/local/sbin/reactive-web-packet-ring"; do bash -n "$f"; done
for f in "$BASE/firewall/install-firewall.sh" "$BASE/firewall/uninstall-firewall.sh" "$BASE/firewall/usr/local/sbin/"* "$BASE/firewall/etc/init.d/reactive-web-firewall"; do sh -n "$f"; done
echo 'Syntax checks passed.'
