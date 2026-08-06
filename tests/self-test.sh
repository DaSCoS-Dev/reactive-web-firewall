#!/usr/bin/env bash
# Copyright (C) 2026 Daniele Stefano Continenza <daniele@dascos.info>
# SPDX-License-Identifier: AGPL-3.0-or-later
set -euo pipefail
BASE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/rules" "$TMP/active"
cp "$BASE/server/etc/reactive-web-firewall/rules.d/"*.pm "$TMP/rules/"
cp "$BASE/server/etc/reactive-web-firewall/allowlist.example" "$TMP/allowlist"
sed \
  -e "s|@@FIREWALL_HOST@@|192.0.2.1|" \
  -e "s|@@FIREWALL_PORT@@|22|" \
  -e "s|@@FIREWALL_USER@@|root|" \
  -e "s|^rules_directory *=.*|rules_directory = $TMP/rules|" \
  -e "s|^allowlist_file *=.*|allowlist_file = $TMP/allowlist|" \
  -e "s|^state_file *=.*|state_file = $TMP/state.tsv|" \
  -e "s|^active_directory *=.*|active_directory = $TMP/active|" \
  "$BASE/server/etc/reactive-web-firewall/reactive-web-firewall.conf.example" > "$TMP/config.conf"
watcher=(perl "$BASE/server/usr/local/sbin/reactive-web-ban.pl" --core "$BASE/server/usr/local/lib/reactive-web-firewall/core.pm" --config "$TMP/config.conf")
line(){ local uri="$1" status="${2:-403}" ua="${3:-scanner}"; printf '203.0.113.77 (example.org:443) - - [05/Aug/2026:15:32:57.575 +0200] "GET %s HTTP/1.1" %s 100 "-" "%s" apache_end_us=1785936777614027' "$uri" "$status" "$ua"; }
expect(){ local rule="$1" input="$2" out; out="$("${watcher[@]}" --test-line "$input")"; [[ "$out" == *$'\t'"$rule"$'\t'* ]] || { echo "Expected $rule, got $out" >&2; exit 1; }; }
"${watcher[@]}" --validate-config >/dev/null
expect git_exploit "$(line '/.git/config')"
expect env_exploit "$(line '/backend/.env')"
expect framework_exploit "$(line '/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php')"
expect wp_batch "$(line '/wp-json/batch/v1')"
expect xmlrpc "$(line '/xmlrpc.php')"
expect sql_injection "$(line '/?id=1%20UNION%20SELECT%201,2,3')"
expect known_webshell "$(line '/wp-content/uploads/alpha.php')"
safe="$("${watcher[@]}" --test-line "$(line '/index.php' 200 'Mozilla/5.0')")"
[[ -z "$safe" ]] || { echo "Safe request matched: $safe" >&2; exit 1; }
echo 'Modular classification self-test passed.'
