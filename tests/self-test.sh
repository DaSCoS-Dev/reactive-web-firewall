#!/usr/bin/env bash
# Copyright (C) 2026 Daniele Stefano Continenza <daniele@dascos.info>
# SPDX-License-Identifier: AGPL-3.0-or-later

set -euo pipefail
BASE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
cp "$BASE/server/etc/reactive-web-firewall/rules.conf.example" "$TMP/rules.conf"
cp "$BASE/server/etc/reactive-web-firewall/allowlist.example" "$TMP/allowlist"

watcher=(perl "$BASE/server/usr/local/sbin/reactive-web-ban.pl"
    --regex "$BASE/server/usr/local/lib/reactive-web-firewall/detector.pm"
    --config "$TMP/rules.conf" --allow-file "$TMP/allowlist"
    --state-file "$TMP/state.tsv" --active-dir "$TMP/active")

line() {
    local uri="$1" status="${2:-403}" ua="${3:-scanner}"
    printf '203.0.113.77 (example.org:443) - - [05/Aug/2026:15:32:57.575 +0200] "GET %s HTTP/1.1" %s 100 "-" "%s" apache_end_us=1785936777614027' "$uri" "$status" "$ua"
}

expect_rule() {
    local expected="$1" input="$2" output
    output="$("${watcher[@]}" --test-line "$input")"
    [[ "$output" == *$'\t'"$expected"$'\t'* ]] || { echo "Expected $expected, got: $output" >&2; exit 1; }
}

expect_rule git_exploit "$(line '/.git/config')"
expect_rule env_exploit "$(line '/backend/.env')"
expect_rule framework_exploit "$(line '/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php')"
expect_rule wp_batch "$(line '/wp-json/batch/v1')"
expect_rule xmlrpc "$(line '/xmlrpc.php')"
expect_rule sql_injection "$(line '/?id=1%20UNION%20SELECT%201,2,3')"
expect_rule known_webshell "$(line '/wp-content/uploads/alpha.php')"

safe="$("${watcher[@]}" --test-line "$(line '/index.php' 200 'Mozilla/5.0')")"
[[ -z "$safe" ]] || { echo "Safe request unexpectedly matched: $safe" >&2; exit 1; }

echo 'Classification self-test passed.'
