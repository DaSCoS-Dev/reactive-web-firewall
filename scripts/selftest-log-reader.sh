#!/usr/bin/env bash
# Copyright (C) 2026 Daniele Stefano Continenza <daniele@dascos.info>
# SPDX-License-Identifier: AGPL-3.0-or-later
set -Eeuo pipefail
BASE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${RWF_LOG_READER_BIN:-/usr/local/sbin/rwf-log-reader}"
CFG="${RWF_LOG_READER_CONF:-/etc/reactive-web-firewall/log-reader.conf}"
[[ -x "$BIN" ]] || BIN="$BASE_DIR/log-reader/rwf-log-reader.pl"
[[ -r "$CFG" ]] || CFG="$BASE_DIR/log-reader/rwf-log-reader.conf"
[[ -x "$BIN" ]] || { echo "rwf-log-reader non trovato: $BIN" >&2; exit 1; }

run() { "$BIN" --config "$CFG" --test-line "$1"; }
line1='198.51.100.31 (rwf-selftest.invalid:443) - - [14/Aug/2026:12:00:00 +0200] "GET /.git/config HTTP/1.1" 404 123 "-" "curl/8"'
line2='rwf-selftest.invalid:443 198.51.100.32 - - [14/Aug/2026:12:00:00 +0200] "POST /?rest_route=/batch/v1 HTTP/1.1" 403 123 "-" "scanner"'
line3='198.51.100.33 (rwf-selftest.invalid:443) - - [14/Aug/2026:12:00:00 +0200] "GET /wp-login.php HTTP/1.1" 404 123 "-" "curl/8"'
line4='198.51.100.34 (rwf-selftest.invalid:443) - - [14/Aug/2026:12:00:00 +0200] "GET /index.php HTTP/1.1" 200 123 "https://rwf-selftest.invalid/" "Mozilla/5.0"'
[[ "$(run "$line1")" == *$'\tgit-repository\t'* ]] || { echo "FAIL git" >&2; exit 1; }
[[ "$(run "$line2")" == *$'\twordpress-batch-v1\t'* ]] || { echo "FAIL batch" >&2; exit 1; }
[[ "$(run "$line3")" == *$'\twordpress-wp-login-context\t'* ]] || { echo "FAIL response-context" >&2; exit 1; }
[[ -z "$(run "$line4")" ]] || { echo "FAIL benign" >&2; exit 1; }
echo "OK: parser, formato storico/vhost_combined e regole response-context." 
