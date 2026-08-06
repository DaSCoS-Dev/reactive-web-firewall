#!/usr/bin/env bash
# Copyright (C) 2026 Daniele Stefano Continenza <daniele@dascos.info>
# SPDX-License-Identifier: AGPL-3.0-or-later

set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
VERSION="$(tr -d '[:space:]' < "$ROOT/VERSION")"
NAME="reactive-web-firewall-$VERSION"
PARENT="$(dirname "$ROOT")"
[[ "$(basename "$ROOT")" == "$NAME" ]] || echo "Warning: directory name is not $NAME" >&2
find "$ROOT" -type f ! -name MANIFEST.sha256 -print0 | sort -z | while IFS= read -r -d '' file; do
    rel="${file#$ROOT/}"
    sha256sum "$file" | sed "s|  $file$|  $rel|"
done > "$ROOT/MANIFEST.sha256"
(cd "$PARENT" && rm -f "$NAME.zip" && zip -qr "$NAME.zip" "$NAME" -x "$NAME/.git/*")
sha256sum "$PARENT/$NAME.zip"
