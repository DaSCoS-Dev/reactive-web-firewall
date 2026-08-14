#!/usr/bin/env python3
# Copyright (C) 2026 Daniele Stefano Continenza <daniele@dascos.info>
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Safely configure Apache CustomLog suppression for RwF cache-hit requests.

RwF sets RWF_SUPPRESS_ACCESSLOG=1 only for requests blocked from its shared
IP cache. Apache CustomLog accepts one optional conditional argument: either
``env=...`` or ``expr=...``.  Therefore an already-conditional CustomLog must
not receive a fourth argument.  V4.3 merges the RwF condition into the
existing condition instead.

Supported single-line forms:
- ``CustomLog DEST FORMAT``
  -> append ``env=!RWF_SUPPRESS_ACCESSLOG``;
- ``CustomLog DEST FORMAT env=VAR`` / ``env=!VAR``
  -> convert to an equivalent ap_expr and AND the RwF condition;
- ``CustomLog DEST FORMAT "expr=EXPRESSION"``
  -> wrap EXPRESSION and AND the RwF condition.

Safety rules:
- edit only active files returned by `apachectl -t -D DUMP_INCLUDES`;
- never rewrite continued/multi-line CustomLog directives;
- leave unknown or non-simple conditional forms untouched and report them;
- after a write batch, run Apache configtest and automatically restore every
  changed file if syntax validation fails;
- `sanitize` mode removes the exact trailing V4/V4.1 RwF env token without
  requiring a valid Apache configuration, allowing recovery from interrupted
  older installer runs.
"""

from __future__ import annotations

import argparse
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ENV_TOKEN = "env=!RWF_SUPPRESS_ACCESSLOG"
RWF_ENV = "RWF_SUPPRESS_ACCESSLOG"
RWF_EXPR = "reqenv('RWF_SUPPRESS_ACCESSLOG') != '1'"
CUSTOM_RE = re.compile(r"^(?P<indent>\s*)CustomLog\s+", re.IGNORECASE)
TRANSFER_RE = re.compile(r"^\s*TransferLog\s+", re.IGNORECASE)
INCLUDE_PATH_RE = re.compile(r"^\s*(?:\(\*\)|\(\d+\))\s+(/.*)$")
TOKEN_AT_END_RE = re.compile(r"\s+env=!RWF_SUPPRESS_ACCESSLOG\s*$", re.IGNORECASE)


def run_apache(apachectl: str, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [apachectl, *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )


def apache_configtest(apachectl: str) -> tuple[bool, str]:
    proc = run_apache(apachectl, "configtest")
    if proc.returncode == 0:
        return True, proc.stdout
    proc2 = run_apache(apachectl, "-t")
    return proc2.returncode == 0, (proc.stdout + proc2.stdout)


def apache_includes(apachectl: str) -> list[Path]:
    proc = run_apache(apachectl, "-t", "-D", "DUMP_INCLUDES")
    if proc.returncode != 0:
        raise RuntimeError("Apache non ha fornito DUMP_INCLUDES:\n" + proc.stdout)

    result: list[Path] = []
    seen: set[str] = set()
    for line in proc.stdout.splitlines():
        m = INCLUDE_PATH_RE.match(line)
        if not m:
            continue
        path = Path(m.group(1)).resolve()
        key = str(path)
        if key not in seen and path.is_file():
            seen.add(key)
            result.append(path)
    return result


def backup_file(path: Path, backup_root: Path) -> Path:
    dest = backup_root / path.relative_to("/")
    dest.parent.mkdir(parents=True, exist_ok=True)
    if not dest.exists():
        shutil.copy2(path, dest)
    return dest


def atomic_write(path: Path, content: str) -> None:
    st = path.stat()
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.rwf.", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as fh:
            fh.write(content)
        os.chmod(tmp_name, st.st_mode)
        try:
            os.chown(tmp_name, st.st_uid, st.st_gid)
        except PermissionError:
            pass
        os.replace(tmp_name, path)
    finally:
        try:
            os.unlink(tmp_name)
        except FileNotFoundError:
            pass


def tokenize_customlog(body: str) -> tuple[list[str] | None, str | None]:
    # A trailing backslash means Apache continues the directive on the next
    # physical line. Do not try to rewrite it automatically.
    if body.rstrip().endswith("\\"):
        return None, "direttiva CustomLog multilinea/continuata"
    try:
        tokens = shlex.split(body, comments=False, posix=True)
    except ValueError as exc:
        return None, f"quoting non analizzabile automaticamente ({exc})"
    if not tokens or tokens[0].lower() != "customlog":
        return None, "direttiva CustomLog non analizzabile"
    return tokens, None


def apache_quote(value: str) -> str:
    """Quote one Apache configuration argument conservatively."""
    if value and not re.search(r"[\s\"\\]", value):
        return value
    return '"' + value.replace('\\', '\\\\').replace('"', '\\"') + '"'


def render_customlog(indent: str, destination: str, log_format: str, condition: str | None, ending: str) -> str:
    parts = [indent + "CustomLog", apache_quote(destination), apache_quote(log_format)]
    if condition is not None:
        # expr= values always need to remain one Apache argument.
        if condition.lower().startswith("expr="):
            parts.append(apache_quote(condition))
        else:
            parts.append(condition)
    return " ".join(parts) + ending


def rwf_wrapped_expression(expr: str) -> str:
    return f"expr=({expr}) && {RWF_EXPR}"


def unwrap_rwf_expression(expr_condition: str) -> str | None:
    """Undo only the exact wrapper produced by rwf_wrapped_expression()."""
    if not expr_condition.lower().startswith("expr="):
        return None
    expr = expr_condition[5:]
    suffix = f") && {RWF_EXPR}"
    if not (expr.startswith("(") and expr.endswith(suffix)):
        return None
    return "expr=" + expr[1:-len(suffix)]


def env_to_expression(condition: str) -> str | None:
    m = re.fullmatch(r"env=(!?)([A-Za-z_][A-Za-z0-9_]*)", condition, re.IGNORECASE)
    if not m:
        return None
    negated, name = m.groups()
    # CustomLog env=VAR tests presence; for normal SetEnvIf/SetEnvIfNoCase
    # variables, -n/-z reqenv(VAR) is the closest ap_expr equivalent and is
    # the form documented by Apache for request environment lookups.
    test = f"-z reqenv('{name}')" if negated else f"-n reqenv('{name}')"
    return rwf_wrapped_expression(test)


def expression_to_simple_env(expr_condition: str) -> str | None:
    """Restore env=/env=! syntax when disabling a V4.3 conversion."""
    if not expr_condition.lower().startswith("expr="):
        return None
    expr = expr_condition[5:].strip()
    m = re.fullmatch(r"-(n|z)\s+reqenv\('([A-Za-z_][A-Za-z0-9_]*)'\)", expr)
    if not m:
        return None
    op, name = m.groups()
    return f"env={name}" if op == "n" else f"env=!{name}"


def process_file(path: Path, mode: str) -> tuple[bool, int, int, list[str], str]:
    original = path.read_text(encoding="utf-8", errors="surrogateescape")
    lines = original.splitlines(keepends=True)
    changed = False
    custom_count = 0
    patched_count = 0
    warnings: list[str] = []
    out: list[str] = []

    for lineno, line in enumerate(lines, 1):
        stripped = line.lstrip()
        if not stripped or stripped.startswith("#"):
            out.append(line)
            continue

        if TRANSFER_RE.match(line):
            warnings.append(
                f"{path}:{lineno}: TransferLog non supporta il filtro condizionale CustomLog; lasciato invariato"
            )
            out.append(line)
            continue

        if not CUSTOM_RE.match(line):
            out.append(line)
            continue

        custom_count += 1
        body = line.rstrip("\r\n")
        ending = line[len(body):]
        tokens, parse_warning = tokenize_customlog(body)

        if parse_warning:
            warnings.append(f"{path}:{lineno}: {parse_warning}; lasciato invariato")
            out.append(line)
            continue

        assert tokens is not None
        indent_match = re.match(r"^\s*", line)
        indent = indent_match.group(0) if indent_match else ""

        if len(tokens) not in (3, 4):
            warnings.append(
                f"{path}:{lineno}: CustomLog ha {len(tokens)-1} argomenti dopo la direttiva; forma non gestita automaticamente"
            )
            out.append(line)
            continue

        destination, log_format = tokens[1], tokens[2]
        condition = tokens[3] if len(tokens) == 4 else None

        if mode == "enable":
            if condition is None:
                new_line = render_customlog(indent, destination, log_format, ENV_TOKEN, ending)
            elif condition.lower() == ENV_TOKEN.lower():
                patched_count += 1
                out.append(line)
                continue
            elif condition.lower().startswith("expr="):
                if RWF_ENV.lower() in condition.lower():
                    patched_count += 1
                    out.append(line)
                    continue
                new_line = render_customlog(
                    indent,
                    destination,
                    log_format,
                    rwf_wrapped_expression(condition[5:]),
                    ending,
                )
            elif condition.lower().startswith("env="):
                converted = env_to_expression(condition)
                if converted is None:
                    warnings.append(
                        f"{path}:{lineno}: condizione {condition!r} non convertibile in sicurezza; lasciata invariata"
                    )
                    out.append(line)
                    continue
                if RWF_ENV.lower() in condition.lower():
                    patched_count += 1
                    out.append(line)
                    continue
                new_line = render_customlog(indent, destination, log_format, converted, ending)
            else:
                warnings.append(
                    f"{path}:{lineno}: terzo argomento CustomLog non riconosciuto ({condition!r}); lasciato invariato"
                )
                out.append(line)
                continue

            out.append(new_line)
            patched_count += 1
            if new_line != line:
                changed = True
            continue

        if mode == "disable":
            if condition is None:
                out.append(line)
                continue
            if condition.lower() == ENV_TOKEN.lower():
                new_line = render_customlog(indent, destination, log_format, None, ending)
                out.append(new_line)
                changed = changed or (new_line != line)
                continue
            unwrapped = unwrap_rwf_expression(condition)
            if unwrapped is not None:
                restored_condition = expression_to_simple_env(unwrapped) or unwrapped
                new_line = render_customlog(indent, destination, log_format, restored_condition, ending)
                out.append(new_line)
                changed = changed or (new_line != line)
                continue
            if RWF_ENV.lower() in condition.lower():
                warnings.append(
                    f"{path}:{lineno}: espressione contiene {RWF_ENV} ma non nel wrapper standard V4.3; non modificata"
                )
            out.append(line)
            continue

        # audit
        if condition is not None and (
            condition.lower() == ENV_TOKEN.lower()
            or RWF_ENV.lower() in condition.lower()
        ):
            patched_count += 1
        elif condition is not None:
            warnings.append(
                f"{path}:{lineno}: CustomLog già condizionale ma senza filtro RwF"
            )
        out.append(line)

    new = "".join(out)
    return changed, custom_count, patched_count, warnings, new


def restore_changed(changed_paths: list[Path], backup_root: Path) -> None:
    for path in changed_paths:
        src = backup_root / path.relative_to("/")
        if src.is_file():
            shutil.copy2(src, path)


def sanitize_tree(apache_root: Path, backup_root: Path | None) -> tuple[int, list[Path]]:
    """Remove only the exact RwF env token from Apache config files.

    This deliberately does not need apachectl/DUMP_INCLUDES so it can repair a
    configuration made invalid by an older interrupted RwF installer.
    """
    changed: list[Path] = []
    seen: set[str] = set()
    if not apache_root.is_dir():
        return 0, changed

    candidates: list[Path] = []
    for p in apache_root.rglob("*"):
        try:
            if not (p.is_file() or p.is_symlink()):
                continue
            rp = p.resolve()
            key = str(rp)
            if key in seen or not rp.is_file():
                continue
            seen.add(key)
            candidates.append(rp)
        except OSError:
            continue

    for path in candidates:
        try:
            original = path.read_text(encoding="utf-8", errors="surrogateescape")
        except (OSError, UnicodeError):
            continue
        if ENV_TOKEN not in original:
            continue
        lines = original.splitlines(keepends=True)
        out: list[str] = []
        file_changed = False
        for line in lines:
            body = line.rstrip("\r\n")
            ending = line[len(body):]
            new_body = TOKEN_AT_END_RE.sub("", body)
            if new_body != body:
                file_changed = True
            out.append(new_body + ending)
        if file_changed:
            if backup_root is not None:
                backup_file(path, backup_root)
            atomic_write(path, "".join(out))
            changed.append(path)
    return len(changed), changed


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--apachectl")
    parser.add_argument("--mode", choices=("enable", "disable", "audit", "sanitize"), required=True)
    parser.add_argument("--backup-dir")
    parser.add_argument("--apache-root")
    args = parser.parse_args()

    if args.mode in ("enable", "sanitize") and not args.backup_dir:
        parser.error("--backup-dir è obbligatorio con --mode enable/sanitize")
    if args.mode != "sanitize" and not args.apachectl:
        parser.error("--apachectl è obbligatorio salvo --mode sanitize")
    if args.mode == "sanitize" and not args.apache_root:
        parser.error("--apache-root è obbligatorio con --mode sanitize")

    backup_root = Path(args.backup_dir).resolve() if args.backup_dir else None

    if args.mode == "sanitize":
        count, paths = sanitize_tree(Path(args.apache_root).resolve(), backup_root)
        for path in paths:
            print(f"ACCESSLOG RIPRISTINATO: {path}")
        print(f"ACCESSLOG SANITIZE: changed_files={count}")
        return 0

    assert args.apachectl is not None
    try:
        files = apache_includes(args.apachectl)
    except Exception as exc:
        print(f"ACCESSLOG ERRORE: {exc}", file=sys.stderr)
        return 2

    total_custom = 0
    total_patched = 0
    changed_files = 0
    warnings: list[str] = []
    changed_paths: list[Path] = []

    for path in files:
        try:
            changed, custom_count, patched_count, file_warnings, new = process_file(path, args.mode)
        except (OSError, UnicodeError) as exc:
            warnings.append(f"{path}: impossibile analizzare il file: {exc}")
            continue

        total_custom += custom_count
        total_patched += patched_count
        warnings.extend(file_warnings)

        if changed and args.mode != "audit":
            if backup_root is not None:
                backup_file(path, backup_root)
            atomic_write(path, new)
            changed_files += 1
            changed_paths.append(path)
            print(f"ACCESSLOG MODIFICATO: {path}")

    # Transactional syntax validation for any actual changes.
    if changed_paths:
        ok, output = apache_configtest(args.apachectl)
        if not ok:
            if backup_root is not None:
                restore_changed(changed_paths, backup_root)
                restored_ok, restored_output = apache_configtest(args.apachectl)
                print("ACCESSLOG ERRORE: configtest fallito dopo la modifica; file ripristinati automaticamente.", file=sys.stderr)
                print(output, file=sys.stderr)
                if not restored_ok:
                    print("ACCESSLOG ERRORE: anche il configtest dopo il ripristino fallisce:\n" + restored_output, file=sys.stderr)
            else:
                print("ACCESSLOG ERRORE: configtest fallito dopo la modifica e non è disponibile un backup automatico.", file=sys.stderr)
                print(output, file=sys.stderr)
            return 5

    print(
        f"ACCESSLOG RISULTATO: mode={args.mode} active_files={len(files)} "
        f"customlog={total_custom} filtered={total_patched} changed_files={changed_files} "
        f"warnings={len(warnings)}"
    )
    for warning in warnings:
        print(f"ACCESSLOG ATTENZIONE: {warning}", file=sys.stderr)

    if total_custom == 0:
        print("ACCESSLOG ATTENZIONE: nessun CustomLog attivo individuato", file=sys.stderr)
        return 3
    if warnings:
        return 4
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
