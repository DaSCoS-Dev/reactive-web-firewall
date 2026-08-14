#!/usr/bin/env python3
# Copyright (C) 2026 Daniele Stefano Continenza <daniele@dascos.info>
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Merge V6 active RwF rules into an existing rules file conservatively.

- Existing custom rules win by name.
- Missing shipped active rules are appended.
- Only two exact, known V5 shapes are semantically migrated in place:
  * env-secret V5 default regex;
  * wordpress-batch-v1 temporary field rule used before TargetRegex existed.
- Existing policy is retained during those migrations.
- Commented/installation-specific shipped rules are never activated.
"""
from __future__ import annotations
import argparse
import re
from pathlib import Path

RULE_RE = re.compile(r'^(?P<indent>\s*)(?P<directive>RwfRule(?:Exact|Prefix|Regex|TargetRegex))\s+(?P<name>[^\s#]+)\s+(?P<rest>.+?)\s*$')

KNOWN_OLD = {
    'env-secret': re.compile(r'^RwfRuleRegex\s+env-secret\s+"\(\^\|/\)\[\.\]env\(\?:\[\./\]\|\$\)"\s+(?P<policy>\S+)\s*$'),
    'wordpress-batch-v1': re.compile(r'^RwfRuleRegex\s+wordpress-batch-v1\s+"\^/\+wp-json/batch/v1\(\?:/\|\$\)"\s+(?P<policy>\S+)\s*$'),
}


def active_rules(lines: list[str]):
    out = []
    for idx, line in enumerate(lines):
        if line.lstrip().startswith('#'):
            continue
        m = RULE_RE.match(line)
        if m:
            out.append((idx, m.group('name'), line.rstrip('\n')))
    return out


def with_policy(shipped_line: str, policy: str) -> str:
    head, _old_policy = shipped_line.rsplit(None, 1)
    return f'{head} {policy}'


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('--existing', required=True)
    ap.add_argument('--shipped', required=True)
    ap.add_argument('--output', required=True)
    args = ap.parse_args()

    existing = Path(args.existing).read_text(encoding='utf-8').splitlines()
    shipped = Path(args.shipped).read_text(encoding='utf-8').splitlines()

    shipped_rules = active_rules(shipped)
    shipped_map = {name: line for _, name, line in shipped_rules}
    existing_rules = active_rules(existing)
    existing_names = {name for _, name, _ in existing_rules}

    migrated = []
    for idx, name, old_line in existing_rules:
        old_re = KNOWN_OLD.get(name)
        new_line = shipped_map.get(name)
        if old_re is None or new_line is None:
            continue
        m = old_re.match(old_line.strip())
        if not m:
            continue
        existing[idx] = with_policy(new_line, m.group('policy'))
        migrated.append(name)

    missing = [(name, line) for _, name, line in shipped_rules if name not in existing_names]

    if missing:
        if existing and existing[-1].strip():
            existing.append('')
        existing.extend([
            '# ============================================================',
            '# RwF V6 managed additions',
            '# Added by installer merge; pre-existing local rules preserved.',
            '# ============================================================',
        ])
        existing.extend(line for _, line in missing)

    Path(args.output).write_text('\n'.join(existing).rstrip() + '\n', encoding='utf-8')

    print(f'existing={len(existing_rules)} migrated={len(migrated)} added={len(missing)}')
    if migrated:
        print('migrated_names=' + ','.join(migrated))
    if missing:
        print('added_names=' + ','.join(name for name, _ in missing))
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
