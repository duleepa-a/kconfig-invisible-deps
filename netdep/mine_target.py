#!/usr/bin/env python3
"""
mine_target.py -- mine for THE class this research targets, and nothing else.

The class, stated precisely:

    code gated by option A establishes shared state;
    code gated by option B, in a different compilation unit, uses that state;
    no Kconfig rule ties B to A;
    so a configuration may retain B while removing A, and B then uses state
    that was never established.

Two queries are run, each aimed at one half of how such a bug gets fixed.

  Q1 "reader was fixed": the message names a CONFIG_ option AND reports a fault
     AND describes state that was absent (NULL / unset / uninitialised). The fix
     normally adds the check the reader was missing.

  Q2 "Kconfig was fixed": the patch modifies a Kconfig file, and the message is
     NOT about a build failure. Adding a `depends on` or `select` to stop a
     *runtime* problem is a maintainer stating the dependency was real but
     unexpressed -- which is this class by definition.

Build failures are excluded throughout: they are caught by the compiler, never
reach a running kernel, and are therefore not the phenomenon under study.
"""
import re
import subprocess
import sys
from collections import OrderedDict

REPO = sys.argv[1] if len(sys.argv) > 1 else '/work/hist'
RANGE = sys.argv[2] if len(sys.argv) > 2 else 'v4.18..v5.4'

FAULT = (r'NULL pointer|null-ptr|NULL deref|Oops|oops|kernel panic|BUG:|'
         r'crash|unable to handle|general protection')
STATE_ABSENT = (r'\bNULL\b|unset|uninitiali[sz]ed|not initiali[sz]ed|'
                r'not registered|not populated|never set|not allocated|'
                r'not assigned|empty')
CONFIG_MENTION = r'CONFIG_[A-Z0-9_]+'

# a build failure, not a runtime dependency
BUILD_FAIL = (r'implicit declaration|undefined reference|build error|'
              r'compile error|build failure|compilation error|-Werror|'
              r'builds? break|fails? to build|link error|undefined symbol')


def git(*args):
    return subprocess.run(['git', '-C', REPO] + list(args),
                          stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                          universal_newlines=True, errors='replace').stdout


log = git('log', '--no-merges', '--format=%H%x01%s%x01%b%x02', RANGE)
records = []
for rec in log.split('\x02'):
    rec = rec.strip('\n')
    if not rec:
        continue
    p = rec.split('\x01')
    if len(p) >= 2:
        records.append((p[0], p[1], p[2] if len(p) > 2 else ''))

print(f'commits scanned: {len(records)}', file=sys.stderr)

q1 = OrderedDict()
for sha, subj, body in records:
    text = subj + '\n' + body
    if re.search(BUILD_FAIL, text, re.I):
        continue
    if not re.search(FAULT, text, re.I):
        continue
    if not re.search(STATE_ABSENT, text, re.I):
        continue
    cfgs = set(re.findall(CONFIG_MENTION, text))
    if not cfgs:
        continue
    q1[sha] = {'subject': subj, 'cfgs': sorted(cfgs)[:4]}

print(f'Q1 hits: {len(q1)}', file=sys.stderr)

# Q2 needs the file list, so restrict to plausible messages first
q2 = OrderedDict()
for sha, subj, body in records:
    text = subj + '\n' + body
    if re.search(BUILD_FAIL, text, re.I):
        continue
    if not re.search(r'depends on|select |Kconfig|dependenc', text, re.I):
        continue
    if not re.search(FAULT + r'|' + STATE_ABSENT, text, re.I):
        continue
    files = [l for l in git('show', '--name-only', '--format=', sha).splitlines() if l]
    kc = [f for f in files if 'Kconfig' in f]
    if kc:
        q2[sha] = {'subject': subj, 'kconfig': kc[:3], 'nfiles': len(files)}

print(f'Q2 hits: {len(q2)}', file=sys.stderr)

print()
print('=' * 86)
print(f'Q1 -- fault + absent state + a named CONFIG option  ({len(q1)} commits)')
print('=' * 86)
for sha, d in q1.items():
    print(f'{sha[:12]}  {d["subject"][:70]}')
    print(f'              options named: {", ".join(d["cfgs"])}')

print()
print('=' * 86)
print(f'Q2 -- Kconfig changed to fix a non-build problem  ({len(q2)} commits)')
print('=' * 86)
for sha, d in q2.items():
    print(f'{sha[:12]}  {d["subject"][:70]}')
    print(f'              Kconfig: {", ".join(d["kconfig"])}  (files: {d["nfiles"]})')
