#!/usr/bin/env python3
"""
mine_bugs2.py -- second mining pass, tuned to the runtime class.

The first pass required Kconfig wording and therefore selected build errors.
This pass looks for the runtime shape instead: a commit whose message reports a
fault AND states that some option or module was absent at the time. That is the
wording maintainers use for this class, and it is how the original control set
was found.

Each hit is then classified by what the fix actually changed:
  guard_added  -- the patch introduces a runtime test (the reader now checks)
  kconfig      -- the patch changes a Kconfig file (dependency made explicit)
  other        -- neither
"""
import re
import subprocess
import sys
from collections import Counter, OrderedDict

REPO = sys.argv[1] if len(sys.argv) > 1 else '/work/hist'
RANGE = sys.argv[2] if len(sys.argv) > 2 else 'v4.18..v5.4'

FAULT = (r'NULL pointer|null-ptr|NULL deref|Oops|oops|kernel panic|BUG:|'
         r'crash|unable to handle|general protection')
ABSENT = (r'is disabled|not loaded|disabled at boot|is not enabled|'
          r'was not loaded|module is not|not present|is absent')

GUARD_ADD = re.compile(
    r'^\+.*(if\s*\(\s*!\s*\w|if\s*\(\s*\w+\s*==\s*NULL|'
    r'if\s*\(\s*\w+\s*\)|_enabled\(\)|IS_ERR|WARN_ON)', re.M)


def git(*args):
    return subprocess.run(['git', '-C', REPO] + list(args),
                          stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                          universal_newlines=True, errors='replace').stdout


out = git('log', '--no-merges', '-i', '--extended-regexp',
          '--grep', FAULT, '--format=%H%x01%s%x01%b%x02', RANGE)

cands = []
for rec in out.split('\x02'):
    rec = rec.strip('\n')
    if not rec:
        continue
    p = rec.split('\x01')
    if len(p) < 3:
        continue
    sha, subj, body = p[0], p[1], p[2]
    if re.search(ABSENT, subj + '\n' + body, re.I):
        cands.append((sha, subj, body))

print(f'commits reporting a fault with something absent: {len(cands)}', file=sys.stderr)

rows = OrderedDict()
for sha, subj, body in cands:
    diff = git('show', '--format=', '--unified=3', sha)
    files = [l for l in git('show', '--name-only', '--format=', sha).splitlines() if l]
    kind = []
    if any('Kconfig' in f for f in files):
        kind.append('kconfig')
    if GUARD_ADD.search(diff):
        kind.append('guard_added')
    if not kind:
        kind = ['other']
    rows[sha] = {
        'subject': subj,
        'kind': '+'.join(kind),
        'files': files,
        'dirs': sorted({f.split('/')[0] for f in files})[:3],
        'nfiles': len(files),
        'absent': (re.search(ABSENT, subj + '\n' + body, re.I) or [''])[0]
        if isinstance(re.search(ABSENT, subj + '\n' + body, re.I), str)
        else re.search(ABSENT, subj + '\n' + body, re.I).group(0),
    }

print()
print('=' * 80)
print('FAULT-WITH-SOMETHING-ABSENT COMMITS')
print('=' * 80)
for sha, d in rows.items():
    print(f'{sha[:12]}  [{d["kind"]:18s}] [{",".join(d["dirs"])}] {d["subject"][:72]}')
    print(f'              trigger wording: "{d["absent"]}"   files: {d["nfiles"]}')

print()
print('summary by what the fix changed:', dict(Counter(d['kind'] for d in rows.values())))
print('summary by subsystem:', dict(Counter(d['dirs'][0] if d['dirs'] else '?'
                                            for d in rows.values())))
