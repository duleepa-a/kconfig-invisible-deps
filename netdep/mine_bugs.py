#!/usr/bin/env python3
"""
mine_bugs.py -- mine kernel history for fixes of the dependency class under study.

The class: code region A establishes shared state that code region B uses, with no
Kconfig rule linking them, so a configuration can retain B while removing A.

Two signals are searched for.

  SIGNAL 1 (strongest): a commit that touches a Kconfig file AND whose message
  describes a runtime fault. Adding a `depends on` or `select` to stop a crash is
  the maintainers stating, in their own words, that a required dependency was
  missing from Kconfig. That is exactly this class.

  SIGNAL 2: a commit that adds a NULL test to a reader, with a message tying the
  fault to an absent module or a disabled option.

Both are message-based and therefore have low recall. They are used as a source of
instances, not as a measurement of prevalence.
"""
import re
import subprocess
import sys
from collections import OrderedDict

REPO = sys.argv[1] if len(sys.argv) > 1 else '/work/hist'
RANGE = sys.argv[2] if len(sys.argv) > 2 else 'v4.18..v5.4'

FAULT = r'NULL pointer|null pointer|NULL deref|oops|Oops|panic|BUG:|crash|use-after-free|unable to handle'
DEP = r'depends on|select |Kconfig|dependency|dependencies'
ABSENT = (r'not enabled|is disabled|not loaded|not set|=n\b|absent|missing|'
          r'without CONFIG|if CONFIG|not built|module is not')


def git(*args):
    return subprocess.run(['git', '-C', REPO] + list(args),
                          stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                          universal_newlines=True, errors='replace').stdout


def commits(grep_args):
    out = git('log', '--no-merges', '--format=%H%x01%s%x01%b%x02', RANGE, *grep_args)
    for rec in out.split('\x02'):
        rec = rec.strip('\n')
        if not rec:
            continue
        parts = rec.split('\x01')
        if len(parts) >= 3:
            yield parts[0], parts[1], parts[2]


def files_of(sha):
    return [l for l in git('show', '--name-only', '--format=', sha).splitlines() if l]


results = OrderedDict()

# SIGNAL 1: message mentions a fault AND a dependency notion
print('mining signal 1 (fault + dependency language) ...', file=sys.stderr)
for sha, subj, body in commits(['-i', '--grep', FAULT, '--extended-regexp']):
    text = subj + '\n' + body
    if not re.search(DEP, text, re.I):
        continue
    if not re.search(ABSENT, text, re.I):
        continue
    fs = files_of(sha)
    kconfig = [f for f in fs if 'Kconfig' in f]
    results[sha] = {
        'subject': subj,
        'files': len(fs),
        'kconfig': kconfig,
        'touches_kconfig': bool(kconfig),
        'dirs': sorted({f.split('/')[0] for f in fs}),
    }

print(f'candidate commits: {len(results)}', file=sys.stderr)
print()

kc = [(s, d) for s, d in results.items() if d['touches_kconfig']]
nokc = [(s, d) for s, d in results.items() if not d['touches_kconfig']]

print('=' * 78)
print(f'GROUP A -- fault-fixing commits that ALSO modify Kconfig: {len(kc)}')
print('(a missing Kconfig dependency, stated by the maintainers)')
print('=' * 78)
for sha, d in kc:
    print(f'{sha[:12]}  {d["subject"][:92]}')
    for f in d['kconfig'][:3]:
        print(f'              Kconfig: {f}')

print()
print('=' * 78)
print(f'GROUP B -- fault + dependency language, source only: {len(nokc)}')
print('=' * 78)
for sha, d in nokc[:40]:
    print(f'{sha[:12]}  [{",".join(d["dirs"][:3])}] {d["subject"][:80]}')
print(f'... {max(0, len(nokc) - 40)} more')
