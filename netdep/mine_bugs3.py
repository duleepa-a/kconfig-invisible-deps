#!/usr/bin/env python3
"""
mine_bugs3.py -- broad, message-only mining for the dependency class.

Earlier passes used one narrow wording. This pass runs several independent
pattern families and merges the results, so that an instance described in any of
the usual ways is caught. It deliberately stays message-only (no `git show`), so
it does not trigger blob fetches and runs over the whole range quickly.

Families:
  A  uninitialised state       -- the carrier is a variable nobody set
  B  feature/option disabled   -- the carrier is whatever the option provides
  C  module absent             -- the carrier lives in a module that is not loaded
  D  stub / dummy returns      -- the carrier is a stub's return value
  E  missing check added       -- the fix adds a test that should have been there

A commit is reported once, with every family that matched it, which is a useful
signal in itself: the strongest instances tend to match several.
"""
import re
import subprocess
import sys
from collections import Counter, OrderedDict

REPO = sys.argv[1] if len(sys.argv) > 1 else '/work/hist'
RANGE = sys.argv[2] if len(sys.argv) > 2 else 'v4.18..v5.4'

FAULT = (r'NULL pointer|null-ptr|NULL deref|NULL-deref|Oops|oops|kernel panic|'
         r'BUG:|crash|unable to handle|general protection|segfault')

FAMILIES = {
    'A_uninit': r'uninitiali[sz]ed|not initiali[sz]ed|never initiali[sz]ed|'
                r'is not set up|was not set up|left unset|is unset',
    'B_disabled': r'is disabled|when disabled|if disabled|not enabled|'
                  r'built without|compiled out|without CONFIG_|when CONFIG_|'
                  r'if CONFIG_|CONFIG_\w+ is not set|=n\b',
    'C_module': r'module is not loaded|not loaded|module is absent|'
                r'is not present|without the \w+ module|module missing',
    'D_stub': r'returns? NULL|return NULL|stub|dummy implementation|no-op|noop',
    'E_check': r'add(?:s|ed)? (?:a )?missing (?:NULL )?check|missing NULL|'
               r'IS_ERR_OR_NULL|add NULL check|check for NULL|forgot to check',
}


def git(*args):
    return subprocess.run(['git', '-C', REPO] + list(args),
                          stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                          universal_newlines=True, errors='replace').stdout


# one pass over the range; filter in Python so each commit is read once
out = git('log', '--no-merges', '--format=%H%x01%s%x01%b%x02', RANGE)

hits = OrderedDict()
total = 0
for rec in out.split('\x02'):
    rec = rec.strip('\n')
    if not rec:
        continue
    p = rec.split('\x01')
    if len(p) < 2:
        continue
    total += 1
    sha, subj = p[0], p[1]
    body = p[2] if len(p) > 2 else ''
    text = subj + '\n' + body
    if not re.search(FAULT, text, re.I):
        continue
    fams = [name for name, pat in FAMILIES.items() if re.search(pat, text, re.I)]
    if not fams:
        continue
    hits[sha] = {'subject': subj, 'fams': fams, 'n': len(fams)}

print(f'commits scanned: {total}', file=sys.stderr)
print(f'fault + at least one family: {len(hits)}', file=sys.stderr)

print()
print('=' * 86)
print('MATCHES, strongest first (number of independent pattern families matched)')
print('=' * 86)
for sha, d in sorted(hits.items(), key=lambda x: -x[1]['n']):
    fams = ','.join(f.split('_')[0] for f in d['fams'])
    print(f'{sha[:12]}  [{d["n"]}: {fams:11s}] {d["subject"][:84]}')

print()
print('family totals:', dict(Counter(f for d in hits.values() for f in d['fams'])))
print('commits matching >=2 families:', sum(1 for d in hits.values() if d['n'] >= 2))
