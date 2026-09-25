#!/usr/bin/env python3
"""Join backslash-continued lines in every Makefile under a tree, in place.
Equivalent to Cozart's `remove-makefile-escaped-newlines` (sed
':a;N;$!ba;s/\\\n/ /g'), reimplemented without shell-escaping ambiguity."""
import sys
import subprocess

root = sys.argv[1]
out = subprocess.run(['find', root, '-name', 'Makefile'],
                      stdout=subprocess.PIPE, universal_newlines=True)
files = [l for l in out.stdout.splitlines() if l]
n_changed = 0
for path in files:
    with open(path, 'r', errors='surrogateescape') as f:
        content = f.read()
    joined = content.replace('\\\n', ' ')
    if joined != content:
        n_changed += 1
        with open(path, 'w', errors='surrogateescape') as f:
            f.write(joined)
print(f'{len(files)} Makefiles scanned, {n_changed} changed', file=sys.stderr)
