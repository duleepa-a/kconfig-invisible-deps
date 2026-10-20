#!/usr/bin/env python3
"""
kconfig_sep.py -- solver-backed replacement for filter F5.

F5 as implemented asks whether the writer's and the definition's build-condition
STRINGS differ. That is unsound in two ways: two conditions can differ textually
while one implies the other, and the test never consults the Kconfig rules, so it
cannot see `depends on`, `select`, or the tristate rule that caps a symbol at `m`
when a dependency is modular.

This script asks the real question of a real Kconfig model (kconfiglib):

    is there a configuration in which the READER's condition holds
    while the WRITER's condition does not?

Method, per candidate pair:
  1. load a base .config;
  2. drive every symbol in the writer's condition to n;
  3. drive every symbol in the reader's condition to y (falling back to m);
  4. read the resulting values back and evaluate both conditions.

Step 4 is what makes this sound: Kconfig may refuse an assignment, or may turn a
symbol back on through `select`, and the readback shows what actually happened.

Usage:
    kconfig_sep.py --root <kernel tree> --candidates <candidates.tsv> \
                   --config .config --out verdicts.tsv
"""
import argparse
import csv
import os
import re
import sys

import kconfiglib

CONFIG_RE = re.compile(r'CONFIG_\w+')


def cond_symbols(cond):
    """CONFIG_* names in a condition string. 'obj-y' / empty => unconditional."""
    if not cond or cond.strip() in ('obj-y', 'None', ''):
        return []
    return CONFIG_RE.findall(cond)


def cond_holds(kconf, names, unknown):
    """A conjunctive condition holds when every named symbol is not n.
    An unconditional condition (no names) always holds."""
    for n in names:
        sym = kconf.syms.get(n[len('CONFIG_'):])
        if sym is None:
            unknown.add(n)
            return None
        if sym.str_value == 'n':
            return False
    return True


def try_separate(kconf, base_config, writer_names, reader_names, unknown):
    """Attempt to build a configuration with reader on and writer off.
    Returns (separable, writer_holds, reader_holds)."""
    kconf.load_config(base_config)

    # 1. drive the writer's condition off
    for n in writer_names:
        sym = kconf.syms.get(n[len('CONFIG_'):])
        if sym is not None and 0 in sym.assignable:
            sym.set_value(0)

    # 2. drive the reader's condition on, preferring y, accepting m
    for n in reader_names:
        sym = kconf.syms.get(n[len('CONFIG_'):])
        if sym is None:
            continue
        for v in (2, 1):
            if v in sym.assignable:
                sym.set_value(v)
                break

    w = cond_holds(kconf, writer_names, unknown)
    r = cond_holds(kconf, reader_names, unknown)
    if w is None or r is None:
        return None, w, r
    return (r and not w), w, r


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--root', required=True, help='kernel source tree')
    ap.add_argument('--candidates', required=True)
    ap.add_argument('--config', default='.config', help='base .config, relative to --root')
    ap.add_argument('--out', required=True)
    args = ap.parse_args()

    os.environ.setdefault('srctree', '.')
    os.environ.setdefault('ARCH', 'x86')
    os.environ.setdefault('SRCARCH', 'x86')
    os.environ.setdefault('KERNELVERSION', '4.18.0')
    for v in ('CC', 'HOSTCC'):
        os.environ.setdefault(v, 'gcc')
    os.environ.setdefault('HOSTCXX', 'g++')
    os.environ.setdefault('CC_VERSION_TEXT', 'gcc 7.5.0')

    cwd = os.getcwd()
    os.chdir(args.root)
    kconf = kconfiglib.Kconfig('Kconfig', warn=False)
    os.chdir(cwd)

    rows = list(csv.DictReader(open(args.candidates), delimiter='\t'))
    unknown = set()
    cache = {}
    out_rows = []

    for r in rows:
        wnames = tuple(sorted(set(cond_symbols(r['writer_cond']))))
        rnames = tuple(sorted(set(cond_symbols(r['reader_cond']))))
        key = (wnames, rnames)
        if key not in cache:
            if not wnames:
                # unconditional writer: always built, never separable
                cache[key] = (False, True, True)
            else:
                os.chdir(args.root)
                cache[key] = try_separate(kconf, args.config, list(wnames),
                                          list(rnames), unknown)
                os.chdir(cwd)
        sep, w, rr = cache[key]
        out_rows.append({
            'sym': r['sym'],
            'writer_obj': r['writer_obj'],
            'reader_obj': r['reader_obj'],
            'reader_func': r['reader_function'] if 'reader_function' in r else r.get('reader_func', ''),
            'writer_cond': r['writer_cond'],
            'reader_cond': r['reader_cond'],
            'separable': {True: 'yes', False: 'no', None: 'unknown'}[sep],
        })

    with open(args.out, 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=list(out_rows[0].keys()), delimiter='\t',
                           lineterminator='\n')
        w.writeheader()
        w.writerows(out_rows)

    sep_syms = {r['sym'] for r in out_rows if r['separable'] == 'yes'}
    unk_syms = {r['sym'] for r in out_rows if r['separable'] == 'unknown'}
    all_syms = {r['sym'] for r in out_rows}
    print(f'pairs: {len(out_rows)}   distinct symbols: {len(all_syms)}')
    print(f'separable by solver:   {len([r for r in out_rows if r["separable"] == "yes"])} pairs, '
          f'{len(sep_syms)} symbols')
    print(f'NOT separable:         {len([r for r in out_rows if r["separable"] == "no"])} pairs')
    print(f'unknown (symbol absent from Kconfig): {len(unk_syms)} symbols')
    if unknown:
        print('unresolved CONFIG names:', ' '.join(sorted(unknown))[:300])
    print()
    print('symbols still separable:')
    for s in sorted(sep_syms):
        print('  ', s)


if __name__ == '__main__':
    main()
