#!/usr/bin/env python3
"""
match_ops.py -- ops-table / direct-pointer-assignment funnel.

Pattern (the "dominant blocker" the original research plan predicted,
never tested until now):

    /* subsystem A, conditionally compiled */
    const struct proto_ops a_ops = { .connect = a_connect, ... };

    /* elsewhere -- could be A's own registration code, or a totally
       different file B */
    some_dispatch_table[N] = &a_ops;   // ADDR reference to a_ops

If a_ops's DEFINING object is excluded (its Kconfig condition is off)
while the object holding the SECOND ADDR reference survives, the second
reference is dangling/undefined at best (link-error filter applies the
same as Part 1) -- or, if the second reference itself is what populates
a slot some UNRELATED, unconditional dispatch path reads, a silent gap.

This reuses Part 1's exact F4 (link-error filter) / F5 (Kconfig
separable) logic, but with the "writer" event redefined from STORE/RMW
in .init.text to ADDR anywhere -- taking a struct's address is the
"exposure" event for an ops table, not a scalar write. Restricted to
struct-shaped symbols (size >= 24 bytes, to exclude plain locks/counters)
whose access is ADDR-dominated (never loaded as a scalar value, which
would indicate it's just an ordinary object, not a dispatch target).

Usage:
    match_ops.py --out /work/out --filename-db /work/out/filename.db \
                 --composed /work/composed_nginx.txt \
                 --root-prefix /work/linux-cosmic/
"""
import argparse
import csv
import os
import sys
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from match import load_tsv, obj_to_srcfile_guess  # noqa: E402
from makefile_cond import resolve_condition  # noqa: E402


def transitive_cond(root, obj):
    """Full multi-level Makefile condition, ANDed into one expression
    string (or None if fully unconditional). Uses makefile_cond.py, NOT
    the single-level filename.db -- that gap (missing outer composite-
    module gates) is exactly what produced the pernet search's 37->8
    false-positive collapse, and applies here identically. stop_dir is
    the object's own top-level directory (net/kernel/mm/lib), not
    hardcoded, since candidates span all four subtrees."""
    src = obj_to_srcfile_guess(obj)
    top = src.split('/', 1)[0]
    conds = resolve_condition(root, src, stop_dir=top)
    if not conds:
        return None
    return ' and '.join(conds)


def load_composed(path):
    with open(path) as f:
        return set(l.strip() for l in f if l.strip())


MIN_STRUCT_SIZE = 24
ALLOWED_ACCESS = {'ADDR', 'DATAREF', 'CALL'}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--out', required=True)
    ap.add_argument('--composed', required=True)
    ap.add_argument('--root', default='/work/linux-cosmic')
    args = ap.parse_args()

    globals_rows = load_tsv(os.path.join(args.out, 'globals.tsv'))
    xref_rows = load_tsv(os.path.join(args.out, 'xref.tsv'))
    composed = load_composed(args.composed)
    cond_cache = {}

    def cached_cond(obj):
        if obj not in cond_cache:
            cond_cache[obj] = transitive_cond(args.root, obj)
        return cond_cache[obj]

    defs = defaultdict(list)
    for r in globals_rows:
        defs[r['sym']].append(r)

    by_sym = defaultdict(list)
    for r in xref_rows:
        by_sym[r['sym']].append(r)

    funnel = {
        'H0_struct_shaped_symbols': 0,
        'H1_addr_referenced': 0,
        'H2_cross_object_addr': 0,
        'H3_link_error_filter_survives': 0,
        'H4_kconfig_separable': 0,
        'candidates_total': 0,
    }

    candidates = []

    for sym, refs in by_sym.items():
        d = defs.get(sym)
        if not d or int(d[0]['size']) < MIN_STRUCT_SIZE:
            continue
        accesses = set(r['access'] for r in refs)
        if not accesses.issubset(ALLOWED_ACCESS):
            continue
        addr_refs = [r for r in refs if r['access'] == 'ADDR']
        if not addr_refs:
            continue
        funnel['H0_struct_shaped_symbols'] += 1
        funnel['H1_addr_referenced'] += 1

        addr_objs = sorted(set(r['obj'] for r in addr_refs))
        if len(addr_objs) < 2:
            continue
        funnel['H2_cross_object_addr'] += 1

        def_entries = d
        for a_obj in addr_objs:
            a_refs = [r for r in addr_refs if r['obj'] == a_obj]
            for b_obj in addr_objs:
                if a_obj == b_obj:
                    continue
                surviving_defs = [e for e in def_entries if e['obj'] != a_obj]
                if not surviving_defs:
                    continue
                funnel['H3_link_error_filter_survives'] += 1

                a_cond = cached_cond(a_obj)
                b_cond = cached_cond(b_obj)
                if a_cond == b_cond:
                    continue
                funnel['H4_kconfig_separable'] += 1

                def real_eval(cond):
                    if cond is None:
                        return True
                    env = {c: (c in composed) for c in cond.replace(' and ', ' ').split()}
                    try:
                        return bool(eval(cond, {'__builtins__': {}}, env))
                    except Exception:
                        return None
                a_val = real_eval(a_cond)
                b_val = real_eval(b_cond)
                exposed = (a_val is False) and (b_val is True)

                candidates.append({
                    'sym': sym,
                    'def_section': def_entries[0]['section'],
                    'size': def_entries[0]['size'],
                    'a_obj': a_obj, 'a_func': a_refs[0]['func'],
                    'a_cond': a_cond or 'obj-y',
                    'b_obj': b_obj,
                    'b_cond': b_cond or 'obj-y',
                    'cozart_exposed': exposed,
                })

    funnel['candidates_total'] = len(candidates)

    cand_path = os.path.join(args.out, 'candidates_ops.tsv')
    fields = ['sym', 'def_section', 'size', 'a_obj', 'a_func', 'a_cond',
              'b_obj', 'b_cond', 'cozart_exposed']
    with open(cand_path, 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=fields, delimiter='\t', lineterminator='\n')
        w.writeheader()
        for c in candidates:
            w.writerow({k: c[k] for k in fields})

    for k, v in funnel.items():
        print(f'{k}\t{v}')
    print(f'\nwritten to {cand_path}', file=sys.stderr)


if __name__ == '__main__':
    main()
