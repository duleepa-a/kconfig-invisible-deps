#!/usr/bin/env python3
"""
verify_p1b_decl.py -- adds the declaration-conditionality check to the
P1b candidate set: for each (sym, obj) pair, finds X's own file-scope
declaration via decl_finder, looks up its guard condition, and checks the
3-way SAT of (reader present) AND (writer absent) AND (declaration
survives). A candidate that fails this 3-way check but passed the
2-way check in match_p1b.py is a confirmed false positive of exactly the
kind that sank `mem_section` and `sysctl_softlockup_all_cpu_backtrace` in
the manual audit -- this makes that check automatic and total instead of
one-off-by-hand.

Usage:
    verify_p1b_decl.py --out /work/out --root /work/linux-cosmic \
                        --guards /work/out/guards.tsv
"""
import argparse
import csv
import os
import sys
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from guardmap import is_satisfiable, config_symbols, free_symbols  # noqa: E402
from decl_finder import find_declaration  # noqa: E402


def load_guards(path):
    g = {}
    with open(path) as f:
        next(f)
        for line in f:
            line = line.rstrip('\n')
            if not line:
                continue
            parts = line.split('\t')
            if len(parts) != 3:
                continue
            file, ln, cond = parts
            g[(file, int(ln))] = cond
    return g


def cond_for(guards, file, line):
    return guards.get((file, line), 'True')


def sat3(reader_expr, writer_expr, decl_expr):
    """SAT of reader AND NOT writer AND decl over the union of all free
    variables. Returns a witness dict or None."""
    syms = sorted(free_symbols(reader_expr) | free_symbols(writer_expr) | free_symbols(decl_expr))
    n = len(syms)
    if n > 22:
        return None
    for bits in range(1 << n):
        a = {s: bool((bits >> i) & 1) for i, s in enumerate(syms)}
        r = is_satisfiable(reader_expr, a)
        w = is_satisfiable(writer_expr, a)
        d = is_satisfiable(decl_expr, a)
        if None in (r, w, d):
            return None
        if r and not w and d:
            return a
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--out', required=True)
    ap.add_argument('--root', required=True)
    ap.add_argument('--guards', required=True)
    args = ap.parse_args()

    guards = load_guards(args.guards)
    cand_path = os.path.join(args.out, 'candidates_p1b.tsv')
    with open(cand_path, newline='') as f:
        rows = list(csv.DictReader(f, delimiter='\t'))

    # resolve declaration once per (sym, obj) -- cache to avoid re-reading
    # the same source file for every reader-site repeat of the same symbol
    decl_cache = {}

    out_rows = []
    n_confirmed_fp = 0
    n_still_candidate = 0
    n_unverified = 0

    for row in rows:
        sym = row['sym']
        obj = row['obj']
        key = (sym, obj)
        if key not in decl_cache:
            src = os.path.join(args.root, obj[:-2] + '.c') if obj.endswith('.o') else None
            result = None
            if src and os.path.isfile(src):
                result = find_declaration(src, sym)
            decl_cache[key] = (src, result)
        src, result = decl_cache[key]

        if result is None:
            verdict = 'UNVERIFIED (declaration not found by text search)'
            n_unverified += 1
        elif result[0] == 'AMBIGUOUS':
            verdict = f'UNVERIFIED (ambiguous: {len(result[1])} candidate lines)'
            n_unverified += 1
        else:
            decl_line, decl_text = result
            rel_src = os.path.relpath(src, args.root)
            decl_cond = cond_for(guards, rel_src, decl_line)
            witness3 = sat3(row['reader_cond'], row['writer_cond'], decl_cond)
            if witness3 is None:
                verdict = f'FALSE POSITIVE (decl at {rel_src}:{decl_line} `{decl_text.strip()}` cond={decl_cond} -- not jointly satisfiable)'
                n_confirmed_fp += 1
            else:
                real_w = {k: v for k, v in witness3.items() if config_symbols(k)}
                verdict = f'STILL A CANDIDATE (decl at {rel_src}:{decl_line} cond={decl_cond}; 3-way witness: {real_w})'
                n_still_candidate += 1

        row['decl_verdict'] = verdict
        out_rows.append(row)

    fields = list(rows[0].keys()) + ['decl_verdict'] if rows else []
    out_path = os.path.join(args.out, 'candidates_p1b_verified.tsv')
    with open(out_path, 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=fields, delimiter='\t', lineterminator='\n')
        w.writeheader()
        for row in out_rows:
            w.writerow(row)

    print(f'confirmed false positives (declaration-conditionality check): {n_confirmed_fp}')
    print(f'still a candidate after 3-way check: {n_still_candidate}')
    print(f'unverified (declaration not resolvable by text search): {n_unverified}')
    print(f'\nwritten to {out_path}', file=sys.stderr)


if __name__ == '__main__':
    main()
