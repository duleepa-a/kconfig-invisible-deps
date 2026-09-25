#!/usr/bin/env python3
"""
exposure_check.py -- does Cozart's ACTUAL composed nginx configuration
realise each P1b candidate, not just "is some hypothetical assignment
satisfiable"?

match_p1b.py's `separable()` does a brute-force SAT search and returns
the FIRST satisfying witness it finds -- useful to know a separation is
*possible*, but not the same as checking whether Cozart's real build
actually hits it. This does the precise version: plug in the REAL
CONFIG_* values from Cozart's composed nginx set (present = True, absent
= False) and evaluate reader/writer/declaration conditions directly. One
evaluation, not a search -- no ambiguity about which witness to check.

UNK_* free variables (unknown macros -- see guardmap.py) have no real
value in composed_nginx.txt by construction (they're not Kconfig
options). Conditions containing them are reported as UNDETERMINED rather
than guessed in either direction.

Usage:
    exposure_check.py --candidates /work/out/candidates_p1b_verified.tsv \
                       --composed /work/composed_nginx.txt
"""
import argparse
import csv
import re
import sys

CONFIG_RE = re.compile(r'\bCONFIG_\w+\b')
UNK_RE = re.compile(r'\bUNK_\w+\b')


def load_composed(path):
    with open(path) as f:
        return set(l.strip() for l in f if l.strip())


def real_eval(expr, composed):
    """Evaluate expr using Cozart's real config as ground truth. Returns
    (value, undetermined_reason) -- value is None if undetermined."""
    unk = UNK_RE.findall(expr)
    if unk:
        return None, f'contains unknown macro(s): {sorted(set(unk))}'
    cfgs = CONFIG_RE.findall(expr)
    env = {c: (c in composed) for c in cfgs}
    try:
        return bool(eval(expr, {'__builtins__': {}}, env)), None
    except Exception as e:
        return None, f'eval error: {e}'


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--candidates', required=True)
    ap.add_argument('--composed', required=True)
    args = ap.parse_args()

    composed = load_composed(args.composed)
    with open(args.candidates, newline='') as f:
        rows = list(csv.DictReader(f, delimiter='\t'))

    n_exposed = 0
    n_not_exposed = 0
    n_undetermined = 0
    out_rows = []

    for row in rows:
        reader_val, reader_undet = real_eval(row['reader_cond'], composed)
        writer_val, writer_undet = real_eval(row['writer_cond'], composed)

        reasons = [r for r in (reader_undet, writer_undet) if r]
        if reasons:
            verdict = f'UNDETERMINED ({"; ".join(reasons)})'
            n_undetermined += 1
        elif reader_val and not writer_val:
            verdict = 'EXPOSED (Cozart nginx config realises reader-present/writer-absent)'
            n_exposed += 1
        else:
            verdict = (f'NOT EXPOSED (reader={reader_val}, writer={writer_val} '
                       f'in the real config -- this exact separation does not occur)')
            n_not_exposed += 1

        row['cozart_exposure'] = verdict
        out_rows.append(row)

    print(f'EXPOSED (real config realises this separation):     {n_exposed}')
    print(f'NOT EXPOSED (real config does not realise it):      {n_not_exposed}')
    print(f'UNDETERMINED (guard involves an unknown macro):     {n_undetermined}')

    fields = list(rows[0].keys()) + ['cozart_exposure'] if rows else []
    out_path = args.candidates.rsplit('.', 1)[0] + '_exposure.tsv'
    with open(out_path, 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=fields, delimiter='\t', lineterminator='\n')
        w.writeheader()
        for r in out_rows:
            w.writerow(r)
    print(f'\nwritten to {out_path}', file=sys.stderr)


if __name__ == '__main__':
    main()
