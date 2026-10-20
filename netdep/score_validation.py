#!/usr/bin/env python3
"""
score_validation.py -- check the F6-F9 flags and `score` against audited cases.

The F6-F9 flags are prioritisation features, not proof, and they overlap. This
compares them with the manual verdicts (results/manual_verdicts.csv, the same
file annotate.py consumes) so any claim like "unguarded readers are the
interesting ones" can be tested instead of assumed.

For every boolean feature it prints, over the audited candidate rows:

    rows with the feature  /  of those, GENUINE_UNGUARDED_READER  / precision
    rows without it        /  of those, GENUINE_UNGUARDED_READER  / precision

and for `score` the rank of each genuine row (1 = top). Unaudited rows and
UNCERTAIN verdicts are excluded and counted, never guessed.

Usage:
    score_validation.py --input boot=f_net_boot/candidates.tsv \
        --input lazy=f_net_lazy/candidates.tsv \
        --verdicts results/manual_verdicts.csv
"""
import argparse
import csv
import sys

FEATURES = ['sole_writer', 'risky_section', 'unguarded', 'cozart_exposed',
            'pointer_sized', 'addr_taken', 'exposed_if_module_unloaded']
POSITIVE = 'GENUINE_UNGUARDED_READER'


def truthy(v):
    return str(v).strip().lower() in ('true', 'yes', '1')


def load_verdicts(path):
    by_sym = {}
    with open(path, encoding='utf-8', newline='') as f:
        for v in csv.DictReader(f):
            by_sym.setdefault(v['symbol'], []).append(v)
    return by_sym


def verdict_for(row, by_sym):
    """Same matching rule as annotate.py: a verdict naming this reader
    function wins over the symbol-wide (blank reader_func_match) one."""
    cands = by_sym.get(row['sym'], [])
    reader = row.get('reader_func') or row.get('reader_function', '')
    hit = next((v for v in cands if v['reader_func_match'] and v['reader_func_match'] == reader), None)
    hit = hit or next((v for v in cands if not v['reader_func_match']), None)
    return hit['verdict'] if hit else None


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument('--input', action='append', required=True, metavar='RUN=candidates.tsv')
    ap.add_argument('--verdicts', required=True)
    args = ap.parse_args(argv)

    by_sym = load_verdicts(args.verdicts)
    rows, skipped = [], 0
    for spec in args.input:
        run, path = spec.split('=', 1)
        with open(path, newline='') as f:
            for r in csv.DictReader(f, delimiter='\t'):
                v = verdict_for(r, by_sym)
                if v in (POSITIVE, 'NOT_A_BUG'):
                    r['_pos'] = (v == POSITIVE)
                    r['_run'] = run
                    rows.append(r)
                else:
                    skipped += 1

    npos = sum(1 for r in rows if r['_pos'])
    print('audited rows: %d (%d genuine); skipped (unaudited or uncertain): %d' % (len(rows), npos, skipped))
    if not rows:
        return 0
    print('base rate: %.3f\n' % (npos / float(len(rows))))
    print('%-28s %22s %22s' % ('feature', 'with: n / genuine / prec', 'without: n / genuine / prec'))
    for feat in FEATURES:
        if feat not in rows[0]:
            continue
        w = [r for r in rows if truthy(r[feat])]
        wo = [r for r in rows if not truthy(r[feat])]

        def cell(rs):
            g = sum(1 for r in rs if r['_pos'])
            return '%5d / %4d / %5.2f' % (len(rs), g, g / float(len(rs))) if rs else '    0 /    - /     -'
        print('%-28s %22s %22s' % (feat, cell(w), cell(wo)))

    ranked = sorted(rows, key=lambda r: -float(r['score']))
    print('\nscore rank of genuine rows (1 = highest score, %d audited rows):' % len(ranked))
    for i, r in enumerate(ranked, start=1):
        if r['_pos']:
            print('  #%-4d score=%-3s %s  reader=%s' % (i, r['score'], r['sym'], r.get('reader_func', '')))
    return 0


if __name__ == '__main__':
    sys.exit(main())
