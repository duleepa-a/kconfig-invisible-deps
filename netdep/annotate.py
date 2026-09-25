#!/usr/bin/env python3
"""
annotate.py -- join tool output (readable_csv.py) with hand-written verdicts.

Tool columns are copied unchanged. Manual columns are appended with a MANUAL_
prefix, from results/manual_verdicts.csv, matched by symbol; a verdict with a
non-empty reader_func_match applies only to rows whose reader_function equals it.
Rows with no verdict are marked NOT_AUDITED (never silently blank).

Usage: annotate.py --input boot=a.tsv --input lazy=b.tsv --out-annotated annotated_<ts>.csv --out-summary by_symbol_<ts>.csv
"""
import argparse, csv, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from readable_csv import rows_for, COLUMNS
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
MANUAL = ['verdict', 'mechanism', 'reason', 'depth', 'recorded_in']


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--input', action='append', required=True, metavar='RUN=TSV')
    ap.add_argument('--verdicts', default=os.path.join(HERE, 'results', 'manual_verdicts.csv'))
    ap.add_argument('--out-annotated', required=True)
    ap.add_argument('--out-summary', required=True)
    a = ap.parse_args()

    verdicts = {}
    for v in csv.DictReader(open(a.verdicts, encoding='utf-8')):
        verdicts.setdefault(v['symbol'], []).append(v)

    header = COLUMNS
    all_rows = []
    for spec in a.input:
        run, tsv = spec.split('=', 1)
        all_rows += [dict(zip(header, r)) for r in rows_for(tsv, run)]

    def pick_for(r):
        cands = verdicts.get(r['symbol'], [])
        return next((v for v in cands if v['reader_func_match'] and v['reader_func_match'] == r['reader_function']), None)             or next((v for v in cands if not v['reader_func_match']), None)

    counts, missing, by_sym = Counter(), Counter(), {}
    with open(a.out_annotated, 'w', newline='', encoding='utf-8-sig') as f:
        w = csv.writer(f)
        w.writerow(header + ['MANUAL_' + m for m in MANUAL])
        for r in all_rows:
            pick = pick_for(r)
            if pick is None:
                missing[r['symbol']] += 1
                vals = ['NOT_AUDITED', '', 'no verdict recorded for this symbol', '', '']
            else:
                vals = [pick[m] for m in MANUAL]
            counts[vals[0]] += 1
            w.writerow([r[h] for h in header] + vals)
            d = by_sym.setdefault((r['symbol'], vals[0]), dict(vals=vals, rows=0, exposed=0, runs=set(),
                                                               defined_in=r['defined_in'], section=r['section']))
            d['rows'] += 1
            d['exposed'] += r['exposed_by_cozart_config'] == 'yes'
            d['runs'].add(r['run'])
    with open(a.out_summary, 'w', newline='', encoding='utf-8-sig') as f:
        w = csv.writer(f)
        w.writerow(['symbol', 'runs', 'rows', 'rows_exposed_by_cozart', 'defined_in', 'section'] +
                   ['MANUAL_' + m for m in MANUAL])
        for (sym, verdict), d in sorted(by_sym.items(), key=lambda x: (x[0][1] != 'GENUINE_UNGUARDED_READER',
                                                                        -x[1]['exposed'], -x[1]['rows'])):
            w.writerow([sym, '+'.join(sorted(d['runs'])), d['rows'], d['exposed'], d['defined_in'], d['section']] + d['vals'])
    print('rows:', len(all_rows), dict(counts))
    if missing:
        print('symbols with no verdict:', dict(missing))


if __name__ == '__main__':
    main()
