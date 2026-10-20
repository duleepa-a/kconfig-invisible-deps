#!/usr/bin/env python3
"""
distinct_variables.py -- one row per distinct variable from match.py's candidate pairs.

Reads one or more candidates.tsv files and writes a CSV with a row per variable.
Every column is computed from the tool's own output; no manual judgement is added.

Usage:
    distinct_variables.py --input boot=my_net_boot/candidates.tsv \
                          --input lazy=my_net_lazy/candidates.tsv \
                          --input fs=my_fs_boot/candidates.tsv \
                          --out distinct_variables.csv
"""
import argparse
import csv
from collections import OrderedDict


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--input', action='append', required=True, metavar='RUN=TSV')
    ap.add_argument('--out', required=True)
    a = ap.parse_args()

    vars_ = OrderedDict()
    for spec in a.input:
        run, path = spec.split('=', 1)
        for r in csv.DictReader(open(path), delimiter='\t'):
            v = vars_.setdefault(r['sym'], {
                'runs': set(), 'pairs': 0, 'writers': set(), 'readers': set(),
                'defined_in': r['def_obj'], 'section': r['def_section'],
                'definition_built_when': r['def_cond'], 'writer_built_when': set(),
            })
            v['runs'].add(run)
            v['pairs'] += 1
            v['writers'].add(r['writer_obj'] + '::' + r['writer_func'])
            v['readers'].add(r['reader_obj'] + '::' + r['reader_func'])
            v['writer_built_when'].add(r['writer_cond'])

    cols = ['symbol', 'runs', 'pairs', 'distinct_writers', 'distinct_readers',
            'defined_in', 'section', 'definition_built_when', 'writer_built_when']
    with open(a.out, 'w', newline='', encoding='utf-8-sig') as f:
        w = csv.writer(f)
        w.writerow(cols)
        for sym, v in sorted(vars_.items(), key=lambda x: -x[1]['pairs']):
            w.writerow([sym, '+'.join(sorted(v['runs'])), v['pairs'],
                        len(v['writers']), len(v['readers']), v['defined_in'],
                        v['section'], v['definition_built_when'],
                        ' | '.join(sorted(v['writer_built_when']))])
    print(len(vars_), 'distinct variables written to', a.out)


if __name__ == '__main__':
    main()
