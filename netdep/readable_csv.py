#!/usr/bin/env python3
"""
readable_csv.py -- turn a match.py candidates TSV into a human-readable CSV.

Purely mechanical: every column and the `why_flagged` sentence are derived from
the tool's own fields. No manual judgement is added here (see annotate.py).

Usage: readable_csv.py --input boot=a.tsv --input lazy=b.tsv --out readable_csv_<timestamp>.csv
"""
import argparse, csv, re

PREFIXES = ('/work/cz/./', '/work/cz/', '/work/linux-cosmic/./', '/work/linux-cosmic/', '/work/ayc/./', '/work/ayc/')


def clean(p):
    for pre in PREFIXES:
        if p.startswith(pre):
            return p[len(pre):]
    return p


def yn(v):
    return 'yes' if str(v) == 'True' else 'no'


COLUMNS = ['run', 'row', 'symbol', 'defined_in', 'section', 'definition_built_when',
           'writer_function', 'writer_object', 'writer_source', 'writer_runs_at', 'writer_built_when',
           'reader_function', 'reader_object', 'reader_source', 'reader_built_when',
           'only_one_writer', 'no_static_initializer_bss', 'no_compare_in_reader_function',
           'exposed_by_cozart_config', 'score', 'why_flagged']


def rows_for(tsv, run):
    out = []
    rows = list(csv.DictReader(open(tsv), delimiter='	'))
    for i, r in enumerate(rows, 1):
        boot = r['writer_is_boot'] == 'True'
        flags = []
        if r['sole_writer'] == 'True':
            flags.append('it is the only writer in the tree')
        if r['risky_section'] == 'True':
            flags.append('the variable is in .bss (no static initializer)')
        if r['unguarded'] == 'True':
            flags.append('no compare/test on the variable was seen in the reader function')
        if r['cozart_exposed'] == 'True':
            flags.append("Cozart's composed nginx config drops the writer but keeps the reader")
        why = (f"{r['sym']} is defined in {r['def_obj']} ({r['def_section']}, built when {r['def_cond']}). "
               f"{r['writer_func']}() in {r['writer_obj']} writes it "
               f"({'at boot (__init)' if boot else 'at run time, not boot'}), built when {r['writer_cond']}. "
               f"{r['reader_func']}() in {r['reader_obj']} reads it, built when {r['reader_cond']}. "
               f"The writer's build condition differs from the definition's, so a configuration could "
               f"drop the writer and keep the reader. "
               + ('Also: ' + '; '.join(flags) + '.' if flags else ''))
        out.append([run, i, r['sym'], r['def_obj'], r['def_section'], r['def_cond'],
                    r['writer_func'], r['writer_obj'], clean(r['writer_src']),
                    'boot (__init)' if boot else 'run time', r['writer_cond'],
                    r['reader_func'], r['reader_obj'], clean(r['reader_src']), r['reader_cond'],
                    yn(r['sole_writer']), yn(r['risky_section']), yn(r['unguarded']),
                    yn(r['cozart_exposed']), r['score'], why])
    return out


def convert_many(inputs, out):
    n = 0
    with open(out, 'w', newline='', encoding='utf-8-sig') as f:
        w = csv.writer(f)
        w.writerow(COLUMNS)
        for run, tsv in inputs:
            rows = rows_for(tsv, run)
            w.writerows(rows)
            n += len(rows)
    return n


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('--input', action='append', required=True, metavar='RUN=TSV',
                    help='e.g. boot=candidates_boot.tsv (repeatable)')
    ap.add_argument('--out', required=True)
    a = ap.parse_args()
    print(convert_many([i.split('=', 1) for i in a.input], a.out), 'rows written to', a.out)
