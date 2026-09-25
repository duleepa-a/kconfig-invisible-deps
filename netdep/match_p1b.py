#!/usr/bin/env python3
"""
match_p1b.py -- P1b funnel: writer and reader of the same global in the
SAME object file, but under different #ifdef CONFIG_* regions.

Unlike match.py's cross-object F4/F5 (which needed the "link-error
filter" because removing a whole FILE can remove a symbol's definition
too), P1b operates within a single translation unit that is either fully
compiled or not (a Makefile-level, all-or-nothing fact). What varies
*within* it is which #ifdef-guarded regions the PREPROCESSOR includes.
So the check here is purely: does the guard map allow a state where the
reader's region is included while the writer's region is excluded?

KNOWN GAP (documented, not silently assumed away): this script does not
verify that X's own *declaration* survives when the writer's region is
excluded. If X's declaration sits inside the SAME #ifdef block as the
writer, removing that block would also remove the declaration, which
would be a compile error the build already catches (same shape as the
cross-object link-error filter, just one level down). Candidates
surviving this funnel therefore still require a manual check -- read the
file, confirm X's own declaration is outside (or independently guarded
from) the writer's block -- before being reported as genuine.

Usage:
    match_p1b.py --out /work/out --guards /work/out/guards.tsv
"""
import argparse
import csv
import os
import sys
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from guardmap import separable, config_symbols, free_symbols, is_satisfiable  # noqa: E402


def load_tsv(path):
    with open(path, newline='') as f:
        return list(csv.DictReader(f, delimiter='\t'))


def load_guards(path):
    g = {}
    with open(path) as f:
        next(f)  # header
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


def cond_for(guards, src_file, src_line, root_prefix):
    if not src_file or not src_line:
        return 'True'
    f = src_file
    if root_prefix and f.startswith(root_prefix):
        f = f[len(root_prefix):]
    f = f.lstrip('/')
    return guards.get((f, int(src_line)), 'True')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--out', required=True)
    ap.add_argument('--guards', required=True)
    ap.add_argument('--root-prefix', default='/work/linux-cosmic/',
                     help='prefix to strip from xref.tsv DWARF absolute paths '
                          'before matching guards.tsv (which is keyed by the same '
                          'root-relative paths used in p1b_files.txt)')
    args = ap.parse_args()

    globals_rows = load_tsv(os.path.join(args.out, 'globals.tsv'))
    xref_rows = load_tsv(os.path.join(args.out, 'xref.tsv'))
    guards = load_guards(args.guards)

    defs = defaultdict(list)
    for r in globals_rows:
        if r['section'] != '.rodata':
            defs[r['sym']].append(r)

    by_sym_obj = defaultdict(list)
    for r in xref_rows:
        by_sym_obj[(r['sym'], r['obj'])].append(r)

    def is_init_writer(r):
        return r['access'] in ('STORE', 'RMW') and (
            '.init.text' in r['func_section'] or 'initcall' in r['func_section']
        )

    def is_reader(r):
        return r['access'] in ('LOAD', 'LOAD_GUARD')

    funnel = {
        'G1_same_object_writer_reader_pairs': 0,
        'G2_have_a_recorded_guard_on_either_side': 0,
        'G3_conditions_differ': 0,
        'G4_sat_separable': 0,
        'candidates_total': 0,
    }

    candidates = []
    for (sym, obj), refs in by_sym_obj.items():
        if sym not in defs:
            continue
        writers = [r for r in refs if is_init_writer(r)]
        readers = [r for r in refs if is_reader(r)]
        if not writers or not readers:
            continue

        all_writers_in_file = [r for r in refs if r['access'] in ('STORE', 'RMW', 'ADDR')]

        for w in writers:
            for r in readers:
                if w['src_file'] == r['src_file'] and w['src_line'] == r['src_line']:
                    continue
                funnel['G1_same_object_writer_reader_pairs'] += 1

                writer_cond = cond_for(guards, w['src_file'], w['src_line'], args.root_prefix)
                reader_cond = cond_for(guards, r['src_file'], r['src_line'], args.root_prefix)

                if writer_cond == 'True' and reader_cond == 'True':
                    continue  # both unconditional -- no #ifdef structure involved at all
                funnel['G2_have_a_recorded_guard_on_either_side'] += 1

                if writer_cond == reader_cond:
                    continue  # same guarded region -- always compiled together
                funnel['G3_conditions_differ'] += 1

                witness = separable(reader_cond, writer_cond)
                if witness is None:
                    continue
                funnel['G4_sat_separable'] += 1

                real_witness = {k: v for k, v in witness.items() if config_symbols(k)}
                sole_writer_in_file = len(all_writers_in_file) == 1
                unguarded = not any(
                    x['access'] == 'LOAD_GUARD' and x['sym'] == sym and
                    x['obj'] == r['obj'] and x['func'] == r['func']
                    for x in refs
                )
                risky_section = defs[sym][0]['section'] in ('.bss', 'COMMON')

                score = (
                    3 * risky_section + 3 * unguarded + 2 * sole_writer_in_file
                )

                candidates.append({
                    'score': score,
                    'sym': sym,
                    'obj': obj,
                    'def_section': defs[sym][0]['section'],
                    'writer_func': w['func'],
                    'writer_loc': f"{w['src_file']}:{w['src_line']}",
                    'writer_cond': writer_cond,
                    'reader_func': r['func'],
                    'reader_loc': f"{r['src_file']}:{r['src_line']}",
                    'reader_cond': reader_cond,
                    'witness': ','.join(f'{k}={v}' for k, v in sorted(real_witness.items())) or '(only-unknown-macros)',
                    'sole_writer_in_file': sole_writer_in_file,
                    'risky_section': risky_section,
                    'unguarded': unguarded,
                })

    funnel['candidates_total'] = len(candidates)
    candidates.sort(key=lambda c: -c['score'])

    cand_path = os.path.join(args.out, 'candidates_p1b.tsv')
    fields = ['score', 'sym', 'obj', 'def_section', 'writer_func', 'writer_loc',
              'writer_cond', 'reader_func', 'reader_loc', 'reader_cond', 'witness',
              'sole_writer_in_file', 'risky_section', 'unguarded']
    with open(cand_path, 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=fields, delimiter='\t', lineterminator='\n')
        w.writeheader()
        for c in candidates:
            w.writerow({k: c[k] for k in fields})

    funnel_path = os.path.join(args.out, 'funnel_p1b.txt')
    with open(funnel_path, 'w') as f:
        for k, v in funnel.items():
            line = f'{k}\t{v}'
            print(line)
            f.write(line + '\n')

    print(f'\ncandidates written to {cand_path}', file=sys.stderr)


if __name__ == '__main__':
    main()
