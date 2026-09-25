#!/usr/bin/env python3
"""
match.py -- the D4-D9 funnel described in the research plan.

Joins globals.tsv + xref.tsv (from netdep.py) with filename.db (Makefile
condition per source file, Cozart's extract-makefile.awk output) and the
composed nginx Kconfig set, to find candidates matching:

    A writes global X during __init  ->  B reads X at runtime
    -> no Kconfig dependency forces A given B
    -> X's DEFINITION survives even when A is absent (link-error filter)

Reports the funnel F0..F9 and a ranked candidate table.

Usage:
    match.py --out /work/out --filename-db /work/out/filename.db \
              --composed-config /work/composed_nginx.txt
"""
import argparse
import csv
import os
import sys
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from makefile_cond import resolve_condition  # noqa: E402

_transitive_cache = {}


def transitive_file_condition(obj, root):
    """Multi-level Makefile condition via makefile_cond.py, ANDed into one
    expression string (None if fully unconditional). Supersedes the flat
    filename.db lookup, which silently drops outer composite-module gates
    -- exactly the bug that turned the pernet search's 37 candidates into
    8 once fixed. Cached per-object since the same file is looked up many
    times across candidate pairs."""
    if obj not in _transitive_cache:
        src = obj_to_srcfile_guess(obj)
        top = src.split('/', 1)[0]
        conds = resolve_condition(root, src, stop_dir=top)
        _transitive_cache[obj] = ' and '.join(conds) if conds else None
    return _transitive_cache[obj]


def real_eval_cond(cond, composed):
    """Evaluate a (possibly multi-conjunct) condition string against
    Cozart's real composed config. None (unconditional) = always True."""
    if cond is None:
        return True
    toks = cond.replace(' and ', ' ').split()
    env = {t: (t in composed) for t in toks}
    try:
        return bool(eval(cond, {'__builtins__': {}}, env))
    except Exception:
        return None


def load_tsv(path):
    with open(path, newline='') as f:
        return list(csv.DictReader(f, delimiter='\t'))


def load_filename_db(path):
    """file -> CONFIG_X ('obj-$(CONFIG_X)'). Absent from this map means
    the file is built unconditionally (obj-y -- extract-makefile.awk
    deliberately drops those, mapping obj-y to CONFIG_OBJ then filtering
    it out)."""
    cond = {}
    with open(path) as f:
        for line in f:
            line = line.rstrip('\n')
            if not line:
                continue
            parts = line.split(' ')
            if len(parts) != 2:
                continue
            fname, config = parts
            cond[fname] = config
    return cond


def file_condition(fname, filename_db, root_prefix):
    """Normalise fname (from DWARF, often an absolute build path) against
    filename_db (relative paths, Cozart-style). Returns CONFIG_X or None
    (None = unconditional / could not resolve)."""
    if not fname:
        return None
    f = fname
    if root_prefix and f.startswith(root_prefix):
        f = f[len(root_prefix):]
    f = f.lstrip('/')
    if f in filename_db:
        return filename_db[f]
    # object path (e.g. net/foo/bar.o) vs source path mismatch fallback:
    # try swapping a trailing .o for .c/.h if caller passed an obj path
    return None


def obj_to_srcfile_guess(obj_rel):
    """net/foo/bar.o -> net/foo/bar.c, used when DWARF src_file is empty
    (DATAREF rows) and we fall back to the object's own file identity."""
    if obj_rel.endswith('.o'):
        return obj_rel[:-2] + '.c'
    return obj_rel


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--out', required=True, help='dir containing globals.tsv/xref.tsv, and where candidates.tsv/funnel.txt are written')
    ap.add_argument('--filename-db', required=True)
    ap.add_argument('--composed-config', required=True, help='newline-separated CONFIG_* names realised in the target Cozart configuration')
    ap.add_argument('--root-prefix', default='/work/linux-cosmic/', help='prefix to strip from DWARF absolute paths before matching filename.db')
    ap.add_argument('--reader-scope', default='net/', help='only count LOAD sites whose obj path starts with this prefix (default: net/, per research scope)')
    ap.add_argument('--use-transitive', action='store_true',
                     help='use makefile_cond.py\'s multi-level Makefile resolver instead of '
                          'the flat filename.db lookup -- corrects the composite-module-gate '
                          'omission that was found via the pernet search. Recommended for any '
                          'new run; kept opt-in so earlier net/ results are not silently altered.')
    ap.add_argument('--root', default='/work/linux-cosmic', help='kernel source root, for --use-transitive')
    ap.add_argument('--writer-mode', choices=['boot', 'lazy', 'any'], default='boot',
                     help='boot (default): STORE/RMW from .init.text/initcall only, matching '
                          'every prior search in this project. lazy: STORE/RMW from ordinary '
                          '.text (NOT boot-time) -- first-use/on-demand initialization, the '
                          'population "boot" structurally excludes. any: both combined.')
    args = ap.parse_args()

    globals_rows = load_tsv(os.path.join(args.out, 'globals.tsv'))
    xref_rows = load_tsv(os.path.join(args.out, 'xref.tsv'))
    filename_db = load_filename_db(args.filename_db)
    with open(args.composed_config) as f:
        composed = set(l.strip() for l in f if l.strip())

    funnel = {}

    # F0: OBJECT symbol definitions, excluding pure .rodata (never a write target)
    defs = defaultdict(list)  # sym -> [ {obj, section, size, bind} ]
    for r in globals_rows:
        if r['section'] == '.rodata':
            continue
        defs[r['sym']].append(r)
    funnel['F0_definitions'] = sum(len(v) for v in defs.values())
    funnel['F0_distinct_symbols'] = len(defs)

    # index xref by symbol
    by_sym = defaultdict(list)
    for r in xref_rows:
        by_sym[r['sym']].append(r)

    def is_boot_writer(r):
        return r['access'] in ('STORE', 'RMW') and (
            '.init.text' in r['func_section'] or 'initcall' in r['func_section']
        )

    def is_lazy_writer(r):
        # Any conditionally-runnable write NOT at boot time -- e.g. a
        # first-use/on-demand initialization (`if (!x) x = alloc(...)`)
        # in ordinary .text, which stays resident and can run whenever
        # its trigger fires, unlike __init code (freed after boot). This
        # is the population is_boot_writer structurally excludes: the
        # Kconfig-invisible-dependency shape is identical, just the
        # writer's timing is runtime-triggered instead of boot-time.
        return r['access'] in ('STORE', 'RMW') and not (
            '.init.text' in r['func_section'] or 'initcall' in r['func_section']
        )

    if args.writer_mode == 'boot':
        is_init_writer = is_boot_writer
    elif args.writer_mode == 'lazy':
        is_init_writer = is_lazy_writer
    else:  # 'any'
        def is_init_writer(r):
            return r['access'] in ('STORE', 'RMW')

    def is_reader(r):
        return r['access'] in ('LOAD', 'LOAD_GUARD') and r['obj'].startswith(args.reader_scope)

    def has_guard(sym, obj, func):
        for r in by_sym[sym]:
            if r['obj'] == obj and r['func'] == func and r['access'] == 'LOAD_GUARD':
                return True
        return False

    candidates = []
    f1_syms = set()
    f2_syms = set()
    f3_pairs = 0
    f4_pairs = 0
    f5_pairs = 0
    f6_pairs = 0
    f7_pairs = 0
    f8_pairs = 0
    f9_pairs = 0

    for sym, refs in by_sym.items():
        if sym not in defs:
            continue  # symbol referenced but never defined in our built set (external, out of scope)

        writers = [r for r in refs if is_init_writer(r)]
        readers = [r for r in refs if is_reader(r)]
        if not writers:
            continue
        f1_syms.add(sym)
        if not readers:
            continue
        f2_syms.add(sym)

        all_writers = [r for r in refs if r['access'] in ('STORE', 'RMW', 'ADDR')]
        def_entries = defs[sym]

        for w in writers:
            for r in readers:
                if w['obj'] == r['obj']:
                    continue  # same compilation unit -- not cross-unit
                f3_pairs += 1

                # F4: link-error filter. True iff some definition of sym
                # lives in an object OTHER than the writer's object -- i.e.
                # removing the writer's object does not remove the symbol.
                surviving_defs = [d for d in def_entries if d['obj'] != w['obj']]
                if not surviving_defs:
                    continue
                f4_pairs += 1

                # F5: Makefile condition differs between (a) the surviving
                # definition's file and (b) the writer's file. Condition is a
                # property of "which .c file produced this .o" -- derive it
                # from the OBJECT's own identity, never from the DWARF-
                # attributed src_file, which can point into an inlined
                # header (e.g. a WRITE_ONCE()/barrier() macro in
                # include/linux/compiler.h) that filename.db never indexes,
                # silently producing a false "unconditional" reading.
                if args.use_transitive:
                    def_cond = transitive_file_condition(surviving_defs[0]['obj'], args.root)
                    writer_cond = transitive_file_condition(w['obj'], args.root)
                    reader_cond = transitive_file_condition(r['obj'], args.root)
                else:
                    def_cond = file_condition(obj_to_srcfile_guess(surviving_defs[0]['obj']), filename_db, args.root_prefix)
                    writer_cond = file_condition(obj_to_srcfile_guess(w['obj']), filename_db, args.root_prefix)
                    reader_cond = file_condition(obj_to_srcfile_guess(r['obj']), filename_db, args.root_prefix)
                # Separable only if the definition's condition differs from the
                # writer's. Equal conditions -- including the case where BOTH
                # are None (i.e. both unconditional/obj-y) -- mean no Kconfig
                # separation is possible: they are compiled together always.
                if def_cond == writer_cond:
                    continue
                f5_pairs += 1

                # F6: sole writer (no other STORE/RMW/ADDR site touches sym anywhere)
                sole_writer = len(all_writers) == 1
                if sole_writer:
                    f6_pairs += 1

                # F7: no safe static default (.bss or COMMON)
                risky_section = surviving_defs[0]['section'] in ('.bss', 'COMMON')
                if risky_section:
                    f7_pairs += 1

                # F8: reader site has no guard hint anywhere in that function
                unguarded = not has_guard(sym, r['obj'], r['func'])
                if unguarded:
                    f8_pairs += 1

                # F9: Cozart exposure -- writer's config absent from composed
                # set while reader's config (or unconditional) is present.
                if args.use_transitive:
                    # writer_cond/reader_cond may be multi-conjunct
                    # ("CONFIG_A and CONFIG_B") under transitive resolution
                    # -- a plain `in composed` membership test is wrong for
                    # those; evaluate the expression against real config
                    # values instead (same fix applied in match_ops.py).
                    w_val = real_eval_cond(writer_cond, composed)
                    r_val = real_eval_cond(reader_cond, composed)
                    writer_absent = (w_val is False)
                    reader_present = (r_val is True)
                else:
                    writer_absent = (writer_cond is not None) and (writer_cond not in composed)
                    reader_present = (reader_cond is None) or (reader_cond in composed)
                exposed = writer_absent and reader_present
                if exposed:
                    f9_pairs += 1

                score = (
                    3 * risky_section + 3 * unguarded + 2 * sole_writer +
                    2 * ('.init.text' in w['func_section']) +
                    1 * (os.path.dirname(w['obj']) != os.path.dirname(r['obj']))
                )

                candidates.append({
                    'sym': sym,
                    'def_obj': surviving_defs[0]['obj'],
                    'def_section': surviving_defs[0]['section'],
                    'writer_obj': w['obj'], 'writer_func': w['func'],
                    'writer_is_boot': '.init.text' in w['func_section'] or 'initcall' in w['func_section'],
                    'writer_src': f"{w['src_file']}:{w['src_line']}",
                    'writer_cond': writer_cond or 'obj-y',
                    'reader_obj': r['obj'], 'reader_func': r['func'],
                    'reader_src': f"{r['src_file']}:{r['src_line']}",
                    'reader_cond': reader_cond or 'obj-y',
                    'def_cond': def_cond or 'obj-y',
                    'sole_writer': sole_writer,
                    'risky_section': risky_section,
                    'unguarded': unguarded,
                    'cozart_exposed': exposed,
                    'score': score,
                })

    funnel['F1_symbols_with_init_writer'] = len(f1_syms)
    funnel['F2_symbols_with_init_writer_and_net_reader'] = len(f2_syms)
    funnel['F3_cross_unit_pairs'] = f3_pairs
    funnel['F4_link_error_filter_survives'] = f4_pairs
    funnel['F5_kconfig_separable_pairs'] = f5_pairs
    funnel['F6_sole_writer_pairs'] = f6_pairs
    funnel['F7_risky_section_pairs'] = f7_pairs
    funnel['F8_unguarded_reader_pairs'] = f8_pairs
    funnel['F9_cozart_exposed_pairs'] = f9_pairs
    funnel['candidates_total'] = len(candidates)

    candidates.sort(key=lambda c: -c['score'])

    cand_path = os.path.join(args.out, 'candidates.tsv')
    fields = ['score', 'sym', 'def_obj', 'def_section', 'def_cond',
              'writer_obj', 'writer_func', 'writer_is_boot', 'writer_src', 'writer_cond',
              'reader_obj', 'reader_func', 'reader_src', 'reader_cond',
              'sole_writer', 'risky_section', 'unguarded', 'cozart_exposed']
    with open(cand_path, 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=fields, delimiter='\t', lineterminator='\n')
        w.writeheader()
        for c in candidates:
            w.writerow({k: c[k] for k in fields})

    funnel_path = os.path.join(args.out, 'funnel.txt')
    with open(funnel_path, 'w') as f:
        for k, v in funnel.items():
            line = f'{k}\t{v}'
            print(line)
            f.write(line + '\n')

    print(f'\ncandidates written to {cand_path}', file=sys.stderr)


if __name__ == '__main__':
    main()
