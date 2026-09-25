#!/usr/bin/env python3
"""
pernet_search.py -- search for Kconfig-invisible pernet-ID dependencies.

Pattern:
    /* subsystem A */
    static struct pernet_operations foo_net_ops = {
        .init = foo_net_init, .id = &foo_net_id, .size = sizeof(struct foo_net),
    };
    register_pernet_subsys(&foo_net_ops);   // WRITES foo_net_id (indirectly,
                                             // inside kernel/net/core/net_namespace.c's
                                             // registration machinery -- never a
                                             // visible STORE at the call site)

    /* subsystem B, possibly a different file/module */
    struct foo_net *fn = net_generic(net, foo_net_id);   // READS foo_net_id

This is structurally the same shape as the kmem_cache/global-pointer
pattern from the original research question, but the write is INDIRECT
(through a function pointer argument, not a visible STORE instruction),
so it is invisible to netdep.py's ELF relocation classifier entirely --
this is why it needed a dedicated text-search pass rather than reuse of
xref.tsv directly. Condition lookup and separability checking reuse the
already-validated guardmap.py (SAT) and the same Makefile-condition
approach as match.py.

Usage:
    pernet_search.py --root /work/linux-cosmic --net-dir net \
                      --filename-db /work/out/filename.db \
                      --globals /work/out/globals.tsv \
                      --composed /work/composed_nginx.txt \
                      --out /work/out/pernet_candidates.tsv
"""
import argparse
import csv
import os
import re
import sys
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from guardmap import compute_guard_map, separable, is_satisfiable, config_symbols  # noqa: E402
from makefile_cond import resolve_condition  # noqa: E402

REGISTER_CALL_RE = re.compile(r'\bregister_pernet_(subsys|device|operations)\s*\(\s*&(\w+)\s*\)')
# net/sched/act_*.c's TC action framework wraps pernet registration inside
# tcf_register_action(&action_ops, &pernet_ops) -- found only after
# vlan_net_id/act_vlan.c looked like a cross-file false positive that
# turned out to be this wrapper hiding act_vlan.c's own, entirely
# self-contained registration from the direct-call-only scan.
TCF_REGISTER_RE = re.compile(r'\btcf_register_action\s*\(\s*&\w+\s*,\s*&(\w+)\s*\)')
ID_FIELD_RE = re.compile(r'\.id\s*=\s*&(\w+)')
NET_GENERIC_RE = re.compile(r'\bnet_generic\s*\([^,]+,\s*(\w+)\s*\)')
FUNC_DEF_RE = re.compile(r'^\s*(?:static\s+)?(?:inline\s+)?[\w\*\s]+?\b(\w+)\s*\([^;{]*\)\s*\{?\s*$')


def find_files(root, net_dir):
    base = os.path.join(root, net_dir)
    for dirpath, _, filenames in os.walk(base):
        for fn in filenames:
            if fn.endswith('.c') or fn.endswith('.h'):
                yield os.path.relpath(os.path.join(dirpath, fn), root)


def enclosing_function(lines, line_idx):
    """Best-effort: scan backwards from line_idx for the nearest function
    definition header. Heuristic, used only for reporting."""
    for i in range(line_idx, max(line_idx - 200, -1), -1):
        m = FUNC_DEF_RE.match(lines[i])
        if m and not lines[i].strip().endswith(';'):
            return m.group(1)
    return '?'


def find_struct_id(lines, struct_name):
    """Find `.id = &SYM` within the named struct's initializer block."""
    pat_decl = re.compile(r'\b' + re.escape(struct_name) + r'\s*(?:\[[^\]]*\])?\s*=\s*\{')
    start = None
    for i, line in enumerate(lines):
        if pat_decl.search(line):
            start = i
            break
    if start is None:
        return None
    depth = 0
    for i in range(start, min(start + 60, len(lines))):
        depth += lines[i].count('{') - lines[i].count('}')
        m = ID_FIELD_RE.search(lines[i])
        if m:
            return m.group(1)
        if depth <= 0 and i > start:
            break
    return None


def load_filename_db(path):
    cond = {}
    with open(path) as f:
        for line in f:
            line = line.rstrip('\n')
            if not line:
                continue
            parts = line.split(' ')
            if len(parts) == 2:
                cond[parts[0]] = parts[1]
    return cond


def load_globals(path):
    defs = defaultdict(list)
    with open(path, newline='') as f:
        for row in csv.DictReader(f, delimiter='\t'):
            defs[row['sym']].append(row)
    return defs


def load_composed(path):
    with open(path) as f:
        return set(l.strip() for l in f if l.strip())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--root', required=True)
    ap.add_argument('--net-dir', default='net')
    ap.add_argument('--filename-db', required=True)
    ap.add_argument('--globals', required=True)
    ap.add_argument('--composed', required=True)
    ap.add_argument('--out', required=True)
    args = ap.parse_args()

    makefile_cond = load_filename_db(args.filename_db)
    defs = load_globals(args.globals)
    composed = load_composed(args.composed)

    # Pass 1: find every (id_symbol, registering_file, registering_line, func)
    writers = []   # (id_sym, file, line, func)
    id_symbols = set()
    file_cache = {}

    def get_lines(rel):
        if rel not in file_cache:
            full = os.path.join(args.root, rel)
            try:
                with open(full, 'r', errors='surrogateescape') as f:
                    file_cache[rel] = f.read().split('\n')
            except FileNotFoundError:
                file_cache[rel] = []
        return file_cache[rel]

    files = list(find_files(args.root, args.net_dir))
    print(f'scanning {len(files)} files under {args.net_dir}/ ...', file=sys.stderr)

    for rel in files:
        lines = get_lines(rel)
        for i, line in enumerate(lines):
            m = REGISTER_CALL_RE.search(line)
            struct_name = m.group(2) if m else None
            if not m:
                m2 = TCF_REGISTER_RE.search(line)
                struct_name = m2.group(1) if m2 else None
            if not struct_name:
                continue
            id_sym = find_struct_id(lines, struct_name)
            if not id_sym:
                continue
            func = enclosing_function(lines, i)
            writers.append((id_sym, rel, i + 1, func))
            id_symbols.add(id_sym)

    print(f'found {len(writers)} pernet registration sites, '
          f'{len(id_symbols)} distinct id symbols', file=sys.stderr)

    # Pass 2: find every net_generic(..., id_sym) read site for each id symbol found
    readers = defaultdict(list)  # id_sym -> [(file, line, func)]
    for rel in files:
        lines = get_lines(rel)
        for i, line in enumerate(lines):
            m = NET_GENERIC_RE.search(line)
            if not m:
                continue
            sym = m.group(1)
            if sym in id_symbols:
                func = enclosing_function(lines, i)
                readers[sym].append((rel, i + 1, func))

    # Build guard maps only for files actually involved
    involved_files = set(w[1] for w in writers)
    for sym, rs in readers.items():
        involved_files.update(r[0] for r in rs)

    guard_cache = {}
    for rel in involved_files:
        guard_cache[rel] = compute_guard_map('\n'.join(get_lines(rel)))

    def guard_cond(rel, line):
        gm = guard_cache.get(rel)
        if not gm or line - 1 >= len(gm):
            return 'True'
        return gm[line - 1]

    mk_cache = {}

    def full_cond(rel, line):
        """Conjunction of the file's TRANSITIVE Makefile condition (every
        level from its own directory up to net/, via makefile_cond.py --
        NOT the single-level filename.db, which silently drops outer
        composite-module gates) and its intra-file preprocessor guard."""
        if rel not in mk_cache:
            mk_cache[rel] = resolve_condition(args.root, rel, stop_dir=args.net_dir)
        mc_list = mk_cache[rel]
        gc = guard_cond(rel, line)
        parts = list(mc_list)
        if gc != 'True':
            parts.append(gc)
        return ' and '.join(f'({p})' for p in parts) if parts else 'True'

    # Guard against name collisions: many subsystems independently name
    # their pernet-id variable "X_net_id" by convention. If a "reader"
    # file ALSO has its own registration site for the same literal name,
    # that is the collision signature -- two unrelated variables sharing
    # a name, not a real cross-file reference (confirmed concretely for
    # both vlan_net_id and nat_net_id: the "reader" file declares its own
    # independent `static unsigned int X_net_id;` and never includes the
    # real one's header). A GLOBAL-bound symbol is a necessary but NOT
    # sufficient condition for a genuine cross-file reference.
    writer_files_by_sym = defaultdict(set)
    for id_sym, wfile, _, _ in writers:
        writer_files_by_sym[id_sym].add(wfile)

    rows = []
    n_collision_skipped = 0
    for id_sym, wfile, wline, wfunc in writers:
        if id_sym not in readers:
            continue
        def_entries = defs.get(id_sym, [])
        # Scope to THIS writer's own file, not "does a GLOBAL entry with
        # this name exist anywhere" -- that check let act_vlan.c's write
        # to its own LOCAL vlan_net_id wrongly match against net/8021q/
        # vlan.c's unrelated GLOBAL vlan_net_id, since both entries share
        # the bare name. If wfile's own object defines id_sym, THAT
        # definition's binding is what matters, not some other file's.
        wfile_obj = re.sub(r'\.c$', '.o', wfile)
        own_entries = [d for d in def_entries if d['obj'] == wfile_obj]
        if own_entries:
            is_global = any(d['bind'] == 'GLOBAL' for d in own_entries)
        else:
            # wfile doesn't define id_sym itself -- it must be using an
            # extern reference to some other file's global. Proceed, but
            # only if a genuine GLOBAL definition exists somewhere.
            is_global = any(d['bind'] == 'GLOBAL' for d in def_entries)
        writer_cond = full_cond(wfile, wline)
        for rfile, rline, rfunc in readers[id_sym]:
            if wfile == rfile and wline == rline:
                continue
            if rfile in writer_files_by_sym[id_sym]:
                n_collision_skipped += 1
                continue  # reader file independently registers the same name -- collision
            if not is_global:
                n_collision_skipped += 1
                continue  # LOCAL binding cannot legitimately be referenced from another file
            rfile_obj = re.sub(r'\.c$', '.o', rfile)
            r_own_entries = [d for d in def_entries if d['obj'] == rfile_obj]
            if r_own_entries and not any(d['bind'] == 'GLOBAL' for d in r_own_entries):
                n_collision_skipped += 1
                continue  # reader file has its own LOCAL shadow of this name
            reader_cond = full_cond(rfile, rline)
            if writer_cond == reader_cond:
                continue

            witness = separable(reader_cond, writer_cond)
            if witness is None:
                continue

            real_witness = {k: v for k, v in witness.items() if config_symbols(k)}

            # exposure check against Cozart's actual composed config
            unk_free = any(not config_symbols(x) and x not in ('True', 'False')
                            for x in [])  # placeholder, real check below
            def real_eval(expr):
                cfgs = re.findall(r'\bCONFIG_\w+\b', expr)
                unk = re.findall(r'\bUNK_\w+\b', expr)
                if unk:
                    return None
                env = {c: (c in composed) for c in cfgs}
                try:
                    return bool(eval(expr, {'__builtins__': {}}, env))
                except Exception:
                    return None
            rv = real_eval(reader_cond)
            wv = real_eval(writer_cond)
            if rv is None or wv is None:
                exposure = 'UNDETERMINED'
            elif rv and not wv:
                exposure = 'EXPOSED'
            else:
                exposure = 'NOT EXPOSED'

            rows.append({
                'id_sym': id_sym,
                'def_obj': def_entries[0]['obj'] if def_entries else '?',
                'def_section': def_entries[0]['section'] if def_entries else '?',
                'def_bind': def_entries[0]['bind'] if def_entries else '?',
                'writer_loc': f'{wfile}:{wline}', 'writer_func': wfunc,
                'writer_cond': writer_cond,
                'reader_loc': f'{rfile}:{rline}', 'reader_func': rfunc,
                'reader_cond': reader_cond,
                'cross_file': wfile != rfile,
                'witness': ','.join(f'{k}={v}' for k, v in sorted(real_witness.items())) or '(only-unknown-macros)',
                'cozart_exposure': exposure,
            })

    fields = ['id_sym', 'def_obj', 'def_section', 'def_bind', 'writer_loc', 'writer_func',
              'writer_cond', 'reader_loc', 'reader_func', 'reader_cond', 'cross_file',
              'witness', 'cozart_exposure']
    with open(args.out, 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=fields, delimiter='\t', lineterminator='\n')
        w.writeheader()
        for r in rows:
            w.writerow(r)

    n_exposed = sum(1 for r in rows if r['cozart_exposure'] == 'EXPOSED')
    n_cross = sum(1 for r in rows if r['cross_file'])
    print(f'skipped as name collisions / non-GLOBAL cross-file refs: {n_collision_skipped}')
    print(f'\ncandidate pairs: {len(rows)} ({n_cross} cross-file)')
    print(f'EXPOSED in Cozart real nginx config: {n_exposed}')
    print(f'written to {args.out}', file=sys.stderr)


if __name__ == '__main__':
    main()
