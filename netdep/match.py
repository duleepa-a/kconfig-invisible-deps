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

Reading the funnel (see LIMITATIONS.md, "match.py"):
  * F0-F5 are the structural filters; F3 is only an initial prefilter and F4
    a *possible* link-survival check (no link is actually performed). F5
    compares Makefile condition TEXT; the solver-backed check is
    kconfig_sep.py, and `ifdef_separable` adds intra-file #ifdef reasoning.
  * F6-F9 are PRIORITISATION FEATURES that feed `score`. They overlap and
    several are weak heuristics; none of them validates a candidate.
    score_validation.py measures how well they rank audited cases.

Symbol identity: by default symbols are matched by (linkage, name, defining
object), not by bare name -- a `static` variable is only ever the same
symbol inside its own object file, and ELF aliases of one storage object
are merged. `--legacy` restores the original name-only behaviour (and the
original F6/F7/F8 definitions) so earlier numbers can be reproduced.

Usage:
    match.py --out /work/out --filename-db /work/out/filename.db \
              --composed-config /work/composed_nginx.txt
"""
import argparse
import csv
import os
import re
import sys
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from makefile_cond import resolve_condition  # noqa: E402
import netdep  # noqa: E402  (instruction helpers only; stdlib)

_transitive_cache = {}

CONFIG_RE = re.compile(r'CONFIG_\w+')
TRI = {'n': 0, 'm': 1, 'y': 2}
TRI_NAME = 'nmy'
GUARD_RANK = {'none': 0, 'function': 1, 'site': 2}


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
    return None


def obj_to_srcfile_guess(obj_rel):
    """net/foo/bar.o -> net/foo/bar.c, used when DWARF src_file is empty
    (DATAREF rows) and we fall back to the object's own file identity."""
    if obj_rel.endswith('.o'):
        return obj_rel[:-2] + '.c'
    return obj_rel


# --------------------------------------------------------------------
# Configuration state (item 38/39): tristate values, not name membership
# --------------------------------------------------------------------

def load_dotconfig(path):
    """Resolved .config -> {CONFIG_X: 'y'|'m'|'n'}. Only tristate/bool
    values are kept; absent symbols are treated as n by the caller."""
    vals = {}
    with open(path, errors='replace') as f:
        for line in f:
            m = re.match(r'^(CONFIG_\w+)=([ym])\s*$', line)
            if m:
                vals[m.group(1)] = m.group(2)
                continue
            m = re.match(r'^# (CONFIG_\w+) is not set', line)
            if m:
                vals[m.group(1)] = 'n'
    return vals


class ConfigView(object):
    """Maps a Makefile condition ('CONFIG_A and CONFIG_B' / None) to a
    tristate. Source is a resolved .config when given (y/m/n are real),
    otherwise Cozart's composed option list, where membership means y."""

    def __init__(self, composed, dotconfig=None):
        self.composed = composed
        self.dotconfig = dotconfig

    def lookup(self, name):
        if self.dotconfig is not None:
            return self.dotconfig.get(name, 'n')
        return 'y' if name in self.composed else 'n'

    def state(self, cond):
        """'y' / 'm' / 'n' (a conjunction takes its weakest member), '?'
        when the condition names no CONFIG option."""
        if cond is None:
            return 'y'
        names = CONFIG_RE.findall(cond)
        if not names:
            return '?'
        return TRI_NAME[min(TRI[self.lookup(n)] for n in names)]


# --------------------------------------------------------------------
# Compile-time (#ifdef) conditions at source lines (items 30/37)
# --------------------------------------------------------------------

class IfdefIndex(object):
    """Presence condition of a source line, via guardmap.py. DWARF paths
    are mapped back onto --root; files that cannot be read give None
    (unknown) rather than a guess."""

    def __init__(self, root, root_prefix):
        self.root = root
        self.root_prefix = root_prefix
        self._cache = {}
        import guardmap
        self.guardmap = guardmap

    def _lines(self, rel):
        if rel not in self._cache:
            full = os.path.join(self.root, rel)
            try:
                with open(full, 'r', errors='surrogateescape') as f:
                    self._cache[rel] = self.guardmap.compute_guard_map(f.read())
            except (IOError, OSError):
                self._cache[rel] = None
        return self._cache[rel]

    def cond_at(self, src_file, src_line):
        if not src_file or not src_line:
            return None
        rel = src_file
        if self.root_prefix and rel.startswith(self.root_prefix):
            rel = rel[len(self.root_prefix):]
        rel = rel.lstrip('/')
        lines = self._lines(rel)
        try:
            n = int(src_line)
        except ValueError:
            return None
        if not lines or n < 1 or n > len(lines):
            return None
        return lines[n - 1]

    def separable(self, reader_make, reader_ifdef, writer_make, writer_ifdef):
        """'yes' / 'no' / 'unknown': is there a configuration where the
        reader's line is compiled in and the writer's line is not,
        combining Makefile gates with #ifdef presence conditions."""
        if reader_ifdef is None or writer_ifdef is None:
            return 'unknown'

        def expr(make, ifdef):
            return '(%s) and (%s)' % (make or 'True', ifdef or 'True')
        r, w = expr(reader_make, reader_ifdef), expr(writer_make, writer_ifdef)
        gm = self.guardmap
        if len(gm.free_symbols(r) | gm.free_symbols(w)) > 22:
            return 'unknown'
        return 'yes' if gm.separable(r, w) is not None else 'no'


# --------------------------------------------------------------------
# Symbol identity (items 19, 20, 21, 42)
# --------------------------------------------------------------------

def build_aliases(globals_rows):
    """ELF aliases = several symbols naming one storage object (same
    object file, section and value, non-zero size). Returns
    (local_alias, global_alias): maps to the canonical symbol key. The
    canonical name prefers GLOBAL, then WEAK, then LOCAL, then name order.
    Empty maps when globals.tsv has no `value` column (older extraction)."""
    groups = defaultdict(list)
    for g in globals_rows:
        if not g.get('value'):
            return {}, {}
        if int(g['size']) > 0:
            groups[(g['obj'], g['section'], g['value'])].append(g)
    local_alias, global_alias = {}, {}
    rank = {'GLOBAL': 0, 'WEAK': 1}
    for members in groups.values():
        if len(members) < 2:
            continue
        members.sort(key=lambda g: (rank.get(g['bind'], 2), g['sym']))
        canon = members[0]
        if canon['bind'] in ('GLOBAL', 'WEAK'):
            ckey = ('G', canon['sym'])
        else:
            ckey = ('L', canon['obj'], canon['sym'])
        for m in members[1:]:
            if m['bind'] == 'LOCAL':
                local_alias[(m['obj'], m['sym'])] = ckey
            else:
                global_alias[m['sym']] = ckey
    return local_alias, global_alias


def is_readonly_section(g, legacy):
    """Section policy. Legacy: the single name '.rodata'. Otherwise ELF
    section flags decide (a section without the W flag is immutable at run
    time), falling back to a '.rodata*' name test only when flags are
    unknown. `.data..ro_after_init` is writable and stays in scope: it is
    written at boot and then frozen, which is exactly the interesting case."""
    if legacy:
        return g['section'] == '.rodata'
    flags = g.get('sec_flags', '')
    if g['section'] in ('COMMON', 'ABS'):
        return False
    if flags:
        return 'W' not in flags
    return g['section'].startswith('.rodata')


def writer_value_kind(r, addr_accesses):
    """What a direct store writes, from the instruction text: 'zero' (clears
    or resets the variable), 'imm', 'reg', 'rmw'. A relocated immediate
    prints as $0x0 in objdump, so an immediate on an instruction that also
    carries an ADDR relocation is an address, not zero."""
    if r['access'] in ('RMW', 'IND_RMW'):
        return 'rmw'
    if r['access'] not in ('STORE', 'IND_STORE'):
        return ''
    parts = (r.get('insn', '').split(None, 1) + ['', ''])[:2]
    mn, ops_s, _ = netdep.strip_prefixes(parts[0], parts[1])
    ops = netdep.split_operands(ops_s)
    if len(ops) >= 2 and ops[0].startswith('$'):
        has_addr = 'ADDR' in addr_accesses.get((r['obj'], r['func'], r.get('addr', '')), ())
        if r.get('addr') and not has_addr and netdep.parse_int(ops[0]) == 0:
            return 'zero'
        return 'imm'
    if ops and ops[0].startswith('%'):
        return 'reg'
    return ''


def site_guard(r, legacy):
    """Guard evidence carried by one read site itself."""
    if legacy:
        return 'cmp_mem' if r['access'] == 'LOAD_GUARD' else ''
    return r.get('guard') or ('cmp_mem' if r['access'] == 'LOAD_GUARD' else '')


def main(argv=None):
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
    ap.add_argument('--root', default='/work/linux-cosmic', help='kernel source root, for --use-transitive and --ifdef-guards')
    ap.add_argument('--writer-mode', choices=['boot', 'lazy', 'any'], default='boot',
                     help='boot (default): STORE/RMW from .init.text/initcall only, matching '
                          'every prior search in this project. lazy: STORE/RMW from ordinary '
                          '.text (NOT boot-time) -- first-use/on-demand initialization, the '
                          'population "boot" structurally excludes. any: both combined.')
    ap.add_argument('--include-indirect', action='store_true',
                     help='also use register-tracked accesses from netdep.py: IND_LOAD '
                          'counts as a read, IND_STORE/IND_RMW as a write. Off by default '
                          'so earlier results reproduce.')
    ap.add_argument('--field-sensitive', action='store_true',
                     help='pair a writer and reader only when their struct-field paths '
                          '(xref `field` column, needs netdep.py --dwarf-fields) are equal '
                          'or nested; an empty/unknown field is compatible with anything.')
    ap.add_argument('--legacy', action='store_true',
                     help='original behaviour: match symbols by bare name, exclude only the '
                          'section named .rodata, count ADDR sites as writers in F6, treat any '
                          'LOAD_GUARD in the function as a guard, one row per access-site pair. '
                          'Use to reproduce the numbers in README section 9.')
    ap.add_argument('--dotconfig', default=None,
                     help='resolved .config: F9 and the *_cfg columns use real y/m/n values. '
                          'Without it, membership in --composed-config means y.')
    ap.add_argument('--ifdef-guards', action='store_true',
                     help='read the writer/reader source lines under --root and add '
                          'writer_ifdef/reader_ifdef/ifdef_separable (guardmap.py presence '
                          'conditions combined with the Makefile gates).')
    args = ap.parse_args(argv)
    legacy = args.legacy

    globals_rows = load_tsv(os.path.join(args.out, 'globals.tsv'))
    xref_rows = load_tsv(os.path.join(args.out, 'xref.tsv'))
    filename_db = load_filename_db(args.filename_db)
    with open(args.composed_config) as f:
        composed = set(l.strip() for l in f if l.strip())
    cfg = ConfigView(composed, load_dotconfig(args.dotconfig) if args.dotconfig else None)
    ifdefs = IfdefIndex(args.root, args.root_prefix) if args.ifdef_guards else None

    have_bind = bool(xref_rows) and 'sym_bind' in xref_rows[0]
    binding = (not legacy) and have_bind
    if not legacy and not have_bind:
        print('warning: xref.tsv has no sym_bind column (extracted by an older netdep.py); '
              'falling back to name-only symbol matching', file=sys.stderr)

    local_alias, global_alias = build_aliases(globals_rows) if binding else ({}, {})

    def canon(sym, obj, bind):
        if not binding:
            return ('G', sym)
        if bind == 'LOCAL':
            return local_alias.get((obj, sym), ('L', obj, sym))
        return global_alias.get(sym, ('G', sym))

    funnel = {}

    # F0: OBJECT symbol definitions that can be a write target. Population
    # is reported by linkage; read-only sections are removed by ELF flags.
    defs = defaultdict(list)  # key -> [ {obj, section, size, bind} ]
    by_bind = defaultdict(int)
    excluded_ro = 0
    for g in globals_rows:
        if is_readonly_section(g, legacy):
            excluded_ro += 1
            continue
        by_bind[g['bind']] += 1
        defs[canon(g['sym'], g['obj'], g['bind'])].append(g)
    funnel['F0_definitions'] = sum(len(v) for v in defs.values())
    funnel['F0_distinct_symbols'] = len(defs)
    funnel['F0_global'] = by_bind.get('GLOBAL', 0)
    funnel['F0_weak'] = by_bind.get('WEAK', 0)
    funnel['F0_local'] = by_bind.get('LOCAL', 0)
    funnel['F0_other_binding'] = sum(v for k, v in by_bind.items() if k not in ('GLOBAL', 'WEAK', 'LOCAL'))
    funnel['F0_excluded_read_only'] = excluded_ro

    # index xref by symbol identity
    by_key = defaultdict(list)
    addr_accesses = defaultdict(set)   # (obj, func, addr) -> accesses at that insn
    for r in xref_rows:
        r['_key'] = canon(r['sym'], r['obj'], r.get('sym_bind') or 'EXT')
        by_key[r['_key']].append(r)
        if r.get('addr'):
            addr_accesses[(r['obj'], r['func'], r['addr'])].add(r['access'])

    WRITE_ACCESS = ('STORE', 'RMW') + (('IND_STORE', 'IND_RMW') if args.include_indirect else ())
    READ_ACCESS = ('LOAD', 'LOAD_GUARD', 'INDIRECT_CALL_READ') + (('IND_LOAD',) if args.include_indirect else ())

    def field_tokens(path):
        return [t for t in (path or '').replace('[]', '.[]').split('.') if t]

    def fields_compatible(a, b):
        ta, tb = field_tokens(a.get('field')), field_tokens(b.get('field'))
        if not ta or not tb:
            return True   # unknown field: never exclude
        n = min(len(ta), len(tb))
        return ta[:n] == tb[:n]

    def is_boot_writer(r):
        return r['access'] in WRITE_ACCESS and (
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
        return r['access'] in WRITE_ACCESS and not (
            '.init.text' in r['func_section'] or 'initcall' in r['func_section']
        )

    if args.writer_mode == 'boot':
        is_init_writer = is_boot_writer
    elif args.writer_mode == 'lazy':
        is_init_writer = is_lazy_writer
    else:  # 'any'
        def is_init_writer(r):
            return r['access'] in WRITE_ACCESS

    def is_reader(r):
        # INDIRECT_CALL_READ: `call *global_ptr(%rip)` reads the pointer.
        return r['access'] in READ_ACCESS and r['obj'].startswith(args.reader_scope)

    def writer_evidence(r):
        return 'inferred' if r['access'].startswith('IND_') else 'direct'

    def reader_evidence(r):
        if r['access'] == 'INDIRECT_CALL_READ':
            return 'indirect_call'
        return 'inferred' if r['access'].startswith('IND_') else 'direct'

    # Functions in which some read of a key carries guard evidence (F8).
    guarded_funcs = set()
    for key, refs in by_key.items():
        for r in refs:
            if r['access'] in ('LOAD', 'LOAD_GUARD', 'IND_LOAD') and site_guard(r, legacy):
                guarded_funcs.add((key, r['obj'], r['func']))

    def guard_level(key, r):
        if not legacy and site_guard(r, legacy):
            return 'site'
        return 'function' if (key, r['obj'], r['func']) in guarded_funcs else 'none'

    candidates = []
    cand_index = {}
    f1_syms = set()
    f2_syms = set()
    f3_pairs = 0
    f4_pairs = 0
    f5_pairs = 0
    f6_pairs = 0
    f7_pairs = 0
    f8_pairs = 0
    f9_pairs = 0
    f9_module_pairs = 0

    for key, refs in by_key.items():
        if key not in defs:
            continue  # symbol referenced but never defined in our built set (external, out of scope)
        if binding and key[0] == 'L':
            continue  # file-local static: cannot be shared across objects (F0_local reports them)

        writers = [r for r in refs if is_init_writer(r)]
        readers = [r for r in refs if is_reader(r)]
        if not writers:
            continue
        f1_syms.add(key)
        if not readers:
            continue
        f2_syms.add(key)

        def_entries = defs[key]
        if binding:
            # externally visible definitions first: a LOCAL definition of
            # a canonical global is an alias inside one object, not a
            # separate surviving copy.
            rank = {'GLOBAL': 0, 'WEAK': 1}
            def_entries = sorted(def_entries, key=lambda d: (rank.get(d['bind'], 2), d['obj']))

        # F6 inputs, per symbol (not per pair)
        if legacy:
            all_writers = [r for r in refs if r['access'] in WRITE_ACCESS + ('ADDR',)]
            n_writer_funcs = len(set((r['obj'], r['func']) for r in all_writers))
            sole_writer = len(all_writers) == 1
            addr_taken = any(r['access'] == 'ADDR' for r in refs)
        else:
            # Count independent writer FUNCTIONS (several stores in one
            # function are one initialisation path), including inferred
            # indirect writers, but never address-taking: ADDR is reported
            # separately as `addr_taken` (possible mutation elsewhere).
            wfuncs = set((r['obj'], r['func']) for r in refs
                         if r['access'] in ('STORE', 'RMW', 'IND_STORE', 'IND_RMW'))
            n_writer_funcs = len(wfuncs)
            sole_writer = n_writer_funcs == 1
            addr_taken = any(r['access'] == 'ADDR' for r in refs)

        for w in writers:
            for r in readers:
                if w['obj'] == r['obj']:
                    continue  # same compilation unit -- not cross-unit
                if args.field_sensitive and not fields_compatible(w, r):
                    continue  # provably different struct fields
                f3_pairs += 1

                # F4: possible link-survival filter (NOT a link test). True
                # iff some definition of sym lives in an object OTHER than
                # the writer's object -- i.e. removing the writer's object
                # does not remove the symbol.
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

                # F6: sole writer
                if sole_writer:
                    f6_pairs += 1

                # F7: no safe static default (.bss or COMMON). Ranking
                # evidence only: zero is a valid initial value for many
                # counters and flags, and a non-zero static initialiser
                # does not make a value valid for every later use.
                dsec = surviving_defs[0]['section']
                if legacy:
                    risky_section = dsec in ('.bss', 'COMMON')
                else:
                    risky_section = dsec == 'COMMON' or dsec == '.bss' or dsec.startswith('.bss.')
                if risky_section:
                    f7_pairs += 1
                dsize = int(surviving_defs[0].get('size') or 0)
                pointer_sized = dsize == 8

                # F8: reader site has no guard evidence
                glevel = guard_level(key, r)
                unguarded = glevel == 'none'
                if unguarded:
                    f8_pairs += 1

                # F9: Cozart exposure -- writer's config absent while the
                # reader's config is present, on tristate values.
                ws, rs, ds = cfg.state(writer_cond), cfg.state(reader_cond), cfg.state(def_cond)
                exposed = (ws == 'n') and rs in ('y', 'm')
                if exposed:
                    f9_pairs += 1
                # writer built as a module that may never be loaded
                module_unloaded = (ws == 'm') and rs == 'y'
                if module_unloaded:
                    f9_module_pairs += 1

                wvalue = writer_value_kind(w, addr_accesses)

                ckey = (key, w['obj'], w['func'], r['obj'], r['func'])
                if not legacy and ckey in cand_index:
                    c = cand_index[ckey]
                    c['_wsites'].add((w['addr'] if 'addr' in w else '', w['src_line']))
                    c['_rsites'].add((r['addr'] if 'addr' in r else '', r['src_line']))
                    c['n_site_pairs'] += 1
                    # a pair is unguarded if ANY read site is; guard
                    # evidence reported is the weakest across sites.
                    if GUARD_RANK[glevel] < GUARD_RANK[c['guard_evidence']]:
                        c['guard_evidence'] = glevel
                    c['unguarded'] = c['guard_evidence'] == 'none'
                    continue

                c = {
                    'sym': key[-1],
                    'sym_scope': 'local' if key[0] == 'L' else 'global',
                    'def_obj': surviving_defs[0]['obj'],
                    'def_section': dsec,
                    'def_bind': surviving_defs[0]['bind'],
                    'def_size': dsize,
                    'pointer_sized': pointer_sized,
                    'n_defs': len(def_entries),
                    'writer_obj': w['obj'], 'writer_func': w['func'],
                    'writer_is_boot': '.init.text' in w['func_section'] or 'initcall' in w['func_section'],
                    'writer_src': f"{w['src_file']}:{w['src_line']}",
                    'writer_cond': writer_cond or 'obj-y',
                    'writer_evidence': writer_evidence(w),
                    'writer_value': wvalue,
                    'writer_field': w.get('field', ''),
                    'reader_obj': r['obj'], 'reader_func': r['func'],
                    'reader_src': f"{r['src_file']}:{r['src_line']}",
                    'reader_cond': reader_cond or 'obj-y',
                    'reader_evidence': reader_evidence(r),
                    'reader_field': r.get('field', ''),
                    'def_cond': def_cond or 'obj-y',
                    'sole_writer': sole_writer,
                    'n_writer_funcs': n_writer_funcs,
                    'addr_taken': addr_taken,
                    'risky_section': risky_section,
                    'unguarded': unguarded,
                    'guard_evidence': glevel,
                    'writer_cfg': ws, 'reader_cfg': rs, 'def_cfg': ds,
                    'cozart_exposed': exposed,
                    'exposed_if_module_unloaded': module_unloaded,
                    'n_site_pairs': 1,
                    '_wsites': set([(w.get('addr', ''), w['src_line'])]),
                    '_rsites': set([(r.get('addr', ''), r['src_line'])]),
                    '_w_boot': '.init.text' in w['func_section'],
                    '_cross_dir': os.path.dirname(w['obj']) != os.path.dirname(r['obj']),
                    'writer_ifdef': '', 'reader_ifdef': '', 'ifdef_separable': '',
                }
                if ifdefs is not None:
                    wi = ifdefs.cond_at(w['src_file'], w['src_line'])
                    ri = ifdefs.cond_at(r['src_file'], r['src_line'])
                    c['writer_ifdef'] = '' if wi is None else wi
                    c['reader_ifdef'] = '' if ri is None else ri
                    c['ifdef_separable'] = ifdefs.separable(reader_cond, ri, writer_cond, wi)
                candidates.append(c)
                cand_index[ckey] = c

    # score: ranking feature only (see module docstring)
    for c in candidates:
        c['n_writer_sites'] = len(c['_wsites'])
        c['n_reader_sites'] = len(c['_rsites'])
        if legacy:
            score = (3 * c['risky_section'] + 3 * c['unguarded'] + 2 * c['sole_writer'] +
                     2 * c['_w_boot'] + 1 * c['_cross_dir'])
        else:
            risky = (3 if c['pointer_sized'] else 1) if c['risky_section'] else 0
            score = (risky + 3 * c['unguarded'] + 2 * c['sole_writer'] +
                     2 * c['_w_boot'] + 1 * c['_cross_dir'])
            if c['writer_value'] == 'zero':
                score -= 2     # a clearing store is not an initialiser
            if c['writer_evidence'] == 'inferred':
                score -= 1
            if c['ifdef_separable'] == 'no':
                score -= 2     # not realisable once #ifdefs are considered
        c['score'] = score

    funnel['F1_symbols_with_init_writer'] = len(f1_syms)
    funnel['F2_symbols_with_init_writer_and_net_reader'] = len(f2_syms)
    funnel['F3_cross_unit_pairs'] = f3_pairs
    funnel['F4_link_error_filter_survives'] = f4_pairs
    funnel['F5_kconfig_separable_pairs'] = f5_pairs
    funnel['F6_sole_writer_pairs'] = f6_pairs
    funnel['F7_risky_section_pairs'] = f7_pairs
    funnel['F8_unguarded_reader_pairs'] = f8_pairs
    funnel['F9_cozart_exposed_pairs'] = f9_pairs
    funnel['F9_writer_module_unloaded_pairs'] = f9_module_pairs
    funnel['candidates_total'] = len(candidates)
    funnel['candidates_distinct_symbols'] = len(set((c['sym'], c['sym_scope'], c['def_obj'] if c['sym_scope'] == 'local' else '') for c in candidates))
    funnel['candidates_distinct_writer_funcs'] = len(set((c['writer_obj'], c['writer_func']) for c in candidates))
    funnel['candidates_distinct_reader_funcs'] = len(set((c['reader_obj'], c['reader_func']) for c in candidates))

    candidates.sort(key=lambda c: -c['score'])

    cand_path = os.path.join(args.out, 'candidates.tsv')
    fields = ['score', 'sym', 'def_obj', 'def_section', 'def_cond',
              'writer_obj', 'writer_func', 'writer_is_boot', 'writer_src', 'writer_cond',
              'reader_obj', 'reader_func', 'reader_src', 'reader_cond',
              'sole_writer', 'risky_section', 'unguarded', 'cozart_exposed',
              # appended: evidence and context for manual review
              'sym_scope', 'def_bind', 'def_size', 'pointer_sized', 'n_defs',
              'writer_evidence', 'writer_value', 'writer_field',
              'reader_evidence', 'reader_field', 'guard_evidence',
              'n_writer_funcs', 'addr_taken', 'n_site_pairs', 'n_writer_sites', 'n_reader_sites',
              'writer_cfg', 'reader_cfg', 'def_cfg', 'exposed_if_module_unloaded',
              'writer_ifdef', 'reader_ifdef', 'ifdef_separable']
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
    return candidates, funnel


if __name__ == '__main__':
    main()
