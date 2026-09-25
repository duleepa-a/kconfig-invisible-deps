#!/usr/bin/env python3
"""
guardmap.py -- nesting-aware preprocessor presence-condition extractor.

For every line of a given set of source files, computes the boolean
presence condition (a Python-evaluable expression string over CONFIG_*
names) required for that line to be compiled in.

This replaces Cozart's own directive-attribution tools for P1b analysis:
[query-directive.go] consults only the single nearest-PRECEDING directive
with no nesting stack (so a line after a nested #endif gets no condition
at all), and [line2directive-config.sh] filters on `grep 'ifdef'` (so
`#if defined(CONFIG_X)`, `IS_ENABLED(CONFIG_X)` and `#elif` are never
matched). Both are unusable for the P1b question: "does the file's own
#ifdef nesting allow a state where this write is excluded while this read
is included?"

Non-CONFIG_* macros/expressions are treated as opaque `True` (over-
approximate -- never claim a region is excluded when we don't actually
know).

Usage:
    guardmap.py --root /work/linux-cosmic --files-list files.txt \
                --out guards.tsv
    guardmap.py --self-test        # run the validation gate, no I/O
"""
import argparse
import os
import re
import sys

DIRECTIVE_RE = re.compile(r'^\s*#\s*(ifdef|ifndef|if|elif|else|endif)\b(.*)$')
IDENT_RE = re.compile(r'\b[A-Za-z_]\w*\b')
CONFIG_RE = re.compile(r'^CONFIG_\w+$')
UNK_RE = re.compile(r'^UNK_\w+$')


def _unk_name(name):
    """A deterministic placeholder for a non-CONFIG_* macro/identifier,
    e.g. a header include-guard token or an arch/version symbol. Treating
    it as a FREE boolean variable (rather than collapsing it to a fixed
    True) is the only sound way to over-approximate: a fixed 'True'
    constant silently inverts under negation (`#ifndef SOME_HEADER_GUARD`
    -- the very first line of nearly every header -- would evaluate to
    `not True` = False, wrongly marking the entire rest of the file as
    never-compiled). A free variable lets `not UNK_X` be satisfied by
    UNK_X=False, which is the correct "we don't know, so don't rule
    either state out" behaviour.
    """
    return 'UNK_' + re.sub(r'\W', '_', name.strip())


def _cfg_or_unk(name):
    name = name.strip()
    return name if CONFIG_RE.match(name) else _unk_name(name)


def normalize_condition(text, kind):
    """kind in ('ifdef','ifndef','if','elif'). Returns a Python-evaluable
    boolean expression string over CONFIG_* and UNK_* identifiers (plus
    True/False/and/or/not)."""
    text = text.strip()

    if kind == 'ifdef':
        return _cfg_or_unk(text)
    if kind == 'ifndef':
        return f'(not {_cfg_or_unk(text)})'

    # kind in ('if', 'elif'): a full preprocessor expression.
    expr = re.sub(r'/\*.*?\*/', '', text)  # strip block comments

    # defined(X) / defined X
    expr = re.sub(r'defined\s*\(\s*(\w+)\s*\)', lambda m: _cfg_or_unk(m.group(1)), expr)
    expr = re.sub(r'defined\s+(\w+)', lambda m: _cfg_or_unk(m.group(1)), expr)

    # IS_ENABLED(X) / IS_BUILTIN(X) / IS_MODULE(X) -- collapsed to "X is
    # present in some form" (we don't model tristate y/m distinction).
    expr = re.sub(r'IS_(?:ENABLED|BUILTIN|MODULE)\s*\(\s*(\w+)\s*\)',
                  lambda m: _cfg_or_unk(m.group(1)), expr)

    # literal 0 / 1 (common for "#if 0 ... #endif" disabled blocks)
    expr = re.sub(r'^\s*0\s*$', 'False', expr)
    expr = re.sub(r'^\s*1\s*$', 'True', expr)

    # Replace every remaining identifier: keep CONFIG_* as itself, keep
    # python keywords, turn everything else into its own free UNK_*
    # variable (macro names, function-like macros already consumed above,
    # arch/version symbols, numeric-looking tokens, etc).
    def repl_ident(m):
        ident = m.group(0)
        if ident.startswith('CONFIG_') or ident.startswith('UNK_'):
            return ident  # already substituted by the defined()/IS_ENABLED() pass above
        if ident in ('True', 'False', 'and', 'or', 'not'):
            return ident
        return _unk_name(ident)
    expr = IDENT_RE.sub(repl_ident, expr)

    # C operators -> Python operators
    expr = expr.replace('&&', ' and ')
    expr = expr.replace('||', ' or ')
    expr = re.sub(r'(?<![=!<>])!(?!=)', ' not ', expr)

    # Collapse now-meaningless comparisons against True/False or UNK_*
    # placeholders (e.g. "#if LINUX_VERSION_CODE >= X" -> "UNK_.. >= UNK_..").
    # A comparison between two unknowns, or an unknown against a literal,
    # is itself unknown -- represent the whole comparison as one fresh
    # free variable rather than silently collapsing to a fixed value.
    def repl_cmp(m):
        return _unk_name(m.group(0))
    expr = re.sub(r'(?:True|False|UNK_\w+|[\d.]+)\s*(?:==|!=|>=|<=|>|<)\s*(?:True|False|UNK_\w+|[\d.]+)',
                  repl_cmp, expr)

    expr = expr.strip()
    return f'({expr})' if expr else 'True'


class Group:
    __slots__ = ('raw_arms',)

    def __init__(self, first_cond):
        self.raw_arms = [first_cond]

    def active_expr(self):
        cur = self.raw_arms[-1]
        if len(self.raw_arms) == 1:
            return cur
        prior_or = ' or '.join(f'({a})' for a in self.raw_arms[:-1])
        return f'(({cur}) and not ({prior_or}))'


def compute_guard_map(text):
    """Returns a list, one entry per line (1-indexed via list[i-1]), of the
    active presence-condition expression string for that line."""
    lines = text.split('\n')
    stack = []
    result = []
    for line in lines:
        m = DIRECTIVE_RE.match(line)
        if m:
            kind, rest = m.group(1), m.group(2)
            if kind in ('ifdef', 'ifndef', 'if'):
                cond = normalize_condition(rest, kind)
                stack.append(Group(cond))
            elif kind == 'elif':
                cond = normalize_condition(rest, 'elif')
                if stack:
                    stack[-1].raw_arms.append(cond)
            elif kind == 'else':
                if stack:
                    stack[-1].raw_arms.append('True')  # "none of the prior arms"
            elif kind == 'endif':
                if stack:
                    stack.pop()
            # directive line itself: attributed to the ENCLOSING scope
            # (i.e. computed from the stack state as of BEFORE this push /
            # AFTER this pop, which is exactly the state variable `stack`
            # holds at this point for ifdef/ifndef/if/endif; for elif/else
            # it's attributed to the now-updated arm, which is a reasonable
            # convention and not load-bearing for our line-level lookups).
            result.append(_combine(stack))
        else:
            result.append(_combine(stack))
    return result


def _combine(stack):
    if not stack:
        return 'True'
    return ' and '.join(f'({g.active_expr()})' for g in stack)


def config_symbols(expr):
    """Real, toggleable Kconfig options mentioned -- for human-readable
    reporting only. Excludes UNK_* placeholders."""
    return set(m for m in IDENT_RE.findall(expr) if m.startswith('CONFIG_'))


def free_symbols(expr):
    """Every free variable (CONFIG_* and UNK_*) -- this is what the SAT
    search must range over, since UNK_* placeholders are unconstrained
    unknowns, not fixed constants (see _unk_name)."""
    return set(m for m in IDENT_RE.findall(expr)
               if m.startswith('CONFIG_') or m.startswith('UNK_'))


def is_satisfiable(expr, assignment):
    """assignment: dict symbol -> True/False, covering every free variable
    in `expr` (caller's responsibility; a KeyError here means the search
    space was built incorrectly, not a "false" result -- so we don't
    default missing symbols silently)."""
    env = dict(assignment)
    try:
        return bool(eval(expr, {'__builtins__': {}}, env))
    except Exception as e:
        print(f'warning: failed to eval {expr!r}: {e}', file=sys.stderr)
        return None


def separable(reader_expr, writer_expr):
    """Brute-force SAT of reader_expr AND NOT writer_expr over the union of
    ALL free variables (CONFIG_* and UNK_*) mentioned in either side.
    UNK_* variables must be included in the search, not fixed at a
    constant, or negation of an unknown macro (e.g. a header include-
    guard's #ifndef) would be silently mis-evaluated. Returns a witness
    dict (may include UNK_* entries; filter with config_symbols() for
    reporting) or None if unsatisfiable / too large to search."""
    syms = sorted(free_symbols(reader_expr) | free_symbols(writer_expr))
    n = len(syms)
    if n > 22:
        return None  # refuse to blow up; not expected in practice
    for bits in range(1 << n):
        assignment = {s: bool((bits >> i) & 1) for i, s in enumerate(syms)}
        r = is_satisfiable(reader_expr, assignment)
        w = is_satisfiable(writer_expr, assignment)
        if r is None or w is None:
            return None
        if r and not w:
            return assignment
    return None


# ---------------------------------------------------------------------
# Validation gate (Step 6 discipline): must pass before trusting real runs.
# ---------------------------------------------------------------------
SELF_TEST_SOURCE = '''\
int global_x;

#ifdef CONFIG_A
void a_init(void) {
    global_x = 1;             /* line 6: writer, under CONFIG_A only */
#ifdef CONFIG_B
    do_something();           /* line 8: writer AND CONFIG_B (nested) */
#endif
}
#endif

#if defined(CONFIG_C) || IS_ENABLED(CONFIG_D)
void reader(void) {
    use(global_x);             /* line 15: reader, under C||D */
}
#elif defined(CONFIG_E)
void reader2(void) {
    use(global_x);              /* line 19: reader, under (not(C||D)) and E */
}
#else
void reader3(void) {
    use(global_x);              /* line 23: reader, under not(C||D) and not E */
}
#endif
'''


def _find_line(text, needle):
    """1-indexed line number of the first line containing `needle`. Finding
    by content rather than hardcoded line numbers avoids the test itself
    being a source of off-by-one bugs."""
    for i, line in enumerate(text.split('\n'), start=1):
        if needle in line:
            return i
    raise AssertionError(f'needle not found: {needle!r}')


def self_test():
    lines = compute_guard_map(SELF_TEST_SOURCE)
    ok = True

    e6 = lines[_find_line(SELF_TEST_SOURCE, 'global_x = 1;') - 1]
    e8 = lines[_find_line(SELF_TEST_SOURCE, 'do_something();') - 1]
    e15 = lines[_find_line(SELF_TEST_SOURCE, 'use(global_x);             /* line 15') - 1]
    e19 = lines[_find_line(SELF_TEST_SOURCE, 'use(global_x);              /* line 19') - 1]
    e23 = lines[_find_line(SELF_TEST_SOURCE, 'use(global_x);              /* line 23') - 1]

    def sat_all_true(expr, syms):
        return is_satisfiable(expr, {s: True for s in syms})

    def sat_all_false(expr, syms):
        return is_satisfiable(expr, {s: False for s in syms})

    print('line 6  (writer, CONFIG_A only):        ', e6)
    print('line 8  (writer, CONFIG_A&&CONFIG_B):   ', e8)
    print('line 15 (reader, C||D):                 ', e15)
    print('line 19 (reader, elif E, not(C||D)):    ', e19)
    print('line 23 (reader, else, not(C||D)&&notE):', e23)

    # line 6: true iff A=True (B irrelevant)
    if is_satisfiable(e6, {'CONFIG_A': True, 'CONFIG_B': False}) is not True:
        print('FAIL: line 6 should be satisfiable with A=T,B=F'); ok = False
    if is_satisfiable(e6, {'CONFIG_A': False, 'CONFIG_B': True}) is not False:
        print('FAIL: line 6 should be false with A=F,B=T'); ok = False

    # line 8: true iff A=True and B=True
    if is_satisfiable(e8, {'CONFIG_A': True, 'CONFIG_B': True}) is not True:
        print('FAIL: line 8 should be true with A=T,B=T'); ok = False
    if is_satisfiable(e8, {'CONFIG_A': True, 'CONFIG_B': False}) is not False:
        print('FAIL: line 8 should be false with A=T,B=F (nesting not respected)'); ok = False

    # line 15: true iff C or D
    if is_satisfiable(e15, {'CONFIG_C': True, 'CONFIG_D': False}) is not True:
        print('FAIL: line 15 should be true with C=T'); ok = False
    if is_satisfiable(e15, {'CONFIG_C': False, 'CONFIG_D': False}) is not False:
        print('FAIL: line 15 should be false with C=F,D=F'); ok = False

    # line 19: true iff not(C or D) and E
    if is_satisfiable(e19, {'CONFIG_C': False, 'CONFIG_D': False, 'CONFIG_E': True}) is not True:
        print('FAIL: line 19 should be true with C=F,D=F,E=T'); ok = False
    if is_satisfiable(e19, {'CONFIG_C': True, 'CONFIG_D': False, 'CONFIG_E': True}) is not False:
        print('FAIL: line 19 should be false when C=T (elif not reached)'); ok = False

    # line 23: true iff not(C or D) and not E
    if is_satisfiable(e23, {'CONFIG_C': False, 'CONFIG_D': False, 'CONFIG_E': False}) is not True:
        print('FAIL: line 23 should be true with C=F,D=F,E=F'); ok = False
    if is_satisfiable(e23, {'CONFIG_C': False, 'CONFIG_D': False, 'CONFIG_E': True}) is not False:
        print('FAIL: line 23 should be false when E=T (elif reached instead)'); ok = False

    # separability check: line 8 (writer) vs line 15 (reader) -- writer
    # requires A&&B, reader requires C||D -- these are independent, so
    # reader=True, writer=False should be satisfiable (e.g. C=T,A=F).
    witness = separable(e15, e8)
    if witness is None:
        print('FAIL: line15-vs-line8 should be separable'); ok = False
    else:
        print('separable(line15, line8) witness:', witness)

    # Regression test: header include-guard idiom. An unknown macro under
    # #ifndef must NOT collapse the guarded body to permanently-excluded.
    guard_src = (
        '#ifndef MY_HEADER_H\n'
        '#define MY_HEADER_H\n'
        'int body_line;\n'
        '#endif\n'
    )
    guard_lines = compute_guard_map(guard_src)
    body_expr = guard_lines[_find_line(guard_src, 'int body_line;') - 1]
    print('header-guard body condition:', body_expr)
    if is_satisfiable(body_expr, {s: False for s in free_symbols(body_expr)}) is not True:
        print('FAIL: header-guard body should be reachable (first inclusion)'); ok = False

    if ok:
        print('\\nSELF-TEST PASSED')
    else:
        print('\\nSELF-TEST FAILED')
    return ok


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--self-test', action='store_true')
    ap.add_argument('--root')
    ap.add_argument('--files-list', help='file listing root-relative .c paths, one per line')
    ap.add_argument('--out')
    args = ap.parse_args()

    if args.self_test:
        ok = self_test()
        sys.exit(0 if ok else 1)

    if not (args.root and args.files_list and args.out):
        ap.error('--root, --files-list and --out are required unless --self-test')

    with open(args.files_list) as f:
        rel_paths = [l.strip() for l in f if l.strip()]

    with open(args.out, 'w') as out:
        out.write('file\tline\tcondition\n')
        n_files = 0
        n_lines = 0
        for rel in rel_paths:
            full = os.path.join(args.root, rel)
            if not os.path.isfile(full):
                print(f'warning: missing {full}', file=sys.stderr)
                continue
            with open(full, 'r', errors='surrogateescape') as f:
                text = f.read()
            conds = compute_guard_map(text)
            for i, cond in enumerate(conds, start=1):
                if cond == 'True':
                    continue  # unconditional lines dominate; skip to keep the table small
                out.write(f'{rel}\t{i}\t{cond}\n')
                n_lines += 1
            n_files += 1
        print(f'{n_files} files processed, {n_lines} conditional lines recorded', file=sys.stderr)


if __name__ == '__main__':
    main()
