#!/usr/bin/env python3
"""
Regression tests for match.py on a tiny synthetic extraction (no kernel, no
toolchain needed). Run: python3 tests/test_match.py
"""
import csv
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import match  # noqa: E402

G_HDR = ['sym', 'obj', 'section', 'size', 'bind', 'value', 'sec_flags']
X_HDR = ['sym', 'obj', 'func', 'func_section', 'access', 'reloc_type', 'src_file',
         'src_line', 'insn', 'addr', 'off', 'field', 'sym_bind', 'guard']


def g(sym, obj, section='.bss', size=8, bind='GLOBAL', value=0, flags='WA'):
    return dict(sym=sym, obj=obj, section=section, size=size, bind=bind, value=value, sec_flags=flags)


def x(sym, obj, func, access, section='.text', insn='', addr='0', bind='EXT', guard='', field='', line=1):
    return dict(sym=sym, obj=obj, func=func, func_section=section, access=access, reloc_type='R',
                src_file='/work/' + obj[:-2] + '.c', src_line=line, insn=insn, addr=addr, off=0,
                field=field, sym_bind=bind, guard=guard)


def run(globals_rows, xref_rows, extra=(), dotconfig=None, conds=None):
    d = tempfile.mkdtemp()
    for name, hdr, rows in (('globals.tsv', G_HDR, globals_rows), ('xref.tsv', X_HDR, xref_rows)):
        with open(os.path.join(d, name), 'w', newline='') as f:
            w = csv.DictWriter(f, fieldnames=hdr, delimiter='\t', lineterminator='\n')
            w.writeheader()
            w.writerows(rows)
    db = os.path.join(d, 'filename.db')
    with open(db, 'w') as f:
        for k, v in (conds or {'net/a.c': 'CONFIG_W', 'net/b.c': 'CONFIG_R'}).items():
            f.write('%s %s\n' % (k, v))
    comp = os.path.join(d, 'composed.txt')
    with open(comp, 'w') as f:
        f.write('CONFIG_R\n')
    argv = ['--out', d, '--filename-db', db, '--composed-config', comp,
            '--root-prefix', '/work/', '--reader-scope', 'net/'] + list(extra)
    if dotconfig:
        dc = os.path.join(d, '.config')
        with open(dc, 'w') as f:
            f.write(dotconfig)
        argv += ['--dotconfig', dc]
    stdout, sys.stdout = sys.stdout, open(os.devnull, 'w')
    try:
        cands, funnel = match.main(argv)
    finally:
        sys.stdout.close()
        sys.stdout = stdout
    return cands, funnel


failures = []


def check(label, cond):
    if not cond:
        failures.append(label)


INIT = '.init.text'

# --- shared fixture: global g defined in d.o, written in a.o (init), read in b.o
base_globals = [g('gv', 'net/d.o')]
base_xref = [x('gv', 'net/a.o', 'a_init', 'STORE', INIT, insn='movq $0x1,0x0(%rip)'),
             x('gv', 'net/b.o', 'b_use', 'LOAD')]

c, f = run(base_globals, base_xref)
check('basic pair found', len(c) == 1 and c[0]['sym'] == 'gv')
check('basic: direct evidence, imm value', c and c[0]['writer_evidence'] == 'direct' and c[0]['writer_value'] == 'imm')

# --- 19/20: same-named LOCAL statics in different objects are not one symbol
gl = [g('counter', 'net/a.o', bind='LOCAL'), g('counter', 'net/b.o', bind='LOCAL'),
      g('counter', 'net/d.o', bind='LOCAL')]
xl = [x('counter', 'net/a.o', 'a_init', 'STORE', INIT, bind='LOCAL'),
      x('counter', 'net/b.o', 'b_use', 'LOAD', bind='LOCAL')]
c, f = run(gl, xl)
check('legacy name matching creates the false pair', len(run(gl, xl, ['--legacy'])[0]) == 1)
check('binding-aware: no false pair', len(c) == 0 and f['F0_local'] == 3)

# --- 20: a LOCAL reference must not bind to an unrelated GLOBAL of the same name
gl2 = [g('shared', 'net/d.o', bind='GLOBAL'), g('shared', 'net/b.o', bind='LOCAL')]
xl2 = [x('shared', 'net/a.o', 'a_init', 'STORE', INIT, bind='EXT'),
       x('shared', 'net/b.o', 'b_use', 'LOAD', bind='LOCAL')]
check('local read does not pair with global writer', len(run(gl2, xl2)[0]) == 0)
check('legacy would pair them', len(run(gl2, xl2, ['--legacy'])[0]) == 1)

# --- 22: section policy from ELF flags
gro = [g('tbl', 'net/d.o', section='.rodata..c_jump_table', flags='A')]
xro = [x('tbl', 'net/a.o', 'a_init', 'STORE', INIT), x('tbl', 'net/b.o', 'b_use', 'LOAD')]
c, f = run(gro, xro)
check('read-only section by flags excluded', len(c) == 0 and f['F0_excluded_read_only'] == 1)
check('legacy keeps non-.rodata read-only sections', len(run(gro, xro, ['--legacy'])[0]) == 1)
grel = [g('rel', 'net/d.o', section='.data..ro_after_init', flags='WA', size=8)]
check('ro_after_init stays in scope', len(run(grel, [x('rel', 'net/a.o', 'i', 'STORE', INIT), x('rel', 'net/b.o', 'u', 'LOAD')])[0]) == 1)

# --- 42: ELF alias of one storage object is one symbol
gal = [g('real', 'net/d.o', value=16), g('real_alias', 'net/d.o', bind='WEAK', value=16)]
xal = [x('real_alias', 'net/a.o', 'a_init', 'STORE', INIT), x('real', 'net/b.o', 'b_use', 'LOAD')]
check('alias writer pairs with canonical reader', len(run(gal, xal)[0]) == 1)
check('legacy misses the alias', len(run(gal, xal, ['--legacy'])[0]) == 0)

# --- 31/32: ADDR is not a writer; sole writer counts functions
xadd = base_xref + [x('gv', 'net/c.o', 'c_fn', 'ADDR')]
c, _ = run(base_globals, xadd)
check('ADDR does not break sole_writer, is reported', c[0]['sole_writer'] and c[0]['addr_taken'])
check('legacy counts ADDR as a writer', not run(base_globals, xadd, ['--legacy'])[0][0]['sole_writer'])
xmulti = base_xref + [x('gv', 'net/a.o', 'a_init', 'STORE', INIT, addr='8')]
c, _ = run(base_globals, xmulti)
check('two stores in one function = one writer function', c[0]['sole_writer'] and c[0]['n_writer_funcs'] == 1)

# --- 41: repeated access sites collapse into one function-pair row
xrep = [x('gv', 'net/a.o', 'a_init', 'STORE', INIT, addr='0', line=1),
        x('gv', 'net/a.o', 'a_init', 'STORE', INIT, addr='8', line=2),
        x('gv', 'net/b.o', 'b_use', 'LOAD', addr='0', line=3),
        x('gv', 'net/b.o', 'b_use', 'LOAD', addr='9', line=4)]
c, f = run(base_globals, xrep)
check('dedupe to one row', len(c) == 1 and c[0]['n_site_pairs'] == 4
      and c[0]['n_writer_sites'] == 2 and c[0]['n_reader_sites'] == 2)
check('funnel keeps site-pair counts', f['F5_kconfig_separable_pairs'] == 4 and f['candidates_total'] == 1)
check('legacy keeps one row per site pair', len(run(base_globals, xrep, ['--legacy'])[0]) == 4)

# --- 24: a clearing store is flagged; an address stored is not "zero"
xz = [x('gv', 'net/a.o', 'a_clear', 'STORE', INIT, insn='movq $0x0,0x0(%rip)', addr='0'),
      x('gv', 'net/b.o', 'b_use', 'LOAD')]
check('zero store flagged', run(base_globals, xz)[0][0]['writer_value'] == 'zero')
xfp = [x('gv', 'net/a.o', 'a_set', 'STORE', INIT, insn='movq $0x0,0x0(%rip)', addr='0'),
       x('cb', 'net/a.o', 'a_set', 'ADDR', INIT, addr='0'),
       x('gv', 'net/b.o', 'b_use', 'LOAD')]
check('relocated immediate is not zero', run(base_globals, xfp)[0][0]['writer_value'] == 'imm')

# --- 25: indirect call through the global counts as a read
xic = [x('gv', 'net/a.o', 'a_init', 'STORE', INIT), x('gv', 'net/b.o', 'b_call', 'INDIRECT_CALL_READ')]
c, _ = run(base_globals, xic)
check('indirect call is a reader', len(c) == 1 and c[0]['reader_evidence'] == 'indirect_call')

# --- 23: inferred writers need --include-indirect and are labelled
xind = [x('gv', 'net/a.o', 'a_init', 'IND_STORE', INIT), x('gv', 'net/b.o', 'b_use', 'LOAD')]
check('inferred writer ignored by default', len(run(base_globals, xind)[0]) == 0)
c, _ = run(base_globals, xind, ['--include-indirect'])
check('inferred writer labelled', len(c) == 1 and c[0]['writer_evidence'] == 'inferred')

# --- 35/36: guard evidence is per site, loaded-value tests count
xg = [x('gv', 'net/a.o', 'a_init', 'STORE', INIT),
      x('gv', 'net/b.o', 'b_checked', 'LOAD', guard='reg_test', addr='0'),
      x('gv', 'net/b.o', 'b_other', 'LOAD', addr='0')]
c, _ = run(base_globals, xg)
by = dict((r['reader_func'], r) for r in c)
check('reg_test guards the site', by['b_checked']['guard_evidence'] == 'site' and not by['b_checked']['unguarded'])
check('unrelated function stays unguarded', by['b_other']['unguarded'])
xg2 = [x('gv', 'net/a.o', 'a_init', 'STORE', INIT),
       x('gv', 'net/b.o', 'b_fn', 'LOAD', guard='reg_test', addr='0'),
       x('gv', 'net/b.o', 'b_fn', 'LOAD', addr='5')]
c, _ = run(base_globals, xg2)
check('merged pair: weakest guard evidence wins', len(c) == 1 and c[0]['guard_evidence'] == 'function' and not c[0]['unguarded'])

# --- 38/39: tristate configuration
cfg = 'CONFIG_W=m\nCONFIG_R=y\n'
c, f = run(base_globals, base_xref, dotconfig=cfg)
check('module writer is not "absent"', c[0]['writer_cfg'] == 'm' and not c[0]['cozart_exposed']
      and c[0]['exposed_if_module_unloaded'] and f['F9_writer_module_unloaded_pairs'] == 1)
c, _ = run(base_globals, base_xref, dotconfig='# CONFIG_W is not set\nCONFIG_R=y\n')
check('n writer + y reader is exposed', c[0]['writer_cfg'] == 'n' and c[0]['cozart_exposed'])
c, _ = run(base_globals, base_xref)
check('composed list: reader in list, writer not => exposed', c[0]['cozart_exposed'] and c[0]['reader_cfg'] == 'y')

# --- 33: pointer-sized .bss ranks above a small counter
gc = [g('gv', 'net/d.o', size=4)]
check('small .bss scores below pointer-sized',
      run(gc, base_xref)[0][0]['score'] < run(base_globals, base_xref)[0][0]['score'])

# --- 21: population split by linkage
gm = [g('a1', 'net/d.o', bind='GLOBAL'), g('a2', 'net/d.o', bind='WEAK'), g('a3', 'net/d.o', bind='LOCAL')]
_, f = run(gm, [])
check('F0 by linkage', (f['F0_global'], f['F0_weak'], f['F0_local']) == (1, 1, 1))

if failures:
    print('%d FAILURE(S):' % len(failures))
    for fl in failures:
        print('  ' + fl)
    sys.exit(1)
print('all match.py tests passed')
