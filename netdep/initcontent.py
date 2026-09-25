#!/usr/bin/env python3
"""
initcontent.py -- conditionally-populated initializer fields (Mechanism #6 class).

Finds struct initializers whose designated field `.f = ...` sits under a
preprocessor guard that differs from the initializer's own guard, then finds
readers `x->f(...)` / `x->f->...` in files that mention the struct type, whose
presence condition can hold while the field's cannot (guardmap.separable), and
which have no NULL test on the field within the enclosing function.

Usage: initcontent.py --root DIR --dirs net include --out out.tsv
       initcontent.py --self-test
"""
import argparse, os, re, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from guardmap import compute_guard_map, separable, config_symbols

INIT_RE = re.compile(r'^(?:static\s+)?(?:const\s+)?struct\s+(\w+)\s+(\w+)(?:\[[^\]]*\])?\s*(?:__\w+\s*)*=\s*\{\s*$')
FIELD_RE = re.compile(r'^\s*\.(\w+)\s*=')


def find_initializers(lines, gmap):
    """yield (type, var, start_line, end_line) 1-indexed."""
    i = 0
    while i < len(lines):
        m = INIT_RE.match(lines[i])
        if m:
            j = i + 1
            while j < len(lines) and not lines[j].startswith('}'):
                j += 1
            yield m.group(1), m.group(2), i + 1, j + 1
            i = j
        i += 1


def cond_fields(lines, gmap):
    out = []
    for typ, var, s, e in find_initializers(lines, gmap):
        base = gmap[s - 1]
        depth = 1
        for ln in range(s + 1, e):
            fm = FIELD_RE.match(lines[ln - 1])
            if fm and depth == 1 and gmap[ln - 1] != base:
                out.append((typ, var, fm.group(1), ln, base, gmap[ln - 1]))
            code = re.sub(r'"(\\.|[^"\\])*"', '', lines[ln - 1])
            depth += code.count('{') - code.count('}')
    return out


def func_span(lines, ln):
    a = ln - 1
    while a > 0 and not lines[a].startswith('{'):
        a -= 1
    b = ln - 1
    while b < len(lines) - 1 and not lines[b].startswith('}'):
        b += 1
    return a, b


def null_tested(lines, ln, field):
    a, b = func_span(lines, ln)
    pat = [re.compile(r'\bif\s*\(\s*!?\s*(?:\w+(?:->|\.))+' + field + r'\b(?!\s*[\(\-])'),
           re.compile(r'!\s*(?:\w+(?:->|\.))+' + field + r'\b'),
           re.compile(r'(?:\w+(?:->|\.))+' + field + r'\s*(==|!=)\s*NULL'),
           re.compile(r'&&\s*(?:\w+(?:->|\.))+' + field + r'\b(?!\s*[\(\-])'),
           re.compile(r'(?:\w+(?:->|\.))+' + field + r'\s*&&')]
    for k in range(a, ln - 1):
        if any(p.search(lines[k]) for p in pat):
            return True
    return any(p.search(lines[ln - 1]) for p in pat)


def makefile_gate(path):
    """CONFIG_* options that the Makefile in the file's directory uses to gate its object."""
    base = os.path.basename(path)[:-2]
    mk = os.path.join(os.path.dirname(path), 'Makefile')
    if not path.endswith('.c') or not os.path.exists(mk):
        return None
    for l in open(mk, errors='replace'):
        m = re.match(r'\s*[\w\-\$\(\)]*-\$\((CONFIG_\w+)\)\s*\+?:?=(.*)$', l)
        if m and (base + '.o') in m.group(2).split():
            return m.group(1)
    return None


def scan(root, dirs):
    files = []
    for d in dirs:
        for dp, _, fn in os.walk(os.path.join(root, d)):
            files += [os.path.join(dp, f) for f in fn if f.endswith(('.c', '.h'))]
    text, gm = {}, {}
    for f in files:
        t = open(f, errors='replace').read()
        text[f] = t.split('\n')
        gm[f] = compute_guard_map(t)
    conds = []
    for f in files:
        for c in cond_fields(text[f], gm[f]):
            conds.append((f,) + c)
    rows = []
    for (f, typ, var, field, ln, base, cond) in conds:
        ref = re.compile(r'->' + field + r'(?:\.\w+)*\s*(\(|->)')
        for g in files:
            if not any(('struct ' + typ) in l for l in text[g]):
                continue
            for k, l in enumerate(text[g], start=1):
                if not ref.search(l) or (g == f and abs(k - ln) < 0):
                    continue
                rexp = gm[g][k - 1]
                mg = makefile_gate(g)
                if mg:
                    rexp = '(%s) and %s' % (rexp, mg)
                w = separable('(%s) and (%s)' % (rexp, base), cond)
                if w is None:
                    continue
                if null_tested(text[g], k, field):
                    continue
                rows.append((typ, var, field, os.path.relpath(f, root), ln, cond,
                             os.path.relpath(g, root), k, gm[g][k - 1], l.strip()))
    return rows


def self_test():
    import tempfile, shutil
    d = tempfile.mkdtemp()
    os.makedirs(d + '/net')
    open(d + '/net/a.c', 'w').write('''\
struct ops { int (*dump)(int); int (*plain)(int); };
static const struct ops my_ops = {
	.plain = p,
#ifdef CONFIG_TMO
	.dump = d,
#endif
};
int use_bad(const struct ops *o)
{
	return o->dump(1);
}
int use_good(const struct ops *o)
{
	if (o->dump)
		return o->dump(1);
	return 0;
}
#ifdef CONFIG_TMO
int use_same(const struct ops *o)
{
	return o->dump(1);
}
#endif
int use_plain(const struct ops *o)
{
	return o->plain(1);
}
''')
    rows = scan(d, ['net'])
    shutil.rmtree(d)
    hits = [(r[2], r[7]) for r in rows]
    assert hits == [('dump', 10)], hits
    print('self-test OK:', hits)


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('--root'); ap.add_argument('--dirs', nargs='+'); ap.add_argument('--out')
    ap.add_argument('--self-test', action='store_true')
    a = ap.parse_args()
    if a.self_test:
        self_test(); sys.exit(0)
    rows = scan(a.root, a.dirs)
    with open(a.out, 'w') as o:
        o.write('type\tvar\tfield\tinit_file\tinit_line\tfield_cond\treader_file\treader_line\treader_cond\treader_text\n')
        for r in rows:
            o.write('\t'.join(str(x) for x in r) + '\n')
    print(len(rows), 'candidate readers')
