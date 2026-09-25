#!/usr/bin/env python3
"""
ipv6dis.py -- calls into IPv6-only machinery that can run when IPv6 is
runtime-disabled (ipv6.disable=1), without a guard.

With ipv6.disable=1 (or IPV6=m not loaded), inet6_init() returns early: the
per-netns IPv6 state (net->ipv6.*) is never allocated. Code outside the IPv6
core that still calls into functions using that state can NULL-deref.

1. Nodes: functions defined in net/ipv6/** and IPv6 headers.
2. D0: nodes whose body touches `->ipv6.` (per-netns IPv6 state).
   Nodes that test ipv6_mod_enabled()/disable_ipv6_mod themselves are safe
   entry points and are excluded.
3. D: transitive closure of D0 over name-based calls between nodes.
4. Report call sites of D functions in callers outside the IPv6 core, unless
   an earlier line in the same function contains a guard token.

Heuristic and name-based; every hit is a candidate for manual audit.
Usage: ipv6dis.py --root DIR --out out.tsv | --self-test
"""
import argparse, glob, os, re, sys

KEYWORDS = set('if while for switch return sizeof else do case defined typeof __typeof__ '
               'offsetof __builtin_expect likely unlikely BUG_ON WARN_ON WARN_ON_ONCE '
               'ARRAY_SIZE container_of rcu_dereference READ_ONCE WRITE_ONCE'.split())
GUARD_RE = re.compile(r'\b(ipv6_mod_enabled|disable_ipv6_mod|__in6_dev_get|in6_dev_get|'
                      r'__in6_dev_get_safely)\b')
D0_RE = re.compile(r'(->|\.)ipv6\.')
CALL_RE = re.compile(r'(?<![\w>.])([A-Za-z_]\w*)\s*\(')
DUAL_RE = re.compile(r'\bAF_INET\b|ETH_P_IP\b|NFPROTO_IPV4|\biph->|\bip_hdr\(|struct iphdr|\bAF_UNSPEC\b')
V6SIG_RE = re.compile(r'AF_INET6|ETH_P_IPV6|NFPROTO_IPV6|NFPROTO_INET|IPPROTO_IPV6|IS_ENABLED\(CONFIG_IPV6\)')
HDR_GLOBS = ['include/net/*ipv6*.h', 'include/net/ip6*.h', 'include/net/addrconf.h',
             'include/net/ndisc.h', 'include/net/if_inet6.h', 'include/net/mld.h',
             'include/net/rawv6.h', 'include/net/transp_v6.h', 'include/net/seg6*.h',
             'include/net/icmpv6.h', 'include/net/inet6_*.h', 'include/net/tcp_v6*.h',
             'include/linux/ipv6*.h', 'include/linux/icmpv6.h', 'include/net/ipv6_stubs.h']
CALLER_DIRS = ['net', 'drivers/net', 'drivers/infiniband', 'drivers/target', 'fs',
               'kernel', 'include', 'lib']


def strip_comments(t):
    t = re.sub(r'/\*.*?\*/', lambda m: '\n' * m.group(0).count('\n'), t, flags=re.S)
    return re.sub(r'//[^\n]*', '', t)


def functions(text):
    """yield (name, is_static, start_line, end_line, body_lines) 1-indexed; kernel style."""
    ls = text.split('\n')
    i = 0
    while i < len(ls):
        if ls[i] == '{':
            j = i - 1
            sig = []
            while j >= 0 and ls[j].strip() and not ls[j].startswith(('}', '#')) and not ls[j].rstrip().endswith(';'):
                sig.insert(0, ls[j])
                j -= 1
            s = ' '.join(sig)
            m = None
            for cand in re.finditer(r'([A-Za-z_]\w*)\s*\(', s):
                if cand.group(1).startswith(('__attribute', '__aligned', '__section', '__printf')):
                    continue
                m = cand
                break
            k = i + 1
            while k < len(ls) and not ls[k].startswith('}'):
                k += 1
            if m and m.group(1) not in KEYWORDS:
                yield m.group(1), bool(re.match(r'\s*static\b', s)), i + 1, k + 1, ls[i:k + 1]
            i = k
        i += 1


def core_files(root):
    mk = os.path.join(root, 'net/ipv6/Makefile')
    txt = open(mk, errors='replace').read().replace('\\\n', ' ')
    core = set()
    for l in txt.split('\n'):
        m = re.match(r'^ipv6-(?:objs|y|\$\([A-Z0-9_]+\))\s*[:+]?=\s*(.*)$', l)
        if m:
            for tok in m.group(1).split():
                if tok.endswith('.o'):
                    core.add('net/ipv6/' + tok[:-2] + '.c')
    return core


def build_graph(root):
    files = [p for p in glob.glob(os.path.join(root, 'net/ipv6/**/*.c'), recursive=True)]
    for g in HDR_GLOBS:
        files += glob.glob(os.path.join(root, g))
    nodes = {}   # id -> dict
    for p in files:
        rel = os.path.relpath(p, root).replace(os.sep, '/')
        is_hdr = rel.endswith('.h')
        for name, static, s, e, body in functions(strip_comments(open(p, errors='replace').read())):
            nid = name if (is_hdr or not static) else rel + '::' + name
            b = '\n'.join(body)
            nodes[nid] = dict(name=name, file=rel, hdr=is_hdr, static=static and not is_hdr,
                              d0=bool(D0_RE.search(b)),
                              self_guard=bool(re.search(r'ipv6_mod_enabled|disable_ipv6_mod', b)),
                              calls={c for c in CALL_RE.findall(b) if c not in KEYWORDS and c != name})
    return nodes


def dangerous(nodes):
    D = {n for n, v in nodes.items() if v['d0'] and not v['self_guard']}

    def resolve(v, c):
        return v['file'] + '::' + c if v['file'] + '::' + c in nodes else (c if c in nodes else None)
    changed = True
    while changed:
        changed = False
        for n, v in nodes.items():
            if n in D or v['self_guard']:
                continue
            for c in v['calls']:
                t = resolve(v, c)
                if t in D:
                    D.add(n)
                    changed = True
                    break
    return D


def scan(root, out):
    core = core_files(root)
    nodes = build_graph(root)
    D = dangerous(nodes)
    entry = {n: nodes[n] for n in D if not nodes[n]['static']}
    entry_by_name = {v['name']: v for v in entry.values()}
    node_files = {v['file'] for v in nodes.values()}
    rows = []
    paths = []
    for d in CALLER_DIRS:
        for dp, _, fn in os.walk(os.path.join(root, d)):
            paths += [os.path.join(dp, f) for f in fn if f.endswith(('.c', '.h'))]
    for p in paths:
        rel = os.path.relpath(p, root).replace(os.sep, '/')
        if rel in core:
            continue
        in_v6dir = rel.startswith('net/ipv6/')
        if rel in node_files and not in_v6dir:
            continue  # header inline wrappers are graph nodes, not callers
        text = strip_comments(open(p, errors='replace').read())
        for name, static, s, e, body in functions(text):
            if in_v6dir and (rel + '::' + name in nodes or name in nodes) and False:
                continue
            btxt = '\n'.join(body)
            dual = bool(DUAL_RE.search(btxt))
            v6 = bool(V6SIG_RE.search(btxt))
            guard_seen = False
            for off, line in enumerate(body):
                if GUARD_RE.search(line):
                    guard_seen = True
                for c in set(CALL_RE.findall(line)):
                    if c in KEYWORDS or c not in entry_by_name or c == name:
                        continue
                    callee = entry_by_name[c]
                    if in_v6dir and callee['file'] not in core:
                        continue
                    rows.append((rel, s + off, name, c, callee['file'], 'GUARDED' if guard_seen else 'UNGUARDED',
                                 int(dual), int(v6), int(not in_v6dir), line.strip()[:110]))
    with open(out, 'w') as f:
        f.write('file\tline\tfunc\tcallee\tcallee_file\tguard\tdual_stack\tv6_signal\toutside_ipv6dir\tsnippet\n')
        for r in rows:
            f.write('\t'.join(str(x) for x in r) + '\n')
    return rows, len(nodes), len(D), len(entry)


def self_test():
    import tempfile, shutil
    d = tempfile.mkdtemp()
    for sub in ('net/ipv6', 'net/netfilter', 'include/net'):
        os.makedirs(os.path.join(d, sub))
    open(d + '/net/ipv6/Makefile', 'w').write('ipv6-y := route.o\nobj-$(CONFIG_IPV6) += ipv6.o\n')
    open(d + '/net/ipv6/route.c', 'w').write('''\
int rt6_lookup(struct net *net)
{
	return net->ipv6.fib6_main_tbl->x;
}
int rt6_wrapper(struct net *net)
{
	return rt6_lookup(net);
}
int safe_entry(struct net *net)
{
	if (!ipv6_mod_enabled())
		return 0;
	return net->ipv6.fib6_main_tbl->x;
}
int harmless(void)
{
	return 1;
}
''')
    open(d + '/net/netfilter/bad.c', 'w').write('''\
static int bad_eval(struct net *net, int proto)
{
	if (proto == ETH_P_IP)
		return 0;
	return rt6_wrapper(net);
}
static int good_eval(struct net *net)
{
	if (!ipv6_mod_enabled())
		return 0;
	return rt6_lookup(net);
}
static int good2(struct net *net, struct net_device *dev)
{
	if (!__in6_dev_get(dev))
		return 0;
	return rt6_lookup(net);
}
static int benign(void)
{
	return harmless() + safe_entry(0);
}
''')
    rows, n, nd, ne = scan(d, d + '/out.tsv')
    shutil.rmtree(d)
    unguarded = sorted((r[2], r[3]) for r in rows if r[5] == 'UNGUARDED')
    guarded = sorted((r[2], r[3]) for r in rows if r[5] == 'GUARDED')
    assert unguarded == [('bad_eval', 'rt6_wrapper')], unguarded
    assert guarded == [('good2', 'rt6_lookup'), ('good_eval', 'rt6_lookup')], guarded
    print('self-test OK: unguarded', unguarded, 'guarded', guarded)


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('--root')
    ap.add_argument('--out')
    ap.add_argument('--self-test', action='store_true')
    a = ap.parse_args()
    if a.self_test:
        self_test()
        sys.exit(0)
    rows, n, nd, ne = scan(a.root, a.out)
    print(f'{n} graph nodes, {nd} dangerous, {ne} dangerous entry points; '
          f'{len(rows)} call sites ({sum(r[5] == "UNGUARDED" for r in rows)} unguarded)')
