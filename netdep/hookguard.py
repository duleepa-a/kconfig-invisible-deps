#!/usr/bin/env python3
"""Exhaustive per-reader NULL-guard check for hook-pointer symbols.

For every textual use of each hook symbol (and its accessor helpers) in the
kernel source, decide: WRITE / DECL / GUARDED / UNGUARDED / UNCLEAR.
Heuristic; UNGUARDED and UNCLEAR are reviewed by hand.
"""
import re, subprocess, sys, os, json

ROOT = '/work/linux-cosmic'
SCOPES = ['net', 'kernel', 'mm', 'lib', 'fs', 'include', 'drivers/net', 'drivers/infiniband']

# symbol -> accessor helper names that return/deref the same pointer
SYMS = {
 'nf_ipv6_ops': ['nf_get_ipv6_ops'],
 'nf_nat_hook': [], 'nf_ct_hook': [], 'ip_ct_attach': [], 'nfnl_ct_hook': [],
 'nf_nat_sip_hooks': [], 'nf_ct_timeout_put_hook': [], 'nf_ct_timeout_find_get_hook': [],
 'nf_br_ops': [], 'br_should_route_hook': [], 'br_fdb_test_addr_hook': [],
 'bpfilter_process_sockopt': [],
 'nf_nat_tftp_hook': [], 'nf_nat_snmp_hook': [], 'nf_nat_irc_hook': [],
 'nf_nat_ftp_hook': [], 'nf_nat_amanda_hook': [],
 'nf_nat_pptp_hook_outbound': [], 'nf_nat_pptp_hook_inbound': [],
 'nf_nat_pptp_hook_exp_gre': [], 'nf_nat_pptp_hook_expectfn': [],
 'nat_t120_hook': [], 'nat_h245_hook': [], 'nat_callforwarding_hook': [],
 'nat_q931_hook': [], 'nat_rtp_rtcp_hook': [],
 'set_h225_addr_hook': [], 'set_ras_addr_hook': [], 'set_sig_addr_hook': [],
 'crc32c_csum_stub': [],
}

def grep(sym):
    cmd = ['grep', '-rnw', '--include=*.c', '--include=*.h', sym] + \
          [os.path.join(ROOT, s) for s in SCOPES if os.path.isdir(os.path.join(ROOT, s))]
    out = subprocess.run(cmd, stdout=subprocess.PIPE, universal_newlines=True).stdout
    for l in out.splitlines():
        m = re.match(r'(.*?):(\d+):(.*)$', l)
        if m:
            yield m.group(1), int(m.group(2)), m.group(3)

filecache = {}
def lines(path):
    if path not in filecache:
        filecache[path] = open(path, errors='replace').read().split('\n')
    return filecache[path]

def func_end(ls, i):
    # scan forward to a line that is exactly "}" at column 0 (end of function)
    for j in range(i, min(i + 200, len(ls))):
        if ls[j].startswith('}'):
            return j
    return min(i + 60, len(ls) - 1)

def classify(path, ln, text, sym, accessors):
    s = text.strip()
    if re.match(r'(extern|EXPORT_SYMBOL|typedef)', s) or 'EXPORT_SYMBOL' in s:
        return 'DECL', ''
    if re.search(r'(RCU_INIT_POINTER|rcu_assign_pointer|WRITE_ONCE)\s*\(\s*' + re.escape(sym) + r'\b', s) \
       or re.match(re.escape(sym) + r'\s*=[^=]', s):
        return 'WRITE', ''
    if re.match(r'^[\w\s\*\(\)_]+\b' + re.escape(sym) + r'\s*(__\w+\s*)*(=|;|__read_mostly)', s) and not re.search(r'\bif\b', s):
        # definition line like: struct x *sym __read_mostly;
        if not re.search(r'rcu_dereference|READ_ONCE', s):
            return 'DECL', ''
    ls = lines(path)
    end = func_end(ls, ln - 1)
    body = ls[ln - 1:end + 1]
    ctx = '\n'.join(body[:14])
    # direct guard on the symbol itself in same statement
    if re.search(r'\bif\s*\(\s*!?\s*' + re.escape(sym) + r'\b', s) or \
       re.search(re.escape(sym) + r'\s*(==|!=)\s*NULL', s) or \
       re.search(r'&&\s*' + re.escape(sym) + r'\b', s):
        return 'GUARDED', s
    # local var assignment: var = <deref of sym or accessor>
    m = re.search(r'(\w+)\s*=\s*(?:rcu_dereference\w*|READ_ONCE|rcu_dereference_protected)?\s*\(?\s*' + re.escape(sym) + r'\b', s)
    if not m:
        for a in accessors:
            m = re.search(r'(\w+)\s*=\s*' + re.escape(a) + r'\s*\(', s)
            if m:
                break
    if m:
        var = m.group(1)
        # find first later line that guards var, and first that derefs var
        guard = deref = None
        for k, bl in enumerate(body[1:40], start=1):
            if guard is None and (re.search(r'\bif\s*\(\s*!?\s*' + var + r'\b', bl) or
                                  re.search(r'\b' + var + r'\s*(==|!=)\s*NULL', bl) or
                                  re.search(r'(&&|\|\|)\s*!?\s*' + var + r'\b', bl) or
                                  re.search(r'\bif\s*\(.*!' + var + r'\b', bl) or
                                  re.search(r'WARN_ON\w*\(\s*!?\s*' + var, bl)):
                guard = k
            if deref is None and re.search(r'\b' + var + r'\s*->', bl):
                deref = k
            if guard is not None and deref is not None:
                break
        if guard is not None and (deref is None or guard <= deref):
            return 'GUARDED', ctx
        if deref is not None:
            return 'UNGUARDED', ctx
        return 'UNCLEAR', ctx
    # direct call through the symbol: sym(...) or sym->...
    if re.search(re.escape(sym) + r'\s*(\(|->)', s):
        return 'UNGUARDED', ctx
    return 'UNCLEAR', ctx

rows = []
for sym, acc in SYMS.items():
    seen = set()
    for path, ln, text in grep(sym):
        key = (path, ln)
        if key in seen:
            continue
        seen.add(key)
        k, ctx = classify(path, ln, text, sym, acc)
        rows.append((sym, path.replace(ROOT + '/', ''), ln, k, text.strip(), ctx))
    # accessor helpers: sites that call the accessor
    for a in acc:
        for path, ln, text in grep(a):
            key = (path, ln)
            if key in seen:
                continue
            seen.add(key)
            if re.search(r'\b' + a + r'\s*\(\s*\)\s*\{|static inline|extern', text):
                continue
            k, ctx = classify(path, ln, text, sym, acc)
            rows.append((sym + ' [via ' + a + ']', path.replace(ROOT + '/', ''), ln, k, text.strip(), ctx))

json.dump(rows, open('/work/hookguard.json', 'w'))
from collections import Counter
c = Counter(r[3] for r in rows)
print('sites:', len(rows), dict(c))
print()
for r in rows:
    if r[3] in ('UNGUARDED', 'UNCLEAR'):
        print(f'{r[3]:10s} {r[0]:32s} {r[1]}:{r[2]}   {r[4][:90]}')
