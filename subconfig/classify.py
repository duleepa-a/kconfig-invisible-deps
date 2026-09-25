#!/usr/bin/env python3
import re, subprocess, struct, bisect, collections

VMLINUX = '/work/linux-cosmic/vmlinux'

def rd(path):
    d = {}
    for l in open(path):
        n, s = l.rstrip('\n').split('\t')
        d[n] = int(s)
    return d

untraced = rd('/work/untraced_funcs.txt')
traced = rd('/work/traced_funcs.txt')

funcs = []
out = subprocess.check_output(['nm', '-S', '-n', VMLINUX], universal_newlines=True)
for line in out.splitlines():
    p = line.split()
    if len(p) == 4 and p[2] in 'tTwW':
        funcs.append((int(p[0], 16), int(p[1], 16), p[3]))
funcs.sort()
starts = [f[0] for f in funcs]
by_start = {}
for a, s, n in funcs:
    by_start.setdefault(a, n)

# direct call/jmp graph
hdr = re.compile(r'^([0-9a-f]{16}) <([^>]+)>:')
ref = re.compile(r'\t(?:callq?|jmpq?|j[a-z]+)\s+([0-9a-f]+) <')
callers = collections.defaultdict(set)   # callee_name -> {caller_name}
cur = None
dis = subprocess.Popen(['objdump', '-d', '--no-show-raw-insn', VMLINUX],
                       stdout=subprocess.PIPE, universal_newlines=True)
for line in dis.stdout:
    m = hdr.match(line)
    if m:
        cur = m.group(2)
        continue
    if cur is None:
        continue
    m = ref.search(line)
    if m:
        t = int(m.group(1), 16)
        i = bisect.bisect_right(starts, t) - 1
        if i >= 0 and funcs[i][0] == t:
            callee = funcs[i][2]
            if callee != cur:
                callers[callee].add(cur)

# address-taken: scan data-ish sections for 8-byte words equal to a function start
addr_taken = set()
sec = subprocess.check_output(['readelf', '-SW', VMLINUX], universal_newlines=True)
blob = open(VMLINUX, 'rb').read()
for line in sec.splitlines():
    m = re.match(r'\s*\[\s*\d+\]\s+(\S+)\s+PROGBITS\s+([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)', line)
    if not m:
        continue
    name, addr, off, size = m.group(1), int(m.group(2), 16), int(m.group(3), 16), int(m.group(4), 16)
    if name.startswith('__ksymtab') or name.startswith('__kcrctab') or name == '.init.data':
        continue
    if name in ('.text', '.init.text', '.exit.text') or 'text' in name:
        continue
    if name.startswith('.debug') or name in ('.comment', '.symtab', '.strtab', '.shstrtab'):
        continue
    end = off + size - (size % 8)
    for o in range(off, end, 8):
        v = struct.unpack_from('<Q', blob, o)[0]
        if v in by_start:
            addr_taken.add(by_start[v])

cls = collections.OrderedDict((k, [0, 0]) for k in
    ['addr_taken (ops tables etc)', 'called_from_traced', 'called_only_from_untraced', 'no_direct_callers'])
untraced_set = set(untraced)
for name, size in untraced.items():
    if name in addr_taken:
        k = 'addr_taken (ops tables etc)'
    else:
        cs = callers.get(name, set())
        if not cs:
            k = 'no_direct_callers'
        elif any(c not in untraced_set for c in cs):
            k = 'called_from_traced'
        else:
            k = 'called_only_from_untraced'
    cls[k][0] += 1
    cls[k][1] += size

tot_b = sum(size for _, size in untraced.items())
print(f'untraced functions: {len(untraced)}  {tot_b/1024:.0f} KiB')
for k, (n, b) in cls.items():
    print(f'  {k:32s} {n:6d} funcs  {b/1024:7.0f} KiB  {100*b/tot_b:5.1f}%')

with open('/work/untraced_classes.tsv', 'w') as f:
    for name, size in untraced.items():
        if name in addr_taken:
            k = 'addr_taken'
        else:
            cs = callers.get(name, set())
            k = 'nocallers' if not cs else ('from_traced' if any(c not in untraced_set for c in cs) else 'only_untraced')
        f.write(f'{name}\t{size}\t{k}\n')

# ---- removal levels ----
total_fn_bytes = sum(f[1] for f in funcs)
def sz(names): return sum(untraced[n] for n in names)
non_addr = {n for n in untraced if n not in addr_taken}

# L1: no direct callers, not address-taken
L1 = {n for n in non_addr if not callers.get(n)}
# L2: fixpoint - all callers already removed
L2 = set(L1)
changed = True
while changed:
    changed = False
    for n in non_addr - L2:
        cs = callers.get(n, set())
        if cs and all(c in L2 for c in cs):
            L2.add(n); changed = True
# L3: also stub non-address-taken functions that traced code still calls
L3 = set(non_addr)
# L4: everything untraced (incl. ops-table targets)
L4 = set(untraced)
print()
print(f'all function bytes: {total_fn_bytes/1024:.0f} KiB')
for name, S in [('L1 unreferenced (no callers, not addr-taken)', L1),
                ('L2 + callers-all-removed closure', L2),
                ('L3 + stub called-from-traced', L3),
                ('L4 + stub ops-table targets', L4)]:
    print(f'  {name:48s} {len(S):6d} funcs {sz(S)/1024:7.0f} KiB  {100*sz(S)/total_fn_bytes:5.1f}% of fn bytes')
