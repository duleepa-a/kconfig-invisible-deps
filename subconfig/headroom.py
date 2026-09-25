#!/usr/bin/env python3
import re, bisect, subprocess, sys

VMLINUX = '/work/linux-cosmic/vmlinux'
TRACE = '/work/tb_trace.log'

# text symbols with sizes
funcs = []
out = subprocess.check_output(['nm', '-S', '-n', VMLINUX], universal_newlines=True)
for line in out.splitlines():
    p = line.split()
    if len(p) != 4:
        continue
    addr, size, typ, name = p
    if typ not in 'tTwW':
        continue
    funcs.append((int(addr, 16), int(size, 16), name))
funcs.sort()
starts = [f[0] for f in funcs]

insn_re = re.compile(r'^0x([0-9a-f]{16}):')
touched = set()
kernel_addrs = 0
for line in open(TRACE, errors='replace'):
    m = insn_re.match(line)
    if not m:
        continue
    a = int(m.group(1), 16)
    if a < 0xffffffff80000000:
        continue
    kernel_addrs += 1
    i = bisect.bisect_right(starts, a) - 1
    if i >= 0 and a < funcs[i][0] + max(funcs[i][1], 1):
        touched.add(i)

total_bytes = sum(f[1] for f in funcs)
touched_bytes = sum(funcs[i][1] for i in touched)
print(f'text functions total : {len(funcs)}  ({total_bytes/1024:.0f} KiB)')
print(f'functions executed   : {len(touched)}  ({touched_bytes/1024:.0f} KiB)')
print(f'functions untraced   : {len(funcs)-len(touched)}  ({(total_bytes-touched_bytes)/1024:.0f} KiB, '
      f'{100*(total_bytes-touched_bytes)/total_bytes:.1f}% of function bytes)')

with open('/work/untraced_funcs.txt', 'w') as f:
    for i, fn in enumerate(funcs):
        if i not in touched:
            f.write(f'{fn[2]}\t{fn[1]}\n')
with open('/work/traced_funcs.txt', 'w') as f:
    for i in sorted(touched):
        f.write(f'{funcs[i][2]}\t{funcs[i][1]}\n')
