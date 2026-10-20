#!/bin/sh
# Compile tests/classify_cases.c like the kernel does (x86-64, mcmodel=kernel,
# -g) and check netdep.py's output against its `// EXPECT:` comments.
# Run inside the Linux container (needs gcc, objdump, readelf).
set -e
here=$(cd "$(dirname "$0")" && pwd)
tmp=$(mktemp -d)
gcc -O1 -g -mcmodel=kernel -fno-pic -fno-pie -fno-asynchronous-unwind-tables \
    -mno-red-zone -c "$here/classify_cases.c" -o "$tmp/classify_cases.o"

rc=0
python3 - "$here" "$tmp/classify_cases.o" <<'EOF' || rc=$?
import os, re, sys
here, obj = sys.argv[1], sys.argv[2]
sys.path.insert(0, os.path.dirname(here))
import netdep
from dwarf_layout import Layouts

syms, sizes = netdep.parse_object_symbols(obj)
res = netdep.SymbolRanges(syms, sizes)
lay = Layouts(obj)
text, unclass, _ = netdep.parse_text_refs(obj, 'classify_cases.o', res, lay.field_path)
data, _ = netdep.parse_data_refs(obj, 'classify_cases.o', res, lay.field_path)
rows = text + data

exp_re = re.compile(r'//\s*EXPECT:\s*(\S+)\s+(\S+)(?:\s+field=(\S+))?')
bad = 0
for line in open(os.path.join(here, 'classify_cases.c')):
    m = exp_re.search(line)
    if not m:
        continue
    sym, acc, field = m.group(1), set(m.group(2).split('|')), m.group(3)
    hit = [r for r in rows if r['sym'] == sym and r['access'] in acc
           and (field is None or r['field'] == field)]
    status = 'ok  ' if hit else 'FAIL'
    if not hit:
        bad += 1
    print('%s %-10s %-34s %s' % (status, sym, m.group(2), 'field=' + field if field else ''))
    if not hit:
        for r in rows:
            if r['sym'] == sym:
                print('       saw: %s field=%r off=%s  %s' % (r['access'], r['field'], r['off'], r['insn']))
print('\n%d unclassified instructions' % len(unclass))
sys.exit(1 if bad else 0)
EOF
rm -rf "$tmp"
exit $rc
