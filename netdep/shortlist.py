#!/usr/bin/env python3
"""Cross-reference solver-confirmed separability with guard status and shape.

A pair is worth manual examination only when all of these hold:
  * a Kconfig solver confirms the reader can be built while the writer is not;
  * the reader shows no guard on the variable;
  * the variable has no safe initial value (.bss / COMMON);
  * the variable is pointer-sized, so an unguarded use is a NULL dereference.
"""
import csv
import sys
from collections import defaultdict

sep_file, cand_file, globals_file = sys.argv[1], sys.argv[2], sys.argv[3]
mode = sys.argv[4] if len(sys.argv) > 4 else ''

size = {}
section = {}
for r in csv.DictReader(open(globals_file), delimiter='\t'):
    size.setdefault(r['sym'], r['size'])
    section.setdefault(r['sym'], r['section'])

# solver verdict, keyed by the pair's identity
sep = {}
for r in csv.DictReader(open(sep_file), delimiter='\t'):
    sep[(r['sym'], r['writer_obj'], r['reader_obj'], r['reader_func'])] = r['separable']

out = defaultdict(lambda: {'pairs': 0, 'unguarded': 0, 'readers': set(), 'writers': set()})
for r in csv.DictReader(open(cand_file), delimiter='\t'):
    k = (r['sym'], r['writer_obj'], r['reader_obj'], r['reader_func'])
    if sep.get(k) != 'yes':
        continue
    d = out[r['sym']]
    d['pairs'] += 1
    d['writers'].add(r['writer_obj'])
    if r['unguarded'] == 'True':
        d['unguarded'] += 1
        d['readers'].add(r['reader_obj'] + '::' + r['reader_func'])

print(f'=== {mode} ===')
print(f'{"symbol":30s} {"sect":20s} {"sz":>4s} {"pairs":>6s} {"unguarded":>10s}  readers')
tier1 = []
for s, d in sorted(out.items(), key=lambda x: -x[1]['unguarded']):
    sec, sz = section.get(s, '?'), size.get(s, '?')
    mark = ''
    if d['unguarded'] and sec in ('.bss', 'COMMON') and sz == '8':
        mark = '   <== pointer, no default, unguarded'
        tier1.append(s)
    print(f'{s:30s} {sec:20s} {sz:>4s} {d["pairs"]:6d} {d["unguarded"]:10d}{mark}')
    if mark:
        for rd in sorted(d['readers'])[:4]:
            print(f'{"":30s}   reader: {rd}')
print()
print('TIER 1 (solver-separable + unguarded + .bss pointer):', tier1 if tier1 else 'none')
