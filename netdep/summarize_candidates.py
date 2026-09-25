import csv, sys
from collections import Counter
rows = list(csv.DictReader(open(sys.argv[1]), delimiter='\t'))
print('rows', len(rows), 'distinct syms', len({r['sym'] for r in rows}))
print(Counter(r['sym'] for r in rows).most_common(6))
print(Counter(r['def_section'] for r in rows).most_common(4))
hi = [r for r in rows if r['risky_section'] == 'True' and r['unguarded'] == 'True']
print('risky(.bss)+unguarded rows', len(hi), 'distinct syms', len({r['sym'] for r in hi}))
print('boot-writer rows', sum(r['writer_is_boot'] == 'True' for r in rows))
