import csv, glob
def syms(p): return {r['sym'] for r in csv.DictReader(open(p), delimiter='\t')}
old = set()
for p in glob.glob('results/candidates_*fix2.tsv') + glob.glob('results/candidates_boot*.tsv') + glob.glob('results/candidates_lazy*.tsv'):
    if 'ayc' in p: continue
    old |= syms(p)
for m in ('boot', 'lazy'):
    new = syms(f'results/candidates_ayc_{m}.tsv')
    print(m, 'total', len(new), 'previously seen', len(new & old), 'NEW', len(new - old))
    rows = [r for r in csv.DictReader(open(f'results/candidates_ayc_{m}.tsv'), delimiter='\t') if r['sym'] in new - old]
    seen = {}
    for r in rows:
        seen.setdefault(r['sym'], r)
    for s, r in sorted(seen.items()):
        print(f"  {s:34s} {r['def_section']:18s} def={r['def_obj'][:34]:34s} w={r['writer_obj'][:32]:32s} wc={r['writer_cond'][:30]} rc={r['reader_cond'][:30]} ung={r['unguarded']}")
