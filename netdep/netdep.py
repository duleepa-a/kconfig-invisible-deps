#!/usr/bin/env python3
"""
netdep.py -- ELF-level global-state dependency extractor.

Scans compiled kernel .o files for OBJECT symbol definitions (globals.tsv)
and their reference sites (xref.tsv), classified by access kind
(STORE / LOAD / ADDR / RMW / DATAREF / CALL) and enclosing function/section.

This is Stage 1 of the detector described in the research plan: it finds
candidates of the shape

    file F_X (obj-y)        defines global X
    file F_A (obj-$(CONFIG_A))   writes X from a function in .init.text
    file F_B (obj-$(CONFIG_B))   reads X from a function in .text, no guard

Two passes per object file:
  - instruction-stream relocations, via `objdump -dr -l` (STORE/LOAD/ADDR/
    RMW/CALL sites inside executable sections, with DWARF source lines)
  - data-section relocations, via `objdump -r` (DATAREF sites: static
    initialisers and ops-table entries living in .data/.rodata, which
    objdump never disassembles as instructions)

Usage:
    netdep.py --root /work/linux-cosmic --subdirs net kernel mm lib \
               --out /work/out
"""
import argparse
import bisect
import os
import re
import subprocess
import sys
from collections import defaultdict

# Mnemonics that, when a relocation's memory operand is the DESTINATION,
# genuinely read-modify-write (as opposed to plain data-movement mnemonics
# like mov/cmov, which just overwrite the destination without reading it).
RMW_BASE_MNEMONICS = {
    'add', 'sub', 'or', 'and', 'xor', 'inc', 'dec', 'adc', 'sbb', 'not', 'neg',
    'xadd', 'cmpxchg', 'cmpxchg8b', 'cmpxchg16b', 'shl', 'shr', 'sal', 'sar',
    'rol', 'ror', 'rcl', 'rcr', 'btc', 'bts', 'btr',
}
# Always both-read-and-write regardless of operand position.
ALWAYS_RMW_MNEMONICS = {'xchg', 'cmpxchg', 'cmpxchg8b', 'cmpxchg16b', 'xadd'}
# Implicit-accumulator arithmetic: reads memory, writes only a register
# (AX/DX or an explicit dest operand for the 3-operand IMUL form) -- never
# writes back to the memory operand itself.
READ_ONLY_ARITH_MNEMONICS = {'mul', 'imul', 'div', 'idiv'}
# Instruction-prefix tokens objdump prints as a separate leading word.
INSN_PREFIXES = {'lock', 'rep', 'repe', 'repz', 'repne', 'repnz', 'bnd', 'notrack'}

DATA_SECTION_PREFIXES = ('.data', '.bss', '.rodata', '.init.data', '.ro_after_init')


def strip_size_suffix(base):
    """movq/addl/cmpb etc -> mov/add/cmp. Only strips a trailing size
    letter when the remainder is still a plausible mnemonic stem (avoids
    mangling instructions that legitimately end in q/l/w/b, e.g. 'bswap')."""
    if len(base) > 3 and base[-1] in 'qlwb' and not base.endswith(('call', 'movabs')):
        return base[:-1]
    return base


def is_mem_operand(op):
    op = op.strip()
    if '(' in op:
        return True
    if op.startswith('%gs:') or op.startswith('%fs:'):
        return True
    if re.match(r'^-?0x[0-9a-fA-F]+$', op):
        return True
    return False


def is_imm_operand(op):
    return op.strip().startswith('$')


def split_operands(operand_str):
    """Split AT&T-syntax operand list on top-level commas, respecting
    parenthesis nesting. SIB addressing without a base register (e.g.
    '0x0(,%rbx,8)') contains a comma *inside* the memory operand, so a
    naive whole-string split on ',' breaks that operand apart -- track
    paren depth and only split at depth 0."""
    operand_str = operand_str.strip()
    if not operand_str:
        return []
    parts = []
    depth = 0
    cur = []
    for ch in operand_str:
        if ch == '(':
            depth += 1
            cur.append(ch)
        elif ch == ')':
            depth -= 1
            cur.append(ch)
        elif ch == ',' and depth == 0:
            parts.append(''.join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    if cur:
        parts.append(''.join(cur).strip())
    return parts


def strip_prefix(mnemonic, operand_str):
    """objdump prints 'lock cmpxchg %eax,0x0(%rip)' with the prefix as the
    apparent mnemonic and the real instruction as the first 'operand'."""
    if mnemonic.lower() in INSN_PREFIXES:
        parts = operand_str.split(None, 1)
        if parts:
            real_mnemonic = parts[0]
            real_operands = parts[1] if len(parts) > 1 else ''
            return real_mnemonic, real_operands
    return mnemonic, operand_str


def classify_instruction(mnemonic, operand_str, reloc_index=0):
    """Return one of STORE / LOAD / ADDR / RMW / CALL / UNKNOWN.

    reloc_index: which relocation (0-based) within the CURRENT
    instruction is being classified. Matters only for the two-relocation
    `movq $imm32, disp32(%rip)` case (mcmodel=kernel absolute addressing
    storing a function pointer into a global/struct field, e.g.
    `pingv6_ops.field = some_func;`) -- that single instruction carries
    TWO relocations, one on the immediate source (the function whose
    address is taken) and one on the memory destination (the global
    being written). Confirmed via verified byte-offset ordering in real
    disassembly (net/ipv6/ping.c's pingv6_init): the destination's
    relocation offset always precedes the source immediate's within the
    instruction encoding (displacement bytes before immediate bytes), so
    reloc_index==0 is the destination (STORE) and any later index is the
    source (ADDR). Before this fix both relocations were classified
    identically as ADDR, making this entire pattern -- writing a
    function pointer into a global -- invisible to every STORE/RMW-based
    writer search in this project."""
    mnemonic, operand_str = strip_prefix(mnemonic, operand_str)
    m = mnemonic.lower()
    base = strip_size_suffix(m)

    if base.startswith('lea'):
        return 'ADDR'
    if base.startswith('cmp') or base.startswith('test') or base.startswith('bt'):
        return 'LOAD'  # GUARD-HINT derived separately from the mnemonic
    if base.startswith('call') or base.startswith('jmp') or re.match(r'^j[a-z]+$', base):
        return 'CALL'

    ops = split_operands(operand_str)

    if base.startswith('push'):
        if len(ops) == 1 and is_imm_operand(ops[0]):
            return 'ADDR'   # pushing sym's address as a constant
        if len(ops) == 1 and is_mem_operand(ops[0]):
            return 'LOAD'   # pushing the VALUE stored at sym
        return 'UNKNOWN'

    if base in ALWAYS_RMW_MNEMONICS:
        if any(is_mem_operand(o) for o in ops):
            return 'RMW'
        return 'UNKNOWN'

    if base in READ_ONLY_ARITH_MNEMONICS:
        # mul/div family, including 3-operand imul ($imm, mem_src, reg_dst):
        # memory operand is read, never written.
        if any(is_mem_operand(o) for o in ops):
            return 'LOAD'
        return 'UNKNOWN'

    if len(ops) == 1:
        op = ops[0]
        if is_imm_operand(op):
            return 'ADDR'
        if is_mem_operand(op):
            return 'RMW'  # inc/dec/neg/not/shl-by-1 etc: single mem operand, read+write
        return 'UNKNOWN'

    if len(ops) == 2:
        src, dst = ops
        if is_imm_operand(src):
            # "movq $sym, mem" -- normally loading sym's ADDRESS as a
            # constant. Only a RIP-relative destination ("mem(%rip)")
            # carries its OWN relocation (a static address needs one
            # resolved at link time) -- when that's the case, this single
            # instruction has TWO relocations, and the first (destination)
            # is a genuine write. A register-relative destination
            # (e.g. "0x28(%r12)", a runtime struct-field offset -- no
            # relocation possible, the address is only known at runtime)
            # is NEVER itself relocated: whatever relocation IS present on
            # such an instruction must belong to the immediate source, at
            # ANY reloc_index. Conflating these two destination shapes was
            # a real bug: it misclassified "sk->sk_prot = &tcp_prot" (a
            # register-relative destination) as a STORE to `tcp_prot`,
            # when tcp_prot's address is merely being taken (ADDR) and
            # written into an unrelated object's field, invisible to this
            # analysis by construction (see the struct-field-tracker
            # discussion -- this is exactly that problem, caught here as a
            # false STORE rather than a missed one).
            if '%rip' in dst and is_mem_operand(dst) and reloc_index == 0:
                return 'STORE'
            return 'ADDR'
        src_mem = is_mem_operand(src)
        dst_mem = is_mem_operand(dst)
        if dst_mem and not src_mem:
            return 'RMW' if base in RMW_BASE_MNEMONICS else 'STORE'
        if src_mem and not dst_mem:
            return 'LOAD'
        return 'UNKNOWN'

    return 'UNKNOWN'


def has_guard_hint(mnemonic, operand_str):
    mnemonic, _ = strip_prefix(mnemonic, operand_str)
    base = strip_size_suffix(mnemonic.lower())
    return base.startswith('cmp') or base.startswith('test') or base.startswith('bt')


SYM_HEAD_RE = re.compile(r'^([A-Za-z_.$][\w.$]*)')


def base_symbol(symexpr):
    m = SYM_HEAD_RE.match(symexpr.strip())
    return m.group(1) if m else symexpr.strip()


def run(cmd):
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                        universal_newlines=True)
    return p.stdout


SEC_HDR_RE = re.compile(r'^\s*\[\s*(\d+)\]\s+(\S+)')
SYM_ROW_RE = re.compile(
    r'^\s*\d+:\s+([0-9a-fA-F]+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s*(.*)$'
)


def parse_symbols(obj_path):
    """Returns list of {name, section, size, bind, value} for OBJECT symbols
    that are defined (not UND) in this object file."""
    sec_out = run(['readelf', '-SW', obj_path])
    idx2name = {}
    for line in sec_out.splitlines():
        m = SEC_HDR_RE.match(line)
        if m:
            idx2name[int(m.group(1))] = m.group(2)

    sym_out = run(['readelf', '-sW', obj_path])
    syms = []
    for line in sym_out.splitlines():
        m = SYM_ROW_RE.match(line)
        if not m:
            continue
        value, size, typ, bind, vis, ndx, name = m.groups()
        name = name.strip()
        if typ != 'OBJECT' or not name:
            continue
        if ndx == 'UND':
            continue
        if ndx == 'ABS':
            section = 'ABS'
        elif ndx == 'COM':
            section = 'COMMON'
        else:
            try:
                section = idx2name.get(int(ndx), 'UNK' + ndx)
            except ValueError:
                section = ndx
        syms.append({
            'name': name, 'section': section, 'size': int(size),
            'bind': bind, 'value': int(value, 16),
        })
    return syms


SECTION_HDR_RE = re.compile(r'^Disassembly of section (\S+):$')
FUNC_HDR_RE = re.compile(r'^[0-9a-f]+\s+<([^>]+)>:$')
SRCLINE_RE = re.compile(r'^(/\S+\.[a-zA-Z]+):(\d+)(?:\s+\(discriminator \d+\))?$')
INSN_RE = re.compile(r'^\s*([0-9a-f]+):\t(.*)$')
RELOC_RE = re.compile(r'^\s*([0-9a-f]+):\s+(R_X86_64_\S+)\s+(.+)$')

SECTION_NAME_RE = re.compile(r'^\.[\w.]*$')


def is_section_name(sym):
    """True for a SECTION name (.text, .bss, .data..percpu, ...) rather
    than an actual symbol. objdump/readelf fall back to "section+offset"
    when a relocation targets a `static` (internal-linkage) object that
    has no retained local symbol-table entry -- this happens often enough
    (measured ~29% of raw relocations in a real kernel build) that it
    must be filtered, not treated as a legitimate global's name. No real
    C identifier begins with '.', so this check is exact, not heuristic."""
    return bool(SECTION_NAME_RE.match(sym))


def parse_text_refs(obj_path, obj_rel):
    """Instruction-stream relocations via `objdump -dr -l`."""
    out = run(['objdump', '-dr', '-l', '--no-show-raw-insn', obj_path])
    section = None
    func = None
    src_file = ''
    src_line = 0
    last_insn = None  # (mnemonic, operand_str, raw)
    reloc_index = 0  # which relocation, 0-based, within the current instruction
    refs = []
    unclassified = []
    n_section_relative = 0

    for line in out.splitlines():
        m = SECTION_HDR_RE.match(line)
        if m:
            section = m.group(1)
            func = None
            continue
        m = FUNC_HDR_RE.match(line)
        if m:
            func = m.group(1)
            continue
        m = SRCLINE_RE.match(line)
        if m:
            src_file, src_line = m.group(1), int(m.group(2))
            continue
        m = RELOC_RE.match(line)
        if m:
            reloc_type = m.group(2)
            symexpr = m.group(3).strip()
            sym = base_symbol(symexpr)
            if is_section_name(sym):
                n_section_relative += 1
                continue
            if last_insn is None:
                access = 'UNKNOWN'
                mnemonic = ''
                raw = ''
            else:
                mnemonic, operand_str, raw = last_insn
                access = classify_instruction(mnemonic, operand_str, reloc_index)
                reloc_index += 1
                if access == 'LOAD' and has_guard_hint(mnemonic, operand_str):
                    access = 'LOAD_GUARD'
            if access == 'UNKNOWN':
                unclassified.append(f'{obj_rel}\t{func}\t{mnemonic if last_insn else "?"}\t{raw if last_insn else line}')
            refs.append({
                'sym': sym, 'obj': obj_rel, 'func': func or '',
                'func_section': section or '', 'access': access,
                'reloc_type': reloc_type, 'src_file': src_file,
                'src_line': src_line, 'insn': raw if last_insn else '',
            })
            continue
        m = INSN_RE.match(line)
        if m:
            rest = m.group(2)
            rest_no_comment = rest.split('#')[0].strip()
            parts = rest_no_comment.split(None, 1)
            mnemonic = parts[0] if parts else ''
            operand_str = parts[1] if len(parts) > 1 else ''
            last_insn = (mnemonic, operand_str, rest_no_comment)
            reloc_index = 0
            continue
    return refs, unclassified, n_section_relative


RELOC_HDR_RE = re.compile(r'^RELOCATION RECORDS FOR \[(\S+)\]:$')
RELOC_ROW_RE = re.compile(r'^([0-9a-f]+)\s+(\S+)\s+(.+)$')


def parse_data_refs(obj_path, obj_rel, symbols):
    """Data-section relocations via `objdump -r` -- these never show up in
    `objdump -d` because .data/.rodata are not disassembled as code.
    Resolves the *container* symbol (the struct/array holding the pointer)
    by offset lookup against this object's own symbol table."""
    by_section = defaultdict(list)  # section -> sorted [(value, size, name)]
    for s in symbols:
        by_section[s['section']].append((s['value'], s['size'], s['name']))
    for sec in by_section:
        by_section[sec].sort()

    def container_of(section, offset):
        entries = by_section.get(section)
        if not entries:
            return None
        values = [e[0] for e in entries]
        i = bisect.bisect_right(values, offset) - 1
        if i < 0:
            return None
        value, size, name = entries[i]
        if size == 0:
            return name if value == offset else None
        if value <= offset < value + size:
            return name
        return None

    out = run(['objdump', '-r', obj_path])
    sec = None
    refs = []
    n_section_relative = 0
    for line in out.splitlines():
        m = RELOC_HDR_RE.match(line)
        if m:
            sec = m.group(1)
            continue
        if not line.strip() or line.startswith('OFFSET'):
            continue
        m = RELOC_ROW_RE.match(line)
        if not m or sec is None:
            continue
        if sec.startswith('.text') or sec.startswith('.init.text') or sec.startswith('.exit.text'):
            continue  # handled by parse_text_refs
        if not sec.startswith(DATA_SECTION_PREFIXES):
            continue
        offset_s, reloc_type, symexpr = m.groups()
        sym = base_symbol(symexpr.strip())
        if is_section_name(sym):
            n_section_relative += 1
            continue
        offset = int(offset_s, 16)
        container = container_of(sec, offset)
        refs.append({
            'sym': sym, 'obj': obj_rel, 'func': container or f'@{sec}+0x{offset:x}',
            'func_section': sec, 'access': 'DATAREF', 'reloc_type': reloc_type,
            'src_file': '', 'src_line': 0, 'insn': '',
        })
    return refs, n_section_relative


def find_objects(root, subdirs, exclude_rel=None):
    """exclude_rel: set of root-relative paths to skip -- kbuild produces
    both per-source-file objects (from CC) and composite module-link
    objects (from `ld -r`, e.g. net/dccp/dccp.o combining ccid.o, feat.o,
    ..., proto.o for a multi-file module). The composite object's symbols
    and relocations are a strict duplicate of its members' -- scanning it
    too double-counts every site under a second "object" name and
    fabricates spurious cross-unit pairs. Exclude it; only the individual
    per-TU objects should be analysed."""
    exclude_rel = exclude_rel or set()
    for sub in subdirs:
        base = os.path.join(root, sub)
        if not os.path.isdir(base):
            print(f'warning: {base} does not exist, skipping', file=sys.stderr)
            continue
        for dirpath, _, filenames in os.walk(base):
            for fn in filenames:
                if not fn.endswith('.o'):
                    continue
                if fn in ('built-in.o',) or fn.endswith('.mod.o'):
                    continue
                full = os.path.join(dirpath, fn)
                rel = os.path.relpath(full, root)
                if rel in exclude_rel:
                    continue
                yield full


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--root', required=True, help='kernel source root (build dir)')
    ap.add_argument('--subdirs', nargs='+', required=True)
    ap.add_argument('--out', required=True)
    ap.add_argument('--exclude-file', default=None,
                     help='file of root-relative .o paths to skip (composite '
                          'module-link objects; see find_objects docstring)')
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)
    root = os.path.abspath(args.root)

    exclude_rel = set()
    if args.exclude_file:
        with open(args.exclude_file) as f:
            exclude_rel = set(l.strip() for l in f if l.strip())
        print(f'{len(exclude_rel)} composite objects excluded', file=sys.stderr)

    objs = sorted(find_objects(root, args.subdirs, exclude_rel))
    print(f'{len(objs)} object files found', file=sys.stderr)

    globals_f = open(os.path.join(args.out, 'globals.tsv'), 'w')
    xref_f = open(os.path.join(args.out, 'xref.tsv'), 'w')
    unclass_f = open(os.path.join(args.out, 'unclassified.txt'), 'w')

    globals_f.write('sym\tobj\tsection\tsize\tbind\n')
    xref_f.write('sym\tobj\tfunc\tfunc_section\taccess\treloc_type\tsrc_file\tsrc_line\tinsn\n')

    n_syms = 0
    n_refs = 0
    n_unclass = 0
    n_section_relative = 0

    for i, obj in enumerate(objs):
        obj_rel = os.path.relpath(obj, root)
        syms = parse_symbols(obj)
        for s in syms:
            globals_f.write(f"{s['name']}\t{obj_rel}\t{s['section']}\t{s['size']}\t{s['bind']}\n")
            n_syms += 1

        text_refs, unclass, n_sr1 = parse_text_refs(obj, obj_rel)
        data_refs, n_sr2 = parse_data_refs(obj, obj_rel, syms)
        n_section_relative += n_sr1 + n_sr2

        for r in text_refs + data_refs:
            xref_f.write(
                f"{r['sym']}\t{r['obj']}\t{r['func']}\t{r['func_section']}\t"
                f"{r['access']}\t{r['reloc_type']}\t{r['src_file']}\t{r['src_line']}\t"
                f"{r['insn']}\n"
            )
            n_refs += 1

        for u in unclass:
            unclass_f.write(u + '\n')
            n_unclass += 1

        if (i + 1) % 200 == 0:
            print(f'  {i+1}/{len(objs)} objects processed', file=sys.stderr)

    globals_f.close()
    xref_f.close()
    unclass_f.close()

    print(f'done: {n_syms} global symbols, {n_refs} reference sites, '
          f'{n_unclass} unclassified instructions, '
          f'{n_section_relative} section-relative relocations dropped '
          f'(unresolvable to a named static symbol)', file=sys.stderr)


if __name__ == '__main__':
    main()
