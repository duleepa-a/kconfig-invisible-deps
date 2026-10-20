#!/usr/bin/env python3
"""
netdep.py -- ELF-level global-state dependency extractor.

Scans compiled kernel .o files for OBJECT symbol definitions (globals.tsv)
and their reference sites (xref.tsv), classified by access kind
(STORE / LOAD / LOAD_GUARD / RMW / ADDR / DATAREF / CALL /
INDIRECT_CALL_READ / IND_LOAD / IND_STORE / IND_RMW) and enclosing
function/section.

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

Supported target: x86-64, AT&T syntax objdump output. Other machines are
skipped with a warning. See LIMITATIONS.md for what is and is not covered.

Usage:
    netdep.py --root /work/linux-cosmic --subdirs net kernel mm lib \
               --out /work/out [--dwarf-fields]
    netdep.py --self-test
"""
import argparse
import bisect
import os
import re
import subprocess
import sys
from collections import defaultdict

# --------------------------------------------------------------------
# Instruction semantics tables
# --------------------------------------------------------------------

# Atomic / always-both-read-and-write regardless of operand position.
ATOMIC_RMW = {'xchg', 'xadd', 'cmpxchg', 'cmpxchg8b', 'cmpxchg16b'}
# Memory destination is both read and written.
RMW_OPS = {
    'add', 'sub', 'or', 'and', 'xor', 'inc', 'dec', 'adc', 'sbb', 'not', 'neg',
    'shl', 'shr', 'sal', 'sar', 'rol', 'ror', 'rcl', 'rcr', 'shld', 'shrd',
    'bts', 'btr', 'btc',
}
# Implicit-accumulator arithmetic: reads memory, writes only registers.
READ_ONLY_ARITH = {'mul', 'imul', 'div', 'idiv'}
# Pure-compare mnemonics: read the memory operand, write nothing.
COMPARE_OPS = {'cmp', 'test', 'bt'}
# Instruction-prefix tokens objdump prints as a separate leading word.
INSN_PREFIXES = {'lock', 'rep', 'repe', 'repz', 'repne', 'repnz', 'bnd', 'notrack'}

KNOWN_STEMS = (ATOMIC_RMW | RMW_OPS | READ_ONLY_ARITH | COMPARE_OPS |
               {'lea', 'push', 'pop', 'call', 'jmp', 'ret', 'nop'})

JCC_RE = re.compile(r'^j(?!mp)[a-z]+$')
X87_STORE_RE = re.compile(r'^(fst|fist|fisttp|fnst|fxsave|fnsave|fsave)')
ASSIGN_PREFIXES = ('mov', 'vmov', 'pextr', 'vpextr', 'extractps', 'vextract', 'stmxcsr')

DATA_SECTION_PREFIXES = ('.data', '.bss', '.rodata', '.init.data', '.ro_after_init')

# Instructions that clobber implicit registers (rax/rdx/rcx/...): drop all
# register-tracking state rather than model each one.
CLOBBER_ALL_STEMS = {'mul', 'div', 'idiv', 'cltd', 'cqto', 'cltq', 'cwtl', 'cpuid',
                     'rdmsr', 'rdtsc', 'rdtscp', 'syscall', 'sysenter', 'xgetbv'}
NO_REG_WRITE_STEMS = COMPARE_OPS | {'push', 'jmp', 'call', 'ret', 'nop'}


def lookup_stem(m):
    """Normalise a mnemonic to its table stem: exact hit first, then one
    trailing size letter stripped (orl->or, callq->call, btsl->bts). Exact
    first keeps 'shl'/'sal'/'rcl' from being mangled."""
    if m in KNOWN_STEMS:
        return m
    if len(m) > 1 and m[-1] in 'bwlq' and m[:-1] in KNOWN_STEMS:
        return m[:-1]
    return m


def is_assign(m):
    return m.startswith(ASSIGN_PREFIXES)


def is_mem_operand(op):
    op = op.strip()
    if op.startswith('*'):
        op = op[1:]
    if '(' in op:
        return True
    if re.match(r'^%[a-z]s:', op):
        return True
    if re.match(r'^-?0x[0-9a-fA-F]+$', op):
        return True
    return False


def is_imm_operand(op):
    return op.strip().startswith('$')


def split_operands(operand_str):
    """Split AT&T-syntax operand list on top-level commas, respecting
    parenthesis nesting (SIB forms like '0x0(,%rbx,8)' contain commas)."""
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


def strip_prefixes(mnemonic, operand_str):
    """objdump prints 'lock cmpxchg %eax,0x0(%rip)' with the prefix as the
    apparent mnemonic and the real instruction as the first 'operand'.
    Returns (real_mnemonic, real_operands, [prefixes])."""
    prefixes = []
    while mnemonic.lower() in INSN_PREFIXES:
        parts = operand_str.split(None, 1)
        if not parts:
            break
        prefixes.append(mnemonic.lower())
        mnemonic = parts[0]
        operand_str = parts[1] if len(parts) > 1 else ''
    return mnemonic, operand_str, prefixes


def strip_prefix(mnemonic, operand_str):
    m, o, _ = strip_prefixes(mnemonic, operand_str)
    return m, o


def is_branch(m):
    stem = lookup_stem(m)
    return stem in ('call', 'jmp') or bool(JCC_RE.match(m))


def _classify_core(m, operand_str, role):
    stem = lookup_stem(m)
    ops = split_operands(operand_str)

    if is_branch(m):
        if ops and ops[0].startswith('*'):
            # call/jmp through memory: reads a global function pointer
            # or jump table. NOT a plain CALL (that is a direct call).
            return 'INDIRECT_CALL_READ' if is_mem_operand(ops[0]) else 'UNKNOWN'
        return 'CALL'
    if role == 'branch':
        return 'CALL'
    if role == 'imm':
        return 'ADDR'            # symbol address used as a constant
    if stem == 'lea':
        return 'ADDR'

    if not any(is_mem_operand(o) for o in ops):
        return 'UNKNOWN'

    # Atomics BEFORE compares: 'cmpxchg' must never fall into 'cmp'.
    if stem in ATOMIC_RMW:
        return 'RMW'
    if stem in COMPARE_OPS:
        return 'LOAD'
    if stem == 'push':
        return 'LOAD'
    if stem == 'pop':
        return 'STORE'
    if stem in READ_ONLY_ARITH:
        return 'LOAD'
    if m.startswith('f'):
        return 'STORE' if X87_STORE_RE.match(m) else 'LOAD'
    if m.startswith('prefetch'):
        return 'LOAD'
    if m.startswith('set'):
        return 'STORE'

    if len(ops) == 1:
        return 'RMW' if stem in RMW_OPS else 'UNKNOWN'

    if is_mem_operand(ops[-1]):
        # Memory destination. Immediate sources do NOT imply a plain
        # store: 'addl $1, g(%rip)' reads and writes g.
        if stem in RMW_OPS:
            return 'RMW'
        if is_assign(m):
            return 'STORE'
        return 'UNKNOWN'
    return 'LOAD'


def classify_instruction(mnemonic, operand_str, role='mem'):
    """Return STORE / LOAD / ADDR / RMW / CALL / INDIRECT_CALL_READ / UNKNOWN.

    role says which operand of the instruction the relocation sits on:
      'mem'    -- the memory operand (displacement field)
      'imm'    -- the immediate operand (address-as-constant => ADDR)
      'branch' -- a direct call/jmp target
    The role is decided from relocation byte offsets (see reloc_role), not
    from relocation order."""
    mnemonic, operand_str, prefixes = strip_prefixes(mnemonic, operand_str)
    acc = _classify_core(mnemonic.lower(), operand_str, role)
    if 'lock' in prefixes and acc == 'STORE':
        acc = 'RMW'
    return acc


def has_guard_hint(mnemonic, operand_str):
    mnemonic, _, _ = strip_prefixes(mnemonic, operand_str)
    return lookup_stem(mnemonic.lower()) in COMPARE_OPS


# --------------------------------------------------------------------
# Relocation helpers
# --------------------------------------------------------------------

SYM_HEAD_RE = re.compile(r'^([A-Za-z_.$][\w.$]*)')
ADDEND_RE = re.compile(r'([+-])0x([0-9a-fA-F]+)\s*$')


def base_symbol(symexpr):
    m = SYM_HEAD_RE.match(symexpr.strip())
    return m.group(1) if m else symexpr.strip()


def parse_sym_addend(symexpr):
    """'foo+0x10' -> ('foo', 16); 'foo' -> ('foo', 0)."""
    symexpr = symexpr.strip()
    sym = base_symbol(symexpr)
    rest = symexpr[len(sym):] if symexpr.startswith(sym) else ''
    m = ADDEND_RE.search(rest)
    addend = 0
    if m:
        addend = int(m.group(2), 16)
        if m.group(1) == '-':
            addend = -addend
    return sym, addend


def reloc_field_size(rtype):
    t = rtype.replace('R_X86_64_', '')
    if t in ('64', 'PC64', 'GOT64', 'GOTOFF64', 'GOTPC64', 'GOTPLT64', 'PLTOFF64'):
        return 8
    if t in ('8', 'PC8'):
        return 1
    if t in ('16', 'PC16'):
        return 2
    return 4


def reloc_is_pcrel(rtype):
    t = rtype.replace('R_X86_64_', '')
    return t.startswith('PC') or t.startswith('PLT') or 'PCREL' in t or t.startswith('GOTPC')


def imm_size_from_mnemonic(m):
    """Fallback immediate width from the AT&T size suffix, used only when
    the instruction length is unknown (last instruction of a function)."""
    m = m.lower()
    if lookup_stem(m) != m and m[-1] in 'bwlq':
        return {'b': 1, 'w': 2}.get(m[-1], 4)
    if m[-1:] in ('b', 'w') and m[:-1] in KNOWN_STEMS:
        return {'b': 1, 'w': 2}[m[-1]]
    return 4


def insn_end(insn):
    return None if insn.get('length') is None else insn['addr'] + insn['length']


def trailing_bytes(insn, field_end):
    """Bytes of the instruction encoding after the relocation field."""
    end = insn_end(insn)
    if end is not None:
        return max(end - field_end, 0)
    mn, ops, _ = strip_prefixes(insn['mnemonic'], insn['ops'])
    if any(is_imm_operand(o) for o in split_operands(ops)):
        return imm_size_from_mnemonic(mn)
    return 0


def reloc_role(insn, rel, idx):
    """Which operand does this relocation belong to: 'branch' / 'mem' / 'imm'.

    Decided from byte offsets: an instruction's immediate is encoded last,
    so with both a memory operand and an immediate, a relocation whose
    field ends exactly at the instruction end is on the immediate, any
    other is on the displacement. Falls back to relocation order only when
    the instruction length is unknown."""
    mn, ops_s, _ = strip_prefixes(insn['mnemonic'], insn['ops'])
    ops = split_operands(ops_s)
    if is_branch(mn):
        return 'mem' if (ops and ops[0].startswith('*')) else 'branch'
    has_imm = any(is_imm_operand(o) for o in ops)
    has_mem = any(is_mem_operand(o) for o in ops)
    if not has_imm:
        return 'mem'
    if not has_mem:
        return 'imm'
    fsize = reloc_field_size(rel['rtype'])
    end = insn_end(insn)
    if end is not None:
        return 'imm' if rel['off'] + fsize == end else 'mem'
    if reloc_is_pcrel(rel['rtype']):
        return 'mem'
    return 'mem' if idx == 0 else 'imm'


def reloc_target_offset(insn, rel, addend):
    """Byte offset inside the target symbol/section that the instruction
    actually addresses. PC-relative: S + A - P + RIP, with RIP = end of the
    instruction, so offset = A + field_size + trailing_bytes."""
    fsize = reloc_field_size(rel['rtype'])
    if reloc_is_pcrel(rel['rtype']):
        return addend + fsize + trailing_bytes(insn, rel['off'] + fsize)
    return addend


# --------------------------------------------------------------------
# Registers and memory operands (for intra-function tracking)
# --------------------------------------------------------------------

REG_FAMILY = {}
for _l in 'abcd':
    for _n in ('r%sx', 'e%sx', '%sx', '%sl', '%sh'):
        REG_FAMILY[_n % _l] = 'r%sx' % _l
for _s in ('si', 'di', 'bp', 'sp'):
    for _n in ('r' + _s, 'e' + _s, _s, _s + 'l'):
        REG_FAMILY[_n] = 'r' + _s
for _i in range(8, 16):
    for _suf in ('', 'd', 'w', 'b'):
        REG_FAMILY['r%d%s' % (_i, _suf)] = 'r%d' % _i
CALLER_SAVED = {'r%sx' % c for c in 'acd'} | {'rsi', 'rdi', 'r8', 'r9', 'r10', 'r11'}

MEM_RE = re.compile(
    r'^\*?(?:%[a-z]s:)?(-?0x[0-9a-fA-F]+|-?\d+)?\((%\w+)?(?:,(%\w+))?(?:,\d)?\)$')


def reg_family(op):
    op = op.strip()
    if op.startswith('%'):
        return REG_FAMILY.get(op[1:])
    return None


def parse_mem(op):
    """-> (disp, base_family, has_index) for 'disp(%base,%idx,scale)'."""
    m = MEM_RE.match(op.strip())
    if not m:
        return None
    disp = int(m.group(1), 0) if m.group(1) else 0
    base = REG_FAMILY.get(m.group(2)[1:]) if m.group(2) else None
    return disp, base, bool(m.group(3))


def parse_int(s):
    s = s.strip().lstrip('$')
    try:
        return int(s, 0)
    except ValueError:
        return None


# --------------------------------------------------------------------
# readelf / symbol tables
# --------------------------------------------------------------------

def run(cmd):
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       universal_newlines=True)
    return p.stdout


SEC_HDR_RE = re.compile(
    r'^\s*\[\s*(\d+)\]\s+(\S+)'
    r'(?:\s+\S+\s+[0-9a-fA-F]+\s+[0-9a-fA-F]+\s+([0-9a-fA-F]+)\s+[0-9a-fA-F]+\s+([A-Za-z]*)\s*\d+\s+\d+\s+\d+)?')
SYM_ROW_RE = re.compile(
    r'^\s*\d+:\s+([0-9a-fA-F]+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s*(.*)$'
)


def is_x86_64(obj_path):
    out = run(['readelf', '-h', obj_path])
    for line in out.splitlines():
        if line.strip().startswith('Machine:'):
            return 'X86-64' in line.upper()
    return False


def parse_object_symbols(obj_path):
    """Returns (symbols, section_sizes). symbols: list of {name, section,
    size, bind, value, flags} for OBJECT symbols defined (not UND) in this object,
    local ones included. section_sizes: {section name: size}."""
    sec_out = run(['readelf', '-SW', obj_path])
    idx2name = {}
    sizes = {}
    flags = {}
    for line in sec_out.splitlines():
        m = SEC_HDR_RE.match(line)
        if m:
            idx2name[int(m.group(1))] = m.group(2)
            if m.group(3):
                sizes[m.group(2)] = max(sizes.get(m.group(2), 0), int(m.group(3), 16))
                flags[m.group(2)] = ''.join(sorted(set(flags.get(m.group(2), '') + (m.group(4) or ''))))

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
            # ELF section flags (W=writable, A=alloc, ...). COMMON has no
            # section: it is writable by definition.
            'flags': 'WA' if section == 'COMMON' else flags.get(section, ''),
        })
    return syms, sizes


def parse_symbols(obj_path):
    return parse_object_symbols(obj_path)[0]


class SymbolRanges(object):
    """(section, byte offset) -> containing OBJECT symbol, by exact range.

    Never guesses: zero-size symbols match only at their exact offset,
    offsets past the section end are rejected, and two *different*
    overlapping ranges make the lookup ambiguous (None). Aliases (identical
    value+size) are one object; GLOBAL binding wins, then name order."""

    def __init__(self, symbols, section_sizes=None):
        self.sizes = section_sizes or {}
        self.binds = {}
        self.by_sec = defaultdict(list)
        for s in symbols:
            prev = self.binds.get(s['name'])
            if prev is None or (prev != 'GLOBAL' and s['bind'] == 'GLOBAL'):
                self.binds[s['name']] = s['bind']
            self.by_sec[s['section']].append((s['value'], s['size'], s['name'], s['bind']))
        self.values = {}
        self.max_end = {}
        for sec, ents in self.by_sec.items():
            ents.sort()
            self.values[sec] = [e[0] for e in ents]
            run_max, ends = 0, []
            for e in ents:
                run_max = max(run_max, e[0] + e[1])
                ends.append(run_max)
            self.max_end[sec] = ends

    def bind_of(self, name):
        """Linkage of `name` as seen from this object: LOCAL / GLOBAL / WEAK
        when this object defines it as an OBJECT, else 'EXT' (resolved by
        the linker across objects, or not an OBJECT). match.py uses this to
        stop same-named statics in different files from being one symbol."""
        return self.binds.get(name, 'EXT')

    def lookup(self, section, offset):
        """-> (name, symbol_value) or None."""
        ents = self.by_sec.get(section)
        if not ents or offset < 0:
            return None
        limit = self.sizes.get(section)
        if limit is not None and limit and offset >= limit:
            return None
        i = bisect.bisect_right(self.values[section], offset) - 1
        sized, zero = [], []
        while i >= 0 and self.max_end[section][i] > offset:
            value, size, name, bind = ents[i]
            if size > 0 and value <= offset < value + size:
                sized.append(ents[i])
            i -= 1
        for e in ents[bisect.bisect_left(self.values[section], offset):
                      bisect.bisect_right(self.values[section], offset)]:
            if e[1] == 0:
                zero.append(e)
        cands = sized or zero
        if not cands:
            return None
        ranges = set((c[0], c[1]) for c in cands)
        if len(ranges) > 1:
            return None   # ambiguous overlap: keep unresolved
        cands.sort(key=lambda c: (c[3] != 'GLOBAL', c[2]))
        return cands[0][2], cands[0][0]


# --------------------------------------------------------------------
# Instruction-stream pass
# --------------------------------------------------------------------

SECTION_HDR_RE = re.compile(r'^Disassembly of section (\S+):$')
FUNC_HDR_RE = re.compile(r'^[0-9a-f]+\s+<([^>]+)>:$')
SRCLINE_RE = re.compile(r'^(/\S+\.[a-zA-Z]+):(\d+)(?:\s+\(discriminator \d+\))?$')
INSN_RE = re.compile(r'^\s*([0-9a-f]+):\t(.*)$')
RELOC_RE = re.compile(r'^\s*([0-9a-f]+):\s+(R_X86_64_\S+)\s+(.+)$')
BRANCH_TARGET_RE = re.compile(r'^\s*([0-9a-f]+)\s+<')

SECTION_NAME_RE = re.compile(r'^\.[\w.]*$')


def is_section_name(sym):
    """True for a SECTION name (.text, .bss, .data..percpu, ...) rather
    than a symbol. Relocations against `static` objects are emitted
    section-relative; they are resolved to the containing symbol via
    SymbolRanges instead of being dropped. No real C identifier begins
    with '.', so this check is exact."""
    return bool(SECTION_NAME_RE.match(sym))


def _resolve_target(sym, off, resolver):
    """Section-relative -> named symbol + offset within it. Returns
    (sym, off) or None when it cannot be resolved to an OBJECT symbol."""
    if not is_section_name(sym):
        return sym, off
    if resolver is None or sym.startswith(('.text', '.init.text', '.exit.text')):
        return None
    hit = resolver.lookup(sym, off)
    if hit is None:
        return None
    name, value = hit
    return name, off - value


IND_ACCESS = {'LOAD': 'IND_LOAD', 'STORE': 'IND_STORE', 'RMW': 'IND_RMW'}


def _mk_ref(sym, obj_rel, func, section, access, rtype, insn, off, field):
    return {
        'sym': sym, 'obj': obj_rel, 'func': func or '', 'func_section': section or '',
        'access': access, 'reloc_type': rtype, 'src_file': insn['src_file'],
        'src_line': insn['src_line'], 'insn': insn['raw'],
        'addr': '%x' % insn['addr'], 'off': off, 'field': field,
        'sym_bind': '', 'guard': '',
    }


def _loaded_value_tested(insns, i, targets, limit=12):
    """True when insns[i] loads the global into a register and, in the
    straight-line code that follows, that register is tested against zero
    and a conditional jump consumes the result:

        mov g(%rip),%rax ; test %rax,%rax ; je ...
        mov g(%rip),%rax ; cmp $0x0,%rax  ; jne ...

    This is the common NULL-check-on-a-hook-pointer shape, and it catches
    the 'copy to a local, then check the local' case that a compare against
    the global itself cannot. It is evidence, not proof: it does not show
    the check dominates the use (that needs a CFG), so it stops at branch
    targets, calls, jumps and any redefinition of the register."""
    mn, ops_s, _ = strip_prefixes(insns[i]['mnemonic'], insns[i]['ops'])
    ops = split_operands(ops_s)
    if len(ops) != 2 or not mn.lower().startswith('mov') or not is_mem_operand(ops[0]):
        return False
    fam = reg_family(ops[1])
    if fam is None:
        return False
    for j in range(i + 1, min(i + 1 + limit, len(insns))):
        nxt = insns[j]
        if nxt['addr'] in targets:
            return False
        mn2, o2, _ = strip_prefixes(nxt['mnemonic'], nxt['ops'])
        m2 = mn2.lower()
        st = lookup_stem(m2)
        ops2 = split_operands(o2)
        zero_test = (
            (st == 'test' and len(ops2) == 2 and reg_family(ops2[0]) == fam
             and reg_family(ops2[1]) == fam) or
            (st == 'cmp' and len(ops2) == 2 and is_imm_operand(ops2[0])
             and parse_int(ops2[0]) == 0 and reg_family(ops2[1]) == fam))
        if zero_test:
            return j + 1 < len(insns) and bool(JCC_RE.match(insns[j + 1]['mnemonic'].lower()))
        if is_branch(m2) or st == 'ret' or st in CLOBBER_ALL_STEMS:
            return False
        if ops2 and reg_family(ops2[-1]) == fam and st not in NO_REG_WRITE_STEMS:
            return False
    return False


def refs_for_function(insns, obj_rel, func, section, resolver=None, fieldfn=None):
    """Classify every relocation of one function's instructions and run
    the intra-function register tracker. Returns (refs, unclassified,
    n_dropped_section_relative)."""
    refs, unclassified = [], []
    dropped = 0

    targets = set()
    for ins in insns:
        mn, ops_s, _ = strip_prefixes(ins['mnemonic'], ins['ops'])
        if is_branch(mn):
            m = BRANCH_TARGET_RE.match(ops_s)
            if m:
                targets.add(int(m.group(1), 16))

    state = {}   # register family -> (sym, off)

    for i, ins in enumerate(insns):
        if ins['addr'] in targets:
            state.clear()
        mn, ops_s, _ = strip_prefixes(ins['mnemonic'], ins['ops'])
        mnl = mn.lower()
        stem = lookup_stem(mnl)
        ops = split_operands(ops_s)

        # ---- direct relocations -------------------------------------
        resolved = []   # (role, sym, off) of relocs that resolved
        for idx, rel in enumerate(ins['relocs']):
            sym, addend = parse_sym_addend(rel['symexpr'])
            off = reloc_target_offset(ins, rel, addend)
            role = reloc_role(ins, rel, idx)
            tgt = _resolve_target(sym, off, resolver)
            if tgt is None:
                dropped += 1
                continue
            sym, off = tgt
            access = classify_instruction(ins['mnemonic'], ins['ops'], role)
            if access == 'LOAD' and has_guard_hint(ins['mnemonic'], ins['ops']):
                access = 'LOAD_GUARD'
            if access == 'UNKNOWN':
                unclassified.append('%s\t%s\t%s\t%s' % (obj_rel, func, ins['mnemonic'], ins['raw']))
            field = fieldfn(sym, off) if (fieldfn and access != 'CALL') else ''
            ref = _mk_ref(sym, obj_rel, func, section, access, rel['rtype'], ins, off, field)
            if access == 'LOAD_GUARD':
                ref['guard'] = 'cmp_mem'
            elif access == 'LOAD' and role == 'mem' and _loaded_value_tested(insns, i, targets):
                ref['guard'] = 'reg_test'
            refs.append(ref)
            resolved.append((role, sym, off))

        have_mem_reloc = any(r[0] == 'mem' for r in resolved)

        # ---- indirect accesses through tracked registers ------------
        if state and not have_mem_reloc and stem not in ('lea', 'nop') and not is_branch(mnl):
            for op in ops:
                pm = parse_mem(op) if is_mem_operand(op) else None
                if not pm or pm[1] not in state:
                    continue
                access = IND_ACCESS.get(classify_instruction(ins['mnemonic'], ins['ops'], 'mem'))
                if access is None:
                    continue
                tsym, toff = state[pm[1]]
                off = toff + pm[0]
                field = fieldfn(tsym, off) if fieldfn else ''
                refs.append(_mk_ref(tsym, obj_rel, func, section, access, 'INDIRECT', ins, off, field))
                break

        # ---- update tracking state ----------------------------------
        if is_branch(mnl):
            if stem == 'call':
                for fam in CALLER_SAVED:
                    state.pop(fam, None)
            elif stem == 'jmp':
                state.clear()
            continue
        if stem == 'ret':
            state.clear()
            continue
        if stem in CLOBBER_ALL_STEMS:
            state.clear()
            continue
        if stem == 'imul' and len(ops) == 1:
            state.clear()
            continue
        if stem == 'cmpxchg':
            state.pop('rax', None)
        if stem in ATOMIC_RMW:
            for o in ops:
                fam = reg_family(o)
                if fam:
                    state.pop(fam, None)
            continue
        if stem in NO_REG_WRITE_STEMS or not ops:
            continue
        dst = reg_family(ops[-1])
        if dst is None:
            continue
        new = None
        src = ops[0]
        if stem == 'lea' and len(ops) == 2:
            direct = [r for r in resolved if r[0] == 'mem']
            pm = parse_mem(src)
            if direct:
                new = (direct[0][1], direct[0][2])
            elif pm and pm[1] in state and not pm[2]:
                new = (state[pm[1]][0], state[pm[1]][1] + pm[0])
        elif mnl.startswith(('mov', 'movabs')) and len(ops) == 2 and mnl in ('mov', 'movq', 'movabs', 'movabsq'):
            imm = [r for r in resolved if r[0] == 'imm']
            sfam = reg_family(src)
            if imm and is_imm_operand(src):
                new = (imm[0][1], imm[0][2])
            elif sfam in state and sfam is not None:
                new = state[sfam]
        elif stem in ('add', 'sub') and len(ops) == 2 and dst in state and is_imm_operand(src):
            n = parse_int(src)
            if n is not None:
                s, o = state[dst]
                new = (s, o + n if stem == 'add' else o - n)
        if new is not None:
            state[dst] = new
        else:
            state.pop(dst, None)

    return refs, unclassified, dropped


def parse_text_refs(obj_path, obj_rel, resolver=None, fieldfn=None):
    """Instruction-stream relocations via `objdump -dr -l`."""
    out = run(['objdump', '-dr', '-l', '--no-show-raw-insn', obj_path])
    section = None
    func = None
    src_file = ''
    src_line = 0
    insns = []
    refs, unclassified = [], []
    n_dropped = 0

    def flush():
        nonlocal n_dropped
        if insns:
            r, u, d = refs_for_function(insns, obj_rel, func, section, resolver, fieldfn)
            refs.extend(r)
            unclassified.extend(u)
            n_dropped += d
            del insns[:]

    for line in out.splitlines():
        m = SECTION_HDR_RE.match(line)
        if m:
            flush()
            section = m.group(1)
            func = None
            continue
        m = FUNC_HDR_RE.match(line)
        if m:
            flush()
            func = m.group(1)
            continue
        m = SRCLINE_RE.match(line)
        if m:
            src_file, src_line = m.group(1), int(m.group(2))
            continue
        m = RELOC_RE.match(line)
        if m:
            if insns:
                insns[-1]['relocs'].append({
                    'off': int(m.group(1), 16), 'rtype': m.group(2),
                    'symexpr': m.group(3).strip()})
            continue
        m = INSN_RE.match(line)
        if m:
            addr = int(m.group(1), 16)
            if insns and addr > insns[-1]['addr']:
                insns[-1]['length'] = addr - insns[-1]['addr']
            rest_no_comment = m.group(2).split('#')[0].strip()
            parts = rest_no_comment.split(None, 1)
            insns.append({
                'addr': addr, 'length': None,
                'mnemonic': parts[0] if parts else '',
                'ops': parts[1] if len(parts) > 1 else '',
                'raw': rest_no_comment, 'relocs': [],
                'src_file': src_file, 'src_line': src_line,
            })
            continue
    flush()
    if resolver is not None:
        for r in refs:
            r['sym_bind'] = resolver.bind_of(r['sym'])
    return refs, unclassified, n_dropped


# --------------------------------------------------------------------
# Data-section pass
# --------------------------------------------------------------------

RELOC_HDR_RE = re.compile(r'^RELOCATION RECORDS FOR \[(\S+)\]:$')
RELOC_ROW_RE = re.compile(r'^([0-9a-f]+)\s+(\S+)\s+(.+)$')


def parse_data_refs(obj_path, obj_rel, resolver, fieldfn=None):
    """Data-section relocations via `objdump -r` -- these never show up in
    `objdump -d`. DATAREF is a *static initialiser*, never a runtime
    write. The container symbol (struct/array holding the pointer) is
    resolved by exact range; an ambiguous or missing owner is kept as
    '@section+0xoff' instead of being guessed."""
    out = run(['objdump', '-r', obj_path])
    sec = None
    refs = []
    n_dropped = 0
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
        sym, addend = parse_sym_addend(symexpr)
        tgt = _resolve_target(sym, addend, resolver)
        if tgt is None:
            n_dropped += 1
            continue
        sym, toff = tgt
        offset = int(offset_s, 16)
        hit = resolver.lookup(sec, offset) if resolver else None
        container = hit[0] if hit else None
        field = fieldfn(container, offset - hit[1]) if (fieldfn and hit) else ''
        refs.append({
            'sym': sym, 'obj': obj_rel, 'func': container or '@%s+0x%x' % (sec, offset),
            'func_section': sec, 'access': 'DATAREF', 'reloc_type': reloc_type,
            'src_file': '', 'src_line': 0, 'insn': '',
            'addr': '%x' % offset, 'off': toff, 'field': field,
            'sym_bind': resolver.bind_of(sym) if resolver else '', 'guard': '',
        })
    return refs, n_dropped


def find_objects(root, subdirs, exclude_rel=None):
    """exclude_rel: set of root-relative paths to skip -- kbuild produces
    both per-source-file objects (from CC) and composite module-link
    objects (from `ld -r`). The composite object's symbols and relocations
    are a strict duplicate of its members' -- scanning it too double-counts
    every site. Exclude it; only individual per-TU objects are analysed."""
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


# --------------------------------------------------------------------
# Self test (labeled instruction table; reports per-class precision/recall)
# --------------------------------------------------------------------

LABELED = [
    # (mnemonic, operands, role, expected access, expected guard hint)
    ('cmpxchg', '%edx,0x0(%rip)', 'mem', 'RMW', False),
    ('cmpxchgq', '%rdx,0x0(%rip)', 'mem', 'RMW', False),
    ('lock', 'cmpxchg %edx,0x0(%rip)', 'mem', 'RMW', False),
    ('lock', 'incl 0x0(%rip)', 'mem', 'RMW', False),
    ('xchg', '%eax,0x0(%rip)', 'mem', 'RMW', False),
    ('xaddl', '%eax,0x0(%rip)', 'mem', 'RMW', False),
    ('cmpl', '$0x0,0x0(%rip)', 'mem', 'LOAD', True),
    ('cmpq', '$0x0,0x0(%rip)', 'mem', 'LOAD', True),
    ('testb', '%al,0x0(%rip)', 'mem', 'LOAD', True),
    ('bt', '%eax,0x0(%rip)', 'mem', 'LOAD', True),
    ('btl', '$0x3,0x0(%rip)', 'mem', 'LOAD', True),
    ('btsl', '$0x3,0x0(%rip)', 'mem', 'RMW', False),
    ('btr', '%eax,0x0(%rip)', 'mem', 'RMW', False),
    ('btcq', '$0x1,0x0(%rip)', 'mem', 'RMW', False),
    ('orl', '$0x1,0x0(%rip)', 'mem', 'RMW', False),
    ('orb', '$0x1,0x0(%rip)', 'mem', 'RMW', False),
    ('addl', '$0x1,0x0(%rip)', 'mem', 'RMW', False),
    ('andq', '$0xfffffffffffffffe,0x0(%rip)', 'mem', 'RMW', False),
    ('addl', '%eax,0x0(%rip)', 'mem', 'RMW', False),
    ('add', '0x0(%rip),%eax', 'mem', 'LOAD', False),
    ('movl', '$0x1,0x0(%rip)', 'mem', 'STORE', False),
    ('movq', '$0x0,0x0(%rip)', 'mem', 'STORE', False),
    ('movq', '$0x0,0x0(%rip)', 'imm', 'ADDR', False),
    ('mov', '%eax,0x0(%rip)', 'mem', 'STORE', False),
    ('mov', '0x0(%rip),%eax', 'mem', 'LOAD', False),
    ('movzbl', '0x0(%rip),%eax', 'mem', 'LOAD', False),
    ('movss', '%xmm0,0x0(%rip)', 'mem', 'STORE', False),
    ('sete', '0x0(%rip)', 'mem', 'STORE', False),
    ('lea', '0x0(%rip),%rax', 'mem', 'ADDR', False),
    ('mov', '$0x0,%rax', 'imm', 'ADDR', False),
    ('call', '0 <foo>', 'branch', 'CALL', False),
    ('callq', '*0x0(%rip)', 'mem', 'INDIRECT_CALL_READ', False),
    ('call', '*0x0(,%rax,8)', 'mem', 'INDIRECT_CALL_READ', False),
    ('jmpq', '*0x0(,%rax,8)', 'mem', 'INDIRECT_CALL_READ', False),
    ('jne', '1a <f+0x1a>', 'branch', 'CALL', False),
    ('push', '0x0(%rip)', 'mem', 'LOAD', False),
    ('push', '$0x0', 'imm', 'ADDR', False),
    ('pop', '0x0(%rip)', 'mem', 'STORE', False),
    ('incl', '0x0(%rip)', 'mem', 'RMW', False),
    ('negq', '0x0(%rip)', 'mem', 'RMW', False),
    ('shll', '0x0(%rip)', 'mem', 'RMW', False),
    ('sarl', '%cl,0x0(%rip)', 'mem', 'RMW', False),
    ('mull', '0x0(%rip)', 'mem', 'LOAD', False),
    ('imul', '0x0(%rip),%eax', 'mem', 'LOAD', False),
    ('imul', '$0x4,0x0(%rip),%eax', 'mem', 'LOAD', False),
    ('fldl', '0x0(%rip)', 'mem', 'LOAD', False),
    ('fstpl', '0x0(%rip)', 'mem', 'STORE', False),
    ('prefetcht0', '0x0(%rip)', 'mem', 'LOAD', False),
    ('weirdop', '%eax,0x0(%rip)', 'mem', 'UNKNOWN', False),
]


def _mk_insn(addr, length, mnemonic, ops, relocs=()):
    return {'addr': addr, 'length': length, 'mnemonic': mnemonic, 'ops': ops,
            'raw': (mnemonic + ' ' + ops).strip(), 'src_file': '', 'src_line': 0,
            'relocs': [{'off': o, 'rtype': t, 'symexpr': s} for o, t, s in relocs]}


def self_test():
    failures = []
    stats = defaultdict(lambda: [0, 0, 0])   # class -> [tp, fp, fn]

    for mn, ops, role, expect, guard in LABELED:
        got = classify_instruction(mn, ops, role)
        g = has_guard_hint(mn, ops)
        if got == expect:
            stats[expect][0] += 1
        else:
            stats[expect][2] += 1
            stats[got][1] += 1
            failures.append('classify %s %s [%s]: got %s want %s' % (mn, ops, role, got, expect))
        if g != guard:
            failures.append('guard %s %s: got %s want %s' % (mn, ops, g, guard))

    def check(label, cond):
        if not cond:
            failures.append(label)

    # relocation field arithmetic / role by byte offset
    check('parse_sym_addend', parse_sym_addend('foo+0x10') == ('foo', 16) and
          parse_sym_addend('.bss-0x4') == ('.bss', -4) and parse_sym_addend('x') == ('x', 0))

    resolver = SymbolRanges(
        [{'name': 'cnt', 'section': '.bss', 'size': 4, 'bind': 'LOCAL', 'value': 0x20},
         {'name': 'arr', 'section': '.bss', 'size': 16, 'bind': 'GLOBAL', 'value': 0x30},
         {'name': 'arr_alias', 'section': '.bss', 'size': 16, 'bind': 'LOCAL', 'value': 0x30},
         {'name': 'ov_a', 'section': '.data', 'size': 8, 'bind': 'LOCAL', 'value': 0},
         {'name': 'ov_b', 'section': '.data', 'size': 8, 'bind': 'LOCAL', 'value': 4}],
        {'.bss': 0x40, '.data': 0x10})
    check('resolver exact', resolver.lookup('.bss', 0x20) == ('cnt', 0x20))
    check('resolver alias prefers GLOBAL', resolver.lookup('.bss', 0x34) == ('arr', 0x30))
    check('resolver gap', resolver.lookup('.bss', 0x24) is None)
    check('resolver past section end', resolver.lookup('.bss', 0x40) is None)
    check('resolver ambiguous overlap', resolver.lookup('.data', 5) is None)

    # `movq $fn, g(%rip)`: two relocations, disp then imm
    insns = [_mk_insn(0, 11, 'movq', '$0x0,0x0(%rip)',
                      [(3, 'R_X86_64_PC32', 'g-0x8'), (7, 'R_X86_64_32S', 'fn')])]
    r, _, _ = refs_for_function(insns, 'x.o', 'f', '.text')
    check('two-reloc store', [(x['sym'], x['access'], x['off']) for x in r] ==
          [('g', 'STORE', 0), ('fn', 'ADDR', 0)])

    # `addl $1, g(%rip)` => RMW, offset 0
    insns = [_mk_insn(0, 7, 'addl', '$0x1,0x0(%rip)', [(2, 'R_X86_64_PC32', 'g-0x5')])]
    r, _, _ = refs_for_function(insns, 'x.o', 'f', '.text')
    check('addl imm rmw', [(x['access'], x['off']) for x in r] == [('RMW', 0)])

    # absolute single reloc on the immediate of `movq $fn, 0x8(%rax)`: ADDR
    insns = [_mk_insn(0, 8, 'movq', '$0x0,0x8(%rax)', [(4, 'R_X86_64_32S', 'fn')])]
    r, _, _ = refs_for_function(insns, 'x.o', 'f', '.text')
    check('imm-only reloc is ADDR', [x['access'] for x in r] == ['ADDR'])

    # section-relative `mov .bss+0x1c(%rip),%eax` => load of cnt
    insns = [_mk_insn(0, 6, 'mov', '0x0(%rip),%eax', [(2, 'R_X86_64_PC32', '.bss+0x1c')])]
    r, _, d = refs_for_function(insns, 'x.o', 'f', '.text', resolver)
    check('section-relative resolved', [(x['sym'], x['access'], x['off']) for x in r] == [('cnt', 'LOAD', 0)] and d == 0)
    r, _, d = refs_for_function(
        [_mk_insn(0, 6, 'mov', '0x0(%rip),%eax', [(2, 'R_X86_64_PC32', '.rodata.str1.1-0x4')])],
        'x.o', 'f', '.text', resolver)
    check('unresolvable section-relative counted', r == [] and d == 1)

    # guard hint on a LOAD from a compare
    insns = [_mk_insn(0, 7, 'cmpl', '$0x0,0x0(%rip)', [(2, 'R_X86_64_PC32', 'g-0x5')])]
    r, _, _ = refs_for_function(insns, 'x.o', 'f', '.text')
    check('guard', [x['access'] for x in r] == ['LOAD_GUARD'])

    # indirect call through a global pointer
    insns = [_mk_insn(0, 6, 'callq', '*0x0(%rip)', [(2, 'R_X86_64_PC32', 'handler-0x4')])]
    r, _, _ = refs_for_function(insns, 'x.o', 'f', '.text')
    check('indirect call read', [x['access'] for x in r] == ['INDIRECT_CALL_READ'])

    # register tracking: lea g -> store through reg -> clobber on call
    insns = [
        _mk_insn(0, 7, 'lea', '0x0(%rip),%rax', [(3, 'R_X86_64_PC32', 'g-0x4')]),
        _mk_insn(7, 4, 'mov', '%rdx,0x8(%rax)'),
        _mk_insn(11, 3, 'mov', '0x10(%rax),%rcx'),
        _mk_insn(14, 5, 'call', '0 <foo>', [(15, 'R_X86_64_PLT32', 'foo-0x4')]),
        _mk_insn(19, 3, 'mov', '(%rax),%rdx'),
    ]
    r, _, _ = refs_for_function(insns, 'x.o', 'f', '.text')
    ind = [(x['sym'], x['access'], x['off']) for x in r if x['access'].startswith('IND_')]
    check('register tracking', ind == [('g', 'IND_STORE', 8), ('g', 'IND_LOAD', 16)])
    check('lea stays ADDR', r[0]['access'] == 'ADDR')

    # tracking is cut at a branch target (merge point)
    insns = [
        _mk_insn(0, 7, 'lea', '0x0(%rip),%rax', [(3, 'R_X86_64_PC32', 'g-0x4')]),
        _mk_insn(7, 2, 'jne', 'd <f+0xd>'),
        _mk_insn(9, 4, 'mov', '%rdx,0x8(%rax)'),
        _mk_insn(13, 4, 'mov', '%rdx,0x8(%rax)'),
    ]
    r, _, _ = refs_for_function(insns, 'x.o', 'f', '.text')
    check('tracking reset at branch target',
          [x['access'] for x in r if x['access'].startswith('IND_')] == ['IND_STORE'])

    # loaded-value NULL test (hook-pointer pattern) vs. no test
    insns = [
        _mk_insn(0, 7, 'mov', '0x0(%rip),%rax', [(3, 'R_X86_64_PC32', 'hook-0x4')]),
        _mk_insn(7, 3, 'test', '%rax,%rax'),
        _mk_insn(10, 2, 'je', '20 <f+0x20>'),
    ]
    r, _, _ = refs_for_function(insns, 'x.o', 'f', '.text')
    check('reg_test guard', r[0]['guard'] == 'reg_test' and r[0]['access'] == 'LOAD')
    insns = [
        _mk_insn(0, 7, 'mov', '0x0(%rip),%rax', [(3, 'R_X86_64_PC32', 'hook-0x4')]),
        _mk_insn(7, 3, 'mov', '%rdx,%rax'),
        _mk_insn(10, 3, 'test', '%rax,%rax'),
        _mk_insn(13, 2, 'je', '20 <f+0x20>'),
    ]
    r, _, _ = refs_for_function(insns, 'x.o', 'f', '.text')
    check('reg_test killed by redefinition', r[0]['guard'] == '')
    r, _, _ = refs_for_function(
        [_mk_insn(0, 7, 'cmpl', '$0x0,0x0(%rip)', [(2, 'R_X86_64_PC32', 'g-0x5')])], 'x.o', 'f', '.text')
    check('cmp_mem guard', r[0]['guard'] == 'cmp_mem')

    # linkage lookup and readelf section-header parsing (flags)
    check('bind_of', resolver.bind_of('arr') == 'GLOBAL' and resolver.bind_of('cnt') == 'LOCAL'
          and resolver.bind_of('nosuch') == 'EXT')
    m1 = SEC_HDR_RE.match('  [ 5] .data..read_mostly PROGBITS 0000000000000000 000100 000010 00  WA  0   0 32')
    m2 = SEC_HDR_RE.match('  [ 6] .rodata          PROGBITS 0000000000000000 000200 000020 00   A  0   0 32')
    m3 = SEC_HDR_RE.match('  [ 7] .foo             PROGBITS 0000000000000000 000300 000020 00      0   0  1')
    check('section flags', m1 and m1.group(4) == 'WA' and m2 and m2.group(4) == 'A'
          and m3 and m3.group(4) == '' and int(m1.group(3), 16) == 16)

    print('class                      tp  fp  fn  precision  recall')
    for cls in sorted(stats):
        tp, fp, fn = stats[cls]
        p = tp / float(tp + fp) if tp + fp else 1.0
        rc = tp / float(tp + fn) if tp + fn else 1.0
        print('%-24s %4d %3d %3d  %8.2f  %6.2f' % (cls, tp, fp, fn, p, rc))
    if failures:
        print('\n%d FAILURE(S):' % len(failures))
        for f in failures:
            print('  ' + f)
        return 1
    print('\nall self-tests passed (%d labeled instructions)' % len(LABELED))
    return 0


# --------------------------------------------------------------------
# main
# --------------------------------------------------------------------

XREF_FIELDS = ['sym', 'obj', 'func', 'func_section', 'access', 'reloc_type',
               'src_file', 'src_line', 'insn', 'addr', 'off', 'field',
               'sym_bind', 'guard']


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--root', help='kernel source root (build dir)')
    ap.add_argument('--subdirs', nargs='+')
    ap.add_argument('--out')
    ap.add_argument('--exclude-file', default=None,
                    help='file of root-relative .o paths to skip (composite '
                         'module-link objects; see find_objects docstring)')
    ap.add_argument('--dwarf-fields', action='store_true',
                    help='fill the xref `field` column from DWARF struct layouts '
                         '(one readelf --debug-dump=info per object: slow)')
    ap.add_argument('--self-test', action='store_true',
                    help='run the labeled instruction table and exit')
    args = ap.parse_args()

    if args.self_test:
        sys.exit(self_test())
    if not (args.root and args.subdirs and args.out):
        ap.error('--root, --subdirs and --out are required')

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

    globals_f.write('sym\tobj\tsection\tsize\tbind\tvalue\tsec_flags\n')
    xref_f.write('\t'.join(XREF_FIELDS) + '\n')

    n_syms = 0
    n_refs = 0
    n_unclass = 0
    n_dropped = 0
    n_skipped_arch = 0
    by_access = defaultdict(int)

    for i, obj in enumerate(objs):
        obj_rel = os.path.relpath(obj, root)
        if not is_x86_64(obj):
            print(f'warning: {obj_rel} is not x86-64, skipped', file=sys.stderr)
            n_skipped_arch += 1
            continue
        syms, sec_sizes = parse_object_symbols(obj)
        for s in syms:
            globals_f.write(f"{s['name']}\t{obj_rel}\t{s['section']}\t{s['size']}\t{s['bind']}"
                            f"\t{s['value']}\t{s['flags']}\n")
            n_syms += 1
        resolver = SymbolRanges(syms, sec_sizes)

        fieldfn = None
        if args.dwarf_fields:
            from dwarf_layout import Layouts
            fieldfn = Layouts(obj).field_path

        text_refs, unclass, d1 = parse_text_refs(obj, obj_rel, resolver, fieldfn)
        data_refs, d2 = parse_data_refs(obj, obj_rel, resolver, fieldfn)
        n_dropped += d1 + d2

        for r in text_refs + data_refs:
            xref_f.write('\t'.join(str(r[k]) for k in XREF_FIELDS) + '\n')
            by_access[r['access']] += 1
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
          f'{n_dropped} section-relative relocations unresolvable to an '
          f'OBJECT symbol (dropped)', file=sys.stderr)
    if n_skipped_arch:
        print(f'  {n_skipped_arch} non-x86-64 objects skipped', file=sys.stderr)
    print('  by access: ' + ', '.join(f'{k}={v}' for k, v in sorted(by_access.items())),
          file=sys.stderr)


if __name__ == '__main__':
    main()
