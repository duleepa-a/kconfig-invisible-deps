#!/usr/bin/env python3
"""
dwarf_layout.py -- map (global variable, byte offset) to a struct-field path.

Stdlib-only parser of `readelf --debug-dump=info -W <obj>`. Used by
netdep.py (--dwarf-fields) to fill the `field` column of xref.tsv so that
a write to `state.enabled` and a read of `state.handler` are no longer
treated as accesses to the same thing (match.py --field-sensitive).

Field paths are relative to the variable: 'enabled', 'ops.handler',
'tbl[].cb'. Array indices are collapsed to '[]'. An empty string means
"unknown / whole object" -- callers must treat it as compatible with
everything (never guess).

Needs -g objects (CONFIG_DEBUG_INFO=y, which the README already requires).
Cost is one DWARF dump per object, which is why it is opt-in.
"""
import re
import subprocess

DIE_RE = re.compile(
    r'^\s*<(\d+)><([0-9a-fA-F]+)>:\s+Abbrev Number:\s+(\d+)(?:\s+\((DW_TAG_\w+)\))?')
ATTR_RE = re.compile(r'^\s*<[0-9a-fA-F]+>\s+(DW_AT_\w+)\s*:\s*(.*?)\s*$')

_TRANSPARENT = ('DW_TAG_typedef', 'DW_TAG_const_type', 'DW_TAG_volatile_type',
                'DW_TAG_restrict_type', 'DW_TAG_atomic_type')
_AGGREGATE = ('DW_TAG_structure_type', 'DW_TAG_union_type', 'DW_TAG_class_type')


class Die(object):
    __slots__ = ('off', 'tag', 'attrs', 'children')

    def __init__(self, off, tag):
        self.off = off
        self.tag = tag
        self.attrs = {}
        self.children = []


def _value(v):
    m = re.match(r'^\([^)]*\):\s*(.*)$', v)
    return m.group(1) if m else v


def _ref(v):
    m = re.match(r'^<0x([0-9a-fA-F]+)>', v)
    return int(m.group(1), 16) if m else None


def _int(v):
    m = re.match(r'^(0x[0-9a-fA-F]+|\d+)', v)
    if m:
        return int(m.group(1), 0)
    m = re.search(r'DW_OP_plus_uconst:\s*(\d+)', v)
    if m:
        return int(m.group(1))
    return None


class Layouts(object):
    """Lazy per-object DWARF type index."""

    def __init__(self, obj_path):
        self.obj_path = obj_path
        self._dies = None
        self._vars = None

    # -- parsing -----------------------------------------------------
    def _load(self):
        if self._dies is not None:
            return
        self._dies = {}
        self._vars = {}
        p = subprocess.run(['readelf', '--debug-dump=info', '-W', self.obj_path],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           universal_newlines=True)
        stack = {}
        cur = None
        for line in p.stdout.splitlines():
            m = DIE_RE.match(line)
            if m:
                depth, off, abbrev, tag = int(m.group(1)), int(m.group(2), 16), int(m.group(3)), m.group(4)
                if abbrev == 0 or not tag:
                    cur = None
                    continue
                cur = Die(off, tag)
                self._dies[off] = cur
                stack[depth] = cur
                if depth > 0 and (depth - 1) in stack:
                    stack[depth - 1].children.append(cur)
                continue
            m = ATTR_RE.match(line)
            if m and cur is not None:
                cur.attrs[m.group(1)] = _value(m.group(2))
        for die in self._dies.values():
            if die.tag == 'DW_TAG_variable' and 'DW_AT_name' in die.attrs:
                t = self._var_type_ref(die)
                if t is not None:
                    self._vars.setdefault(die.attrs['DW_AT_name'], t)

    def _var_type_ref(self, die):
        t = _ref(die.attrs.get('DW_AT_type', ''))
        if t is None and 'DW_AT_specification' in die.attrs:
            spec = self._dies.get(_ref(die.attrs['DW_AT_specification']))
            if spec is not None:
                t = _ref(spec.attrs.get('DW_AT_type', ''))
        return t

    # -- type helpers ------------------------------------------------
    def _strip(self, off, limit=16):
        die = self._dies.get(off)
        while die is not None and die.tag in _TRANSPARENT and limit > 0:
            die = self._dies.get(_ref(die.attrs.get('DW_AT_type', '')))
            limit -= 1
        return die

    def _size(self, off, depth=0):
        die = self._strip(off)
        if die is None or depth > 16:
            return None
        if 'DW_AT_byte_size' in die.attrs:
            return _int(die.attrs['DW_AT_byte_size'])
        if die.tag == 'DW_TAG_pointer_type':
            return 8
        if die.tag == 'DW_TAG_array_type':
            n = self._array_count(die)
            elt = _ref(die.attrs.get('DW_AT_type', ''))
            es = self._size(elt, depth + 1) if elt is not None else None
            if n is not None and es is not None:
                return n * es
        return None

    def _array_count(self, die):
        total = None
        for c in die.children:
            if c.tag != 'DW_TAG_subrange_type':
                continue
            if 'DW_AT_count' in c.attrs:
                n = _int(c.attrs['DW_AT_count'])
            elif 'DW_AT_upper_bound' in c.attrs:
                ub = _int(c.attrs['DW_AT_upper_bound'])
                n = None if ub is None else ub + 1
            else:
                n = None
            if n is None:
                return None
            total = n if total is None else total * n
        return total

    # -- public ------------------------------------------------------
    def field_path(self, var, offset):
        """Field path inside global `var` covering byte `offset`, or ''."""
        if offset is None or offset < 0:
            return ''
        self._load()
        t = self._vars.get(var)
        if t is None:
            return ''
        parts = []
        self._descend(t, offset, parts, 0)
        out = ''
        for p in parts:
            out += p if p == '[]' else ('.' + p if out else p)
        return out

    def _descend(self, type_off, offset, parts, depth):
        if depth > 12:
            return
        die = self._strip(type_off)
        if die is None:
            return
        if die.tag in _AGGREGATE:
            for mem in die.children:
                if mem.tag != 'DW_TAG_member':
                    continue
                loc = _int(mem.attrs.get('DW_AT_data_member_location', '0')) or 0
                mt = _ref(mem.attrs.get('DW_AT_type', ''))
                if mt is None:
                    continue
                size = self._size(mt)
                if size is None:
                    size = 1
                if loc <= offset < loc + max(size, 1):
                    name = mem.attrs.get('DW_AT_name')
                    if name:
                        parts.append(name)
                    self._descend(mt, offset - loc, parts, depth + 1)
                    return
        elif die.tag == 'DW_TAG_array_type':
            elt = _ref(die.attrs.get('DW_AT_type', ''))
            es = self._size(elt) if elt is not None else None
            if es:
                parts.append('[]')
                self._descend(elt, offset % es, parts, depth + 1)
