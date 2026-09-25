#!/usr/bin/env python3
"""
makefile_cond.py -- transitive (multi-level) Kconfig condition resolver
for a source file's compilation, walking the FULL Makefile hierarchy.

extract-makefile.awk (and filename.db built from it) only captures a
SINGLE level: for `foo-$(CONFIG_X) += bar.o`, it records bar.c's
condition as CONFIG_X and stops -- it never checks whether `foo.o` itself
is conditionally built. For a composite object (directory descend ->
composite .o -> named member), this silently drops every outer conjunct.

Concretely, for net/8021q/vlanproc.c:

    net/Makefile:        obj-y                    += 8021q/       (unconditional descent)
    net/8021q/Makefile:  obj-$(CONFIG_VLAN_8021Q)  += 8021q.o      (composite gate)
                          8021q-$(CONFIG_PROC_FS)   += vlanproc.o  (member gate)

    TRUE condition:      CONFIG_VLAN_8021Q AND CONFIG_PROC_FS
    filename.db reports only:  CONFIG_PROC_FS

This walks from the target file's own directory up to (and including) a
stop directory, chasing both WITHIN a single Makefile (member -> the
member-group's own `obj-` gate) and ACROSS directory levels (this
directory's descent condition in its parent's Makefile), ANDing every
conjunct found.

Deliberately independent of extract-makefile.awk/filename.db -- built
fresh after the vlan/sunrpc pernet candidates showed this exact gap
producing false positives.
"""
import os
import re
import sys
from functools import lru_cache

OBJ_LINE_RE = re.compile(r'^(\w+)-\$\(CONFIG_(\w+)\)\s*[:+]?=\s*(.+)$')
OBJ_Y_LINE_RE = re.compile(r'^(\w+)-y\s*[:+]?=\s*(.+)$')


def _read_makefile(path):
    if not os.path.isfile(path):
        return ''
    with open(path, 'r', errors='surrogateescape') as f:
        return f.read()


@lru_cache(maxsize=None)
def _parse_makefile(mk_path):
    """Returns [(prefix, config_or_None, [members]), ...] -- one entry per
    `prefix[-$(CONFIG_X)|-y] += member1 member2 ...` line."""
    entries = []
    for line in _read_makefile(mk_path).split('\n'):
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        m = OBJ_LINE_RE.match(line)
        if m:
            prefix, cfg, rest = m.group(1), m.group(2), m.group(3)
            entries.append((prefix, 'CONFIG_' + cfg, rest.split()))
            continue
        m = OBJ_Y_LINE_RE.match(line)
        if m:
            prefix, rest = m.group(1), m.group(2)
            entries.append((prefix, None, rest.split()))
            continue
    return entries


def _resolve_in_file(mk_path, target, max_chase=6):
    """Chase `target` through possibly-multiple lines WITHIN one Makefile:
    e.g. target='vlan.o' found as a member of the unconditional '8021q-y'
    group -> chase target='8021q.o' -> found in 'obj-$(CONFIG_VLAN_8021Q)'
    -> that's a TERMINAL obj- line (kbuild's reserved build-target
    keyword), so stop and return [CONFIG_VLAN_8021Q]. Returns [] if
    target is never found as a member in this file (it's resolved
    elsewhere, e.g. as a directory-descend target in the parent)."""
    conds = []
    entries = _parse_makefile(mk_path)
    for _ in range(max_chase):
        found = False
        for prefix, cfg, members in entries:
            if target in members:
                found = True
                if cfg is not None:
                    conds.append(cfg)
                if prefix == 'obj':
                    return conds  # terminal: fully resolved at this level
                target = prefix + '.o'
                break
        if not found:
            break
    return conds


def resolve_condition(root, rel_file_path, stop_dir='net'):
    """List of CONFIG_X strings (conjunction; [] = fully unconditional)
    covering every Makefile level from rel_file_path's own directory up
    to and including stop_dir."""
    parts = rel_file_path.split('/')
    dirparts = parts[:-1]
    if not dirparts or dirparts[0] != stop_dir:
        return []

    target = re.sub(r'\.[ch]$', '.o', parts[-1])
    all_conds = []

    for idx in range(len(dirparts), 0, -1):
        cur_dir = '/'.join(dirparts[:idx])
        mk_path = os.path.join(root, cur_dir, 'Makefile')
        all_conds.extend(_resolve_in_file(mk_path, target))
        if cur_dir == stop_dir:
            break
        this_dir_name = dirparts[idx - 1]
        target = this_dir_name + '/'  # parent references this dir as 'name/'

    seen = set()
    out = []
    for c in all_conds:
        if c not in seen:
            seen.add(c)
            out.append(c)
    return out


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print('usage: makefile_cond.py <root> <rel_file_path>', file=sys.stderr)
        sys.exit(1)
    print(resolve_condition(sys.argv[1], sys.argv[2]))
