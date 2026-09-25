#!/usr/bin/env python3
"""
decl_finder.py -- find a global variable's file-scope DECLARATION line by
text search.

DWARF is NOT reliable for this: for an externally-linked (EXPORT_SYMBOL'd)
global, DW_AT_decl_file/decl_line reflects wherever the compiler first
encountered an `extern` declaration -- typically a widely-included header
-- not the translation unit's own file-scope definition. Verified
concretely on `mem_section`: DWARF in mm/sparse.o points to
`mmzone.h:1148` (the header's extern), while the real definition (with a
completely different, conditionally-typed declaration) is at
`mm/sparse.c:26`. This was discovered by cross-checking a DWARF "match"
against a `grep -B` context match that turned out to be a false positive
(an unrelated `__s32` typedef's `decl_line: 26`) -- a caution to keep
applying throughout: verify by reading, don't trust proximity in grep
output as structural.

So: text search the object's own primary .c file for a plausible
file-scope declaration of the symbol. Conservative by design -- if the
search is ambiguous (0 or >1 plausible matches), report that explicitly
rather than guessing; callers should treat those as "unverified", not as
evidence either way.
"""
import re
import sys

# A plausible file-scope declaration: the symbol as a whole word, not a
# member-access (`.sym` / `->sym`) or a function call (`sym(`), on a line
# with shallow indentation (file scope, not inside a function body -- the
# kernel's dominant style is >=1 tab of indentation for anything inside a
# function). Allows an array suffix and/or a `= initializer` before `;`.
def _decl_pattern(sym):
    return re.compile(
        r'^[ \t]{0,1}[A-Za-z_][\w\s\*]*?\b' + re.escape(sym) +
        r'\b\s*(\[[^\]]*\])?\s*(=[^;]*)?;\s*(/\*.*\*/)?\s*$'
    )


def find_declaration(source_path, sym):
    """Returns (line_number, line_text) if exactly one plausible file-scope
    declaration is found; ('AMBIGUOUS', [candidates]) if more than one;
    None if none found."""
    pat = _decl_pattern(sym)
    matches = []
    try:
        with open(source_path, 'r', errors='surrogateescape') as f:
            for i, line in enumerate(f, start=1):
                # reject obvious non-declarations even if the shape matches
                if re.search(r'\.' + re.escape(sym) + r'\b', line):
                    continue
                if re.search(r'->\s*' + re.escape(sym) + r'\b', line):
                    continue
                if pat.match(line):
                    matches.append((i, line.rstrip('\n')))
    except FileNotFoundError:
        return None

    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        return ('AMBIGUOUS', matches)
    return None


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print('usage: decl_finder.py <source_path> <symbol_name>', file=sys.stderr)
        sys.exit(1)
    print(find_declaration(sys.argv[1], sys.argv[2]))
