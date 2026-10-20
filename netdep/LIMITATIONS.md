# netdep.py extraction: limitations and their status

Scope: the ELF extraction step (`netdep.py`, plus the `match.py` options that consume its new output).
Status values: **fixed** (default behaviour), **opt-in** (implemented, behind a flag so earlier numbers still
reproduce), **mitigated** (reduced but not eliminated), **open** (not addressed; documented here).

Supported target: x86-64, AT&T-syntax `objdump` output, Linux kernel objects built with `CONFIG_DEBUG_INFO=y`.

## Status of each limitation

| # | Limitation | Status | What was done / what remains |
|---|---|---|---|
| 1 | Incomplete instruction classification | fixed | Prefix rules replaced by a table-driven lookup (`lookup_stem`, `RMW_OPS`, `ATOMIC_RMW`, `COMPARE_OPS`, `READ_ONLY_ARITH`, assign prefixes). Unlisted mnemonics with a memory destination are now `UNKNOWN` (reported in `unclassified.txt`) instead of silently `STORE`. Exercised by `netdep.py --self-test`. Remains: the table covers common integer, x87 and SSE moves; other vector/system instructions fall to `UNKNOWN`. |
| 2 | `cmpxchg` classified as a load | fixed | Atomic families are checked before the exact `cmp`/`test`/`bt` match; `cmpxchg` is no longer a guard hint. |
| 3 | `bts/btr/btc` read-only | fixed | `bt` is a read-only guard; `bts/btr/btc` are RMW. |
| 4 | Immediate-source arithmetic as STORE | fixed | Only assign-family mnemonics (`mov*`, `set*`, ...) give STORE; `addl $1, g(%rip)` is RMW. Also fixes a latent bug: `orl/orq/orb` (3-letter stems) used to fall through to STORE. |
| 5 | Relocation order used to pick the operand | fixed | The relocation's role (displacement, immediate or branch target) is decided from byte offsets: an immediate is encoded last, so a relocation whose field ends at the instruction end is on the immediate. Instruction length comes from the next instruction's address; if unknown, the mnemonic's size suffix and then relocation order are fallbacks. Remains: the fallback can still be wrong for the last instruction of a function that has both an absolute displacement and an immediate. |
| 6 | Indirect calls separated from loads | fixed | `call/jmp *g(%rip)` is the new access kind `INDIRECT_CALL_READ`; `match.py` and `match_p1b.py` treat it as a read. Adds rows relative to earlier runs. |
| 7 | Indirect accesses through registers | opt-in | Within one function, `lea g(%rip),%r`, `mov $g,%r`, register copies and `add/sub $n` are tracked; a later `disp(%r)` access emits `IND_LOAD/IND_STORE/IND_RMW` with offset `tracked + disp`. State is dropped on writes to the register, on calls (caller-saved registers), at unconditional jumps/returns and at every branch target. `match.py --include-indirect` uses these rows. Remains: no interprocedural or memory-based pointer tracking (pointer stored in a struct, passed as an argument, returned from a function); inline asm is not modelled; callee-saved registers are assumed to survive calls. |
| 8 | Address-taking is not writing | fixed | `ADDR` stays its own category and is never promoted to a writer (it is only counted in F6's "sole writer" test, which makes F6 more conservative). Writes through taken addresses appear only as `IND_STORE/IND_RMW` rows (see 7). |
| 9 | Structure fields | opt-in | `netdep.py --dwarf-fields` fills the `field` column (e.g. `enabled`, `ops.handler`, `tbl[].cb`) from DWARF layouts (`dwarf_layout.py`); `match.py --field-sensitive` pairs a writer and reader only when their paths are equal or nested; an unknown field is compatible with everything. Remains: access size is not modelled (a 4-byte write is attributed to the field at its start offset); array indices are collapsed; bitfields are not distinguished; costs one `readelf --debug-dump=info` per object. |
| 10 | Section-relative relocations discarded | fixed | `.bss+0x20`-style relocations are resolved (section + addend, adjusted for PC-relative encoding) to the containing OBJECT symbol with `SymbolRanges`. Only unresolvable ones (string literals, anonymous data, ambiguous overlaps) are dropped and counted in the final summary. Adds rows relative to earlier runs. |
| 11 | DWARF source attribution can mislead | mitigated | Every row now carries `addr` (instruction offset in its section; unique with `obj` + `func_section`). `src_file:src_line` is an audit hint, not proof: inlining and macros can point at a header. The DWARF inline chain is not extracted. |
| 12 | Mnemonic/operand parsing is heuristic | mitigated | Operand splitting, prefix stripping, segment overrides and `*` indirect operands are handled and covered by the self-test. It is still text parsing of `objdump`, not a structured decoder (Capstone was deliberately not adopted: the container is stdlib-only). Exotic encodings land in `UNKNOWN`. |
| 13 | UNKNOWN count is not accuracy | mitigated | `--self-test` prints per-class precision and recall over a labeled instruction table, and `tests/run_classify_cases.sh` checks compiler-generated code. The kernel-wide extraction still has no ground truth, so accuracy there is inferred from these tests, not measured. |
| 14 | Data relocations are not runtime writes | fixed | `DATAREF` is a separate access kind and `match.py` never counts it as a writer. Rows record the container symbol (or `@section+offset` when it cannot be named) and the offset. Remains: no model of which init code consumes a static table. |
| 15 | Containment by offset is approximate | fixed | `SymbolRanges` requires `value <= off < value+size` and `off < section size`, matches zero-size symbols only at their exact offset, treats identical ranges as aliases (GLOBAL binding preferred) and returns "unresolved" for different overlapping ranges instead of guessing. |
| 16 | Only compiled objects are visible | open | Code excluded by the analysed `.config` has no object file and is invisible. Mitigation is procedural: run the pipeline on several configurations (the `allyesconfig` census in README section 7 is one) and compare. The tool cannot see `#ifdef`-ed-out code. |
| 17 | Architecture dependence | open (guarded) | Only x86-64 AT&T is supported. Objects whose ELF machine is not x86-64 are skipped with a warning rather than misclassified. No other backend exists. |
| 18 | Optimisation alters visible accesses | open | Inlining, constant folding, register caching and removed stores change which accesses exist in the object. The runs use the kernel's normal `-O2`; a source-level read of important candidates is still required. The regression file uses `-O1` and accepts alternatives (`A|B`) for that reason. |

## Residual gaps not in the original list

* Reads and writes through pointers loaded from memory, or in other functions, are not attributed to the global
  (only the intra-function register tracking above).
* `rep movs/stos`, `xsave` and other implicit-operand instructions rarely carry a relocation and are not modelled.
* `LOAD_GUARD` means "a compare/test/bt touched the variable in this function"; it does not prove the compare
  protects the use.
* Per-CPU variables (`%gs:` accesses) are recognised as memory operands; per-CPU offsets are not resolved to a
  CPU-specific object.
* `xref.tsv` gains `addr`, `off`, `field` (appended; the first nine columns are unchanged). Expect small,
  explainable differences from the numbers in README section 9: reclassified `or`-family and `add $imm` sites,
  newly resolved section-relative references, and new `INDIRECT_CALL_READ` rows. The README numbers have not been
  regenerated for this change.

## How this was checked

* `python3 netdep.py --self-test`: labeled instruction table, relocation-role/offset arithmetic, section-relative
  resolution, register tracking, branch-target reset. Run locally; passes.
* `sh tests/run_classify_cases.sh`: compiles `tests/classify_cases.c` and checks extractor output (including
  struct fields and a static ops table). Needs a Linux/ELF toolchain; **not run yet** (the dev machine only has a
  Windows MinGW toolchain, which produces PE objects).
* Not yet done: a full kernel re-extraction and an old-vs-new comparison of `xref.tsv` by access class.
