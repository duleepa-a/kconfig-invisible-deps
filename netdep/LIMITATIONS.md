# netdep / match: limitations and their status

Scope: items 1-18 are the ELF extraction step (`netdep.py`); items 19-42 are the matching funnel (`match.py`).
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

## Matching funnel (`match.py`), items 19-42

Default behaviour changed with these fixes; `match.py --legacy` restores the previous name-matching and the
previous F6/F7/F8 definitions so the numbers in README section 9 can be reproduced. The `--legacy` equivalence is
argued from the code and covered by `tests/test_match.py`, but has **not** been checked against the real
kernel extraction yet. Re-extract with the current `netdep.py` (it adds `sym_bind`, `value`, `sec_flags`, `guard`);
against an older `xref.tsv` (no `sym_bind`) `match.py` warns and falls back to name matching.

| # | Limitation | Status | What was done / what remains |
|---|---|---|---|
| 19 | Symbols matched only by name | fixed | Identity is (linkage, name, defining object): a reference is LOCAL only if the referencing object defines that name as a local OBJECT (`sym_bind`), and then it is keyed to that object. Same-named statics in different files no longer pair. Remains: a function-scope static is keyed by its mangled ELF name (`x.1234`), which is unique per object. |
| 20 | Excluding LOCAL definitions is not enough | fixed | Both definitions and references carry linkage; a LOCAL reference never binds to a GLOBAL definition of the same name, and file-local keys are excluded from cross-object candidates. |
| 21 | F0 is not strictly the visible globals | fixed | F0 is reported by linkage (`F0_global`, `F0_weak`, `F0_local`, `F0_other_binding`); only GLOBAL/WEAK symbols enter F1 onward. TLS and non-OBJECT symbols are not extracted. |
| 22 | Only `.rodata` excluded | fixed | Read-only is decided by the ELF section flags (no `W`), with a `.rodata*` name test only when flags are unknown; `.data..ro_after_init` stays in scope. `F0_excluded_read_only` counts the removed definitions. A writable section that is in practice never written is not detected. |
| 23 | F1 misses indirect writers | opt-in | `IND_STORE/IND_RMW` rows (intra-function register tracking) are used with `--include-indirect` and labelled `writer_evidence=inferred`; F6 always counts them as possible writers. Remains: no interprocedural pointer analysis, so stores through pointers passed in or loaded from memory are still missed. |
| 24 | Observed stores treated as initialization | mitigated | Candidates record the store's value kind (`writer_value`: zero / imm / reg / rmw), the struct field, and boot vs run time; a store of zero lowers the score. Not modelled: the effect of the value on what the reader needs, or whether the path is reachable. |
| 25 | F2 misses indirect readers | mitigated | `call *g(%rip)` (`INDIRECT_CALL_READ`) is a reader by default; `IND_LOAD` with `--include-indirect`. Reads through arbitrary aliases are still invisible. |
| 26 | F3 assumes different objects are separable | open | F3 is only a structural prefilter; Kbuild may always build the two objects together. F5 and the solver step, not F3, carry the build-condition reasoning. |
| 27 | F4 is not a link test | open | F4 means "a definition lives in another object". Nothing links the proposed configuration; build it and inspect symbol resolution and module/built-in compatibility before relying on a candidate. |
| 28 | F4 misses `#ifdef`-removed initializers in one source file | open here, separate path | A writer and definition in the same object are skipped by the cross-unit check by design. That case is covered by `match_p1b.py` / `guardmap.py`, not by this funnel. |
| 29 | F5 compares expressions | mitigated | F5 stays a textual prefilter. `kconfig_sep.py` is the real check and now asks *definition present AND reader present AND writer absent* against Kconfig; run it on `candidates.tsv`. It is a separate step, not folded into `match.py`, and has not been run since this change. |
| 30 | Intra-file preprocessor conditions | opt-in | `--ifdef-guards` reads the writer/reader source lines under `--root`, computes their presence conditions with `guardmap.py`, and adds `writer_ifdef`, `reader_ifdef`, `ifdef_separable` (yes/no/unknown, combined with the Makefile gates). Unreadable files give `unknown`, never a guess. The DWARF line can point into an inlined header, in which case the condition is that header line's. Not run on real sources yet. |
| 31 | F6 counts ADDR as writers | fixed | F6 counts only writes (direct and inferred); `addr_taken` reports address escape separately. |
| 32 | F6 counts sites, not paths | mitigated | F6 counts distinct writer *functions* (`n_writer_funcs`), so several stores in one function are one writer. Callers of a shared helper and path feasibility are not modelled. |
| 33 | F7 assumes `.bss` is risky | mitigated | F7 stays a flag but only ranks: a pointer-sized `.bss` object (`pointer_sized`) outweighs a small counter in `score`. Reader semantics and invariants are not analysed. |
| 34 | F7 overlooks initialized `.data` | mitigated | Section placement is documented as ranking evidence, not a safety verdict. |
| 35 | F8 uses comparisons as guards | mitigated | Guard evidence is per read site (`guard_evidence`: site / function / none): a compare on the global, or a zero-test of a register the global was loaded into followed by a conditional jump. This is not CFG dominance or path-sensitivity: a test elsewhere in the function does not prove the use is protected. |
| 36 | F8 misses guards on local aliases | mitigated | The "load into a register, test the register" pattern (the usual hook-pointer NULL check) is recognised in straight-line code. Spills to the stack, copies through several registers, and checks on companion variables are not. |
| 37 | F8 ignores compile-time protection | opt-in | Use `--ifdef-guards` (see 30); the reader's `#ifdef` condition is reported and a pair that cannot occur once `#ifdef`s are applied is demoted. |
| 38 | F9 list is not a resolved `.config` | opt-in | `--dotconfig` evaluates y/m/n per option (`writer_cfg`, `reader_cfg`, `def_cfg`). Without it, membership in the composed list still means `y`, as before. |
| 39 | F9 does not establish module loading | open (flagged) | `exposed_if_module_unloaded` marks writer=`m`, reader=`y`; whether the module loads, and in what order, needs a runtime model or observation (the QEMU witnesses in `results/`). |
| 40 | F6-F9 look like independent proof | mitigated | Documented as prioritisation features in `match.py`, the README and here. `score_validation.py` compares each flag and the score with `results/manual_verdicts.csv`. The audited set is small, so treat its numbers as a sanity check, not a validation. |
| 41 | Counts inflated by repeated sites | fixed | Rows are one per (symbol, writer function, reader function) with `n_site_pairs`/`n_writer_sites`/`n_reader_sites`; the funnel keeps site-pair counts for F3-F9 and adds `candidates_distinct_symbols`, `_writer_funcs`, `_reader_funcs`. |
| 42 | Duplicate or aliased definitions | mitigated | Symbols with the same object, section, value and non-zero size are merged to a canonical symbol (GLOBAL, then WEAK, then LOCAL); `n_defs` records multiple definitions. Aliases across objects with different values, and weak/strong override relationships, are only recorded, not resolved. |

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
* `python3 tests/test_match.py`: synthetic extraction covering linkage-aware identity, aliases, section flags,
  F6/F7/F8/F9 changes, dedupe, evidence labels and `--legacy`. Run locally; passes.
* `python3 score_validation.py`: smoke-tested on made-up rows only; not yet run on real candidates.
* Not yet done: a full kernel re-extraction, an old-vs-new comparison of `xref.tsv` by access class, a check that
  `match.py --legacy` reproduces README section 9, and a run of `kconfig_sep.py` (needs kconfiglib and the tree).
