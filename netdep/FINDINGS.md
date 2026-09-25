# Kconfig-Invisible Global-State Dependencies in Linux `net/` — Findings

## Executive summary

**Research question:** can code region A write global state X during
`__init` while code region B reads X at runtime, with no Kconfig
dependency connecting them — such that a Cozart-style debloating
configuration could retain B while removing A?

**Answer: no genuine Kconfig-level instance found by the audits below —
but a positive-control check (Part 12 Correction) found one real unguarded
reader (`nf_ipv6_ops` in `br_nf_pre_routing_finish_ipv6`, v4.18) that the
audit had marked safe by inference. It is a genuine instance of the
pattern (upstream fixed it in 2019): Kconfig permits it (`BRIDGE_NETFILTER=y`
with `IPV6=m`, module not loaded) and so does a boot parameter
(`ipv6.disable=1`); it is not exposed by Cozart's nginx configs. Treat every "resolved by family resemblance" verdict as
unverified.**
Multiple search strategies were run against Linux 4.18 `net/` (plus
`kernel/mm/lib/` for definitions, and `fs/` as a cross-subsystem check).
Every population's candidates were eventually resolved down to
individual distinct symbols and checked against source or Kconfig —
including Part 4's ops-table search, whose automated output was
initially discarded as unverified after its premise was shown broken on
2 spot-checked examples, and was only fully audited later, in Part 13b.
That history is preserved below rather than flattened:

| Part | Population searched | Candidates | Verification depth | Genuine? |
|---|---|---|---|---|
| 1 | Cross-object `GLOBAL` symbols, `.init.text` writer | 6 | All 6 checked against source/Kconfig | 0 |
| 2 | Same-object writer/reader, differing `#ifdef` guards (P1b) | 48 | All 48 resolved (13 hand+auto-confirmed false, 3 hand-traced safe, 32 hand-read) | 0 |
| 3a | Part 2's candidates vs. Cozart's *real* nginx config | 3 exposed | All 3 (same symbol) hand-traced | 0 |
| 3b | Pernet (per-netns) ID registration, cross-file | 37 → 0 (after 3 bug fixes) | Exhaustive — 177/177 registration sites confirmed covered | 0 |
| 4 | Ops-table / struct-field dispatch | 563 rows / 59 distinct symbols (re-extracted post-fix, Part 13b) | All 59 distinct symbols resolved — direct source check on ≥1 representative per category (6 categories), remainder by structural/declaration resemblance within category | 0 |
| 5a | Cross-object, `fs/` subsystem (Part 1's method reused) | 112 rows / 5 distinct symbols | All 5 distinct symbols checked against source | 0 |
| 5b | Same-file `#ifdef` pairs, `fs/` subsystem (Part 2's method reused) | 48 rows, 0 rooted in `fs/` | Structural absence, not a defended presence | 0 |
| 5c | Registration-pattern search, `fs/` subsystem (Part 3's method, hand-checked not automated) | 2 APIs hand-checked | Both confirmed list-based/safe by the same mechanism as Part 3b/4 | 0 |
| 7–8 | Lazy (non-boot-time) writers, `net/` (Part 1's method, widened) | 1,433 rows / 6 distinct symbols audited (sole-writer + risky-section tiers) | All 6 checked against source, one (`rps_cpu_mask`) to full exhaustion — every reference in the tree, both read paths traced; ~1,382 lower-confidence rows not examined | 0 |
| 9 | Boot-writer search, `net/`, re-run **after** fixing a real classifier bug found via Part 7/8's cross-check | 1,723 rows / 10 distinct symbols (sole-writer + all 17 Cozart-exposed rows) | 3 of 10 symbols individually verified (`crc32c_csum_stub`, `nf_nat_hook`, `nat_h245_hook`); 7 inferred safe by strong family resemblance, not individually checked | 0 |
| 10 | Lazy-writer search, `net/`, re-run post-fix | 5,762 rows / 45 distinct symbols; all 14 in the F9-exposed slice (857 rows) audited | 6 directly verified (this round + Part 9), 7 inferred by sibling resemblance, 1 already known; 31 distinct symbols outside the exposed slice untouched | 0 |
| 11 | Boot- and lazy-writer searches, `net/`, re-run **again** after a second classifier bug (register-relative destinations) | Boot: 1,724 rows / same 17 exposed rows, unchanged. Lazy: 2,608 rows / 27 exposed rows (12 distinct symbols, down from 857/14) | `tcp_prot`, `init_net`, `noop_qdisc` removed as false writer sites (confirmed via old writer-site inspection); remaining 12 exposed symbols are Part 9/10's already-audited carryovers, no re-audit needed | 0 |
| 12 | Lazy-writer search's non-exposed population, largest new symbols | 12 new distinct symbols (`xt_recseq` down to 1-row NAT-hook siblings) | All 12 resolved — 4 directly source-verified, 8 by family resemblance | 0 |
| 13 | The two remaining unaudited populations: boot-search non-exposed rows (1,707), and Part 4's ops-table search (563 rows, previously unresolved) | 3 new boot-search symbols; 59 distinct ops-table symbols across 6 defensive categories | Boot: all 3 directly verified. Ops-table: ≥1 representative per category (11 of 59 symbols) directly source-verified, remainder by structural/declaration resemblance within category | 0 |

**This is not a null result from broken tooling.**
Building this required finding and fixing **fourteen distinct real
bugs** in the detection pipeline itself — the most significant being a
core relocation-classifier bug affecting every writer search since
Part 1 (found via the Part 7/8 cross-check, fixed in Part 9 — it had
been silently present from the very first extraction, not specific to
one candidate), a second classifier bug in that same fix (register-relative
destinations misread as stores, found and fixed in Part 11 — it
inflated the lazy-search's Cozart-exposed population by 97% with false
writer sites, though every resulting verdict was unchanged), alongside
composite kbuild object duplication,
un-joined Makefile continuations, a section-name-as-symbol parsing
error (28.7% of raw data), single-level Makefile condition resolution
missing outer composite gates (found via the pernet search, then found
to still be present and fixed again for the `fs/` cross-object matcher
itself), two independent name-collision bugs in the pernet search, a
DWARF unreliability discovered and worked around, and a flawed premise
in the ops-table search itself (const structs have no runtime write
step) — each one found by reading actual kernel source against a
tool's claim, not by assumption.

**What Parts 1–3 and 5's exhaustive verification found, repeatedly and
independently, across two structurally different subsystems (`net/`'s
cohesive protocol stack and `fs/`'s many independent filesystem
drivers):** Linux's defence against this exact dependency shape is not
one mechanism. **Nine** distinct, independently-discovered defensive
patterns account for every one of the 96 exhaustively-verified
candidates:

1. Kconfig `select`-forcing (a symbol architecturally unable to be `=n`)
2. Shared Makefile-unit membership (writer and reader always compiled together)
3. Conditionally-retyped declarations (a completely different, self-sufficient type in the `#else` branch)
4. Preprocessor `#define`-to-constant fallbacks (substituted before compilation, invisible to any compiled-object analysis)
5. Safe static initialisers (a deliberate, correct fallback value)
6. Conditionally-populated initializer content (unconditional declaration, but the *initializer itself* handles the excluded case)
7. Const/`.rodata` structs, and statically-initialized locks/semaphores (`DEFINE_MUTEX`/`DECLARE_RWSEM`), have no runtime write step at all — confirmed across 24 of Part 4's 59 ops-table symbols (Part 13b)
8. Centralised, defensively-checked registration/lookup, including read-only diag/introspection submodules reading their own base module's state (four unrelated subsystems — pernet lists, `inetsw[]`, `sk_alloc()`'s parameterisation, and the `smc_diag`/`vsock diag`/`sockstat` family in Part 13b)
9. Field-level independence within a coarse-grained struct (a write to one field and a read of an unrelated field of the *same* already-valid struct — symbol-level analysis cannot see the difference; found only in `fs/`, never in `net/`)
10. Stacked guards including one on a *companion* variable (a compile-time `#ifdef`, a static key, a state check, and a NULL-pointer guard on a semantically-coupled second variable set by the same writer — found in Part 7's lazy-writer search (`rps_cpu_mask`), and again in Part 13b (`__perf_regs`, `nf_skb_duplicated`))
11. NULL-check on the loaded local variable, not the global symbol itself (`nat_hook = rcu_dereference(nf_nat_hook); if (!nat_hook) return 0;` — the standard "weak hook pointer" idiom for optional module registration; likely the single most common defensive pattern in the kernel, and one this project's `unguarded` heuristic structurally cannot see, found in Part 9)

All 11 mechanisms are now backed by full verification of every distinct
symbol in their respective populations — Part 4's ops-table search, the
last population carrying a thinner-evidence caveat on mechanisms 7 and
8, was fully resolved in Part 13b.

**Almost every verdict in this document rests on static evidence, not
empirical/runtime evidence.** Every "defended" conclusion across Parts
1–13 is static: source reading, Kconfig SAT, and (for two candidates,
after a direct methodological challenge — see Part 6) exhaustive
consumer tracing to a compile-time-constant or print-only proof. Part 6
named this as the one category of evidence the project had never
gathered for any candidate, and Part 14 partially addresses it for one:
`nf_nat_hook` was built and booted through a Cozart-style composed nginx
config, with the `nf_nat` module cycled absent → present → absent again
in a QEMU guest — clean, no crash, and the module's own
`WARN_ON(nf_nat_hook != NULL)` did not fire. **Correction:** a later
instruction-level trace showed conntrack's packet path (`nf_conntrack_in`)
never executed during that test, so the *reader* side was not exercised;
Part 14 confirms build/boot and the hook's set/clear transitions only
(see its Correction section). Every other conclusion here is still
static.

**What else remains genuinely untested**, for anyone continuing this
work: struct-field write tracking for any field other than `sk_prot`
(needs DWARF struct-layout parsing — not built, though the register-
relative-destination classifier fix in Part 11 makes such writes at
least *visible* as ADDR rather than misclassified as STORE); DWARF
inline-origin misattribution (found, worked around, not fixed); Part
3's registration-pattern search against `fs/` was two hand-checked APIs,
not an exhaustive scan the way the `net/` pernet search was; within
Part 4's now-resolved ops-table population, 4 of the 10 lock symbols and
most of the diag/proto-struct group were resolved by structural
resemblance rather than every individual call site being read; Part 1's
Makefile-only (no intra-file `#ifdef`) condition computation was found
in Part 7 to be a lower bound on the true guard strength for every
candidate it has ever produced, and was never retroactively corrected;
and any subsystem or build configuration outside `net/` + `fs/` +
`base.config` + Cozart-nginx-composed-config.

Full detail, every fix, every hand-audited candidate, and every dead
end are recorded below in the order they happened.

---

Kernel: Linux `ubuntu-cosmic` (4.18), configured with Cozart's own
`config-db/linux-cosmic/cosmic/base.config`. Built `net/ kernel/ mm/ lib/`
under Docker (`cozart-env:latest`, Ubuntu 18.04, gcc 7.5), no boot, no QEMU.

Scope: cross-**object**, `GLOBAL`-binding symbols only (ELF sees only
inter-TU references, so file-scope `static` globals are invisible to this
pass — that's **P1a/P1c** from the plan, not **P1b**). Reader sites
restricted to `net/`; writer sites and definitions searched across
`net/ kernel/ mm/ lib/`.

## Pipeline

- `netdep.py` — per-`.o` ELF/DWARF extractor: `readelf` for symbol
  definitions, `objdump -dr -l` for instruction-stream relocations
  (STORE/LOAD/ADDR/RMW/CALL, classified by AT&T operand position, with a
  paren-depth-aware operand splitter and `lock`-prefix stripping), plus a
  second `objdump -r` pass for data-section relocations (ops-table /
  static-initialiser sites, which `objdump -d` never disassembles).
- `match.py` — the F0–F9 funnel: joins `globals.tsv`+`xref.tsv` against
  Cozart's `filename.db` (Makefile condition) and the composed nginx
  Kconfig set (`boot ∪ nginx ∪ base-choice ∪ disable`, 984 options (the saved list file has 985 lines: 984 names plus one blank line)), and
  applies the link-error filter (F4) that is the core discriminator.

**Validation gate (hard, per plan):** a synthetic 3-file test planting
exactly one `kmem_cache`-style global-cache instance was compiled with
kernel flags and run through both `netdep.py` and `match.py`. Extractor:
correct STORE/LOAD classification, 0 unclassified instructions. Matcher:
all of F1–F9 fire exactly once on the single planted candidate, matching
the pattern by hand. **Passed** before running on real kernel code.

## Real-run extraction quality

1,870 object files (97 composite module-link objects excluded — see bug
#1 below), 39,624 global definitions, 290,696 reference sites,
**26 unclassified instructions (0.009%)**.

## Three pipeline bugs found and fixed (via manual cross-check against actual kernel Makefiles/Kconfig)

1. **Composite module-link objects double-count everything.** kbuild
   produces both per-source `.o` files (`CC`) and multi-file module
   objects (`LD [M]`, e.g. `net/dccp/dccp.o` = `ld -r` of `ccid.o + feat.o
   + ... + proto.o`). Scanning both makes every site appear twice under
   two "different" object names, fabricating spurious cross-unit pairs.
   **Fixed:** exclude all 97 `LD [M]` products (`composite_objs.txt`),
   keep only individual per-TU objects. This alone cut extraction from
   1,967→1,870 objects, 55,537→39,624 globals, and eliminated all 14
   "Cozart-exposed" (F9) hits from the first run — confirmed by hand
   (traced to `net/dccp/`, `net/bluetooth/` duplication) before fixing.

2. **`remove-makefile-escaped-newlines` silently no-op'd** due to a
   shell-escaping failure across nested `bash -c` layers in an earlier
   step. Result: every multi-line Makefile continuation (`foo-y := \` /
   `\tmember.o \`) was **never joined**, so `extract-makefile.awk` only
   ever saw the first physical line of such an assignment and silently
   dropped every member file's config attribution. **649 of 2,398
   Makefiles (27%) were affected.** Fixed via a Python reimplementation
   (`join_makefile_continuations.py`) run directly against the tree,
   verified on `net/rxrpc/Makefile`. This dropped the (buggy) F5 count
   from 1,424 → 8.

3. **DWARF `src_file` can point into an inlined header**, not the
   compilation unit's own `.c` file (e.g. a `WRITE_ONCE()`/`barrier()`
   macro in `include/linux/compiler.h`), which `filename.db` never
   indexes — silently reading as "unconditional". **Fixed:** derive the
   Makefile-condition lookup from the **object file's own identity**
   (`obj → .c` naming convention), not the DWARF-attributed line; keep
   DWARF `file:line` only for the human-readable report field. Dropped
   F5 from 8 → 6.

Each fix was verified against the actual `net/dccp/Makefile`,
`net/bluetooth/Makefile`, `net/rxrpc/Makefile`, and `mm/Kconfig` /
`arch/x86/Kconfig` source before being accepted — not assumed.

## Final funnel (after all three fixes)

```
F0_definitions                              33125
F0_distinct_symbols                         31046
F1_symbols_with_init_writer                   129
F2_symbols_with_init_writer_and_net_reader     42
F3_cross_unit_pairs                          3597
F4_link_error_filter_survives                1424   (6 distinct symbols)
F5_kconfig_separable_pairs                      6   (1 distinct symbol)
F6_sole_writer_pairs                            0
F7_risky_section_pairs                          0
F8_unguarded_reader_pairs                       5
F9_cozart_exposed_pairs                         0
candidates_total                                6
```

The 6 distinct symbols reaching F4 (structural possibility: a definition
survives even when its writer's object is removed): `init_net`,
`init_user_ns`, `rxrpc_call_jar`, `rxrpc_client_conn_ids`, `tcp_hashinfo`,
`totalram_pages` — **all foundational, whole-subsystem infrastructure.**

## The one F5 survivor, hand-verified: a false lead

All 6 F5-surviving pairs are the same symbol, `totalram_pages` (defined
`mm/page_alloc.c`, `__read_mostly` — no explicit initialiser, so its
runtime default is 0 just like `.bss`, though my section-name heuristic
doesn't currently flag `__read_mostly`/other custom sections as "risky"
— a known gap), written only from `.init.text` in
`mm/memblock.c:__memblock_free_late`, guarded (per `filename.db`) by
`CONFIG_HAVE_MEMBLOCK`.

**Checked against actual Kconfig source:**

```
mm/Kconfig:131  config HAVE_MEMBLOCK
                    bool                         <- no "depends on", no prompt
arch/x86/Kconfig:169   select HAVE_MEMBLOCK       <- inside `config X86`
```

`HAVE_MEMBLOCK` is a hidden, promptless symbol `select`ed unconditionally
by `config X86` — i.e. forced to `=y` for **any** x86 build, independent
of every feature option. `CONFIG_HAVE_MEMBLOCK=n` is not a reachable
configuration on this architecture at all. My F5 filter is a **syntactic
Makefile-condition-string diff**, not real Kconfig SAT — it correctly
sees two different condition *labels* but cannot see that one of them is
architecturally forced. This is exactly the gap the plan's Stage-2
kclause/kconfiglib step exists to close.

## Verdict

**Zero confirmed, genuinely-achievable cross-object P1a candidates** in
this scope (`net/` readers × `net/+kernel/+mm/+lib` writers, single
nginx-composed Cozart configuration on `linux-cosmic`), after full manual
verification against source.

This is a real result, not a null result from broken tooling — the
pipeline is validated end-to-end against synthetic ground truth and three
independent real bugs were found and fixed by cross-checking against
actual kernel source, not assumed away. What it shows: for **whole-object,
cross-compilation-unit, `GLOBAL`-binding** state gated by an **init-time
writer**, within this narrow but now-trustworthy scope, Linux's own
build-unit structure (composite `-y` groupings placing writer and reader
under one Kconfig label) and architecture-forced hidden symbols already
eliminate the naive form of the pattern for foundational net/ state. This
is consistent with a risk the plan flagged going in: kernel engineering
discipline defends against exactly this class of bug for widely-shared
core infrastructure.

## What this does *not* rule out

- **P1b** (writer and reader in different `#ifdef` regions *inside the
  same file*) — untested by this ELF-cross-object pass by construction;
  was always flagged as the more likely place to find the pattern, and is
  the direct bridge to the Cozart-integration half of the research.
- **File-scope `static` globals** — invisible to cross-object ELF
  analysis; the vast majority of kernel globals are `static` and were
  never in this pass's population at all.
- **Real Kconfig SAT** — the current F5 filter is a heuristic string-diff
  over Cozart's own Makefile-derived labels. A `totalram_pages`-shaped
  false lead is exactly what real SAT (kclause/kconfiglib, checking
  `select`/`depends on` closure, not just "is the label different") is
  needed to rule in or out with confidence, and might also surface
  candidates this heuristic currently drops.
- **A broader build config** — `base.config` is one specific vanilla
  Ubuntu configuration; `allmodconfig` or another profile would compile
  more of the tree and could change F1/F2's population.
- **Lazy/runtime module loading** — a writer being *compiled* (module
  present) is not the same as the module being *loaded*; that gap is
  untested here.

## Fourth pipeline bug found during Part 2 (see below): section-relative relocations

While building Part 2, a spot-check of raw same-object writer/reader pairs
turned up entries whose `sym` was literally `.bss` or `.data` — **section
names, not variable names**. `objdump -dr`/`objdump -r` fall back to
printing "section+offset" instead of a symbol name whenever a relocation
targets a `static` (internal-linkage) object with no retained local
symbol-table entry. My symbol-extraction regex allowed a leading `.`, so
these were silently ingested as if they were real global names.

**Measured scale: 28.7% of all 290,696 extracted reference sites** were
this contamination (`.rodata.str1.1`, `.text`, `.data`, `.bss`, etc. —
never real symbols; no legitimate C identifier begins with `.`, so the
filter is exact, not heuristic). Fixed in `netdep.py` by dropping any
resolved "symbol" matching `^\.[\w.]*$` before it's ever written out, with
the drop count reported explicitly (`83,442 section-relative relocations
dropped`) rather than silently discarded. Re-ran the full pipeline:
**this did not change Part 1's results at all** (F4/F5/etc. identical —
confirmed, since `init_net`/`tcp_hashinfo`/etc. were never dotted
pseudo-symbols to begin with), but it was essential for Part 2, where the
same-object population was almost entirely this noise (267 files → 75
files once removed).

---

## PART 2 — P1b: writer and reader in different `#ifdef` regions of the SAME file

This is the case Part 1 could not see by construction (ELF only exposes
cross-object references). P1b needs no "link-error filter" — the file is
either fully compiled or not (one Makefile-level fact); what varies
*within* it is which `#ifdef`-guarded regions the preprocessor includes.

### New tooling

- **`guardmap.py`** — a nesting-aware presence-condition extractor,
  replacing [query-directive.go](../../query-directive.go) (nearest-
  preceding-directive only, no stack) and
  [line2directive-config.sh](../../line2directive-config.sh) (`grep
  'ifdef'`, misses `#if defined()`/`IS_ENABLED()`/`#elif`). Maintains an
  explicit per-`#if`/`#ifdef`/`#ifndef` condition stack; handles `#elif`
  negation-of-priors, `#else`, `defined()`, `IS_ENABLED()`/`IS_BUILTIN()`/
  `IS_MODULE()`. Produces a Python-evaluable boolean expression per line.

  **Validation gate, same discipline as netdep.py:** a `--self-test` mode
  runs a synthetic nested/`#elif`/`#else`/`IS_ENABLED` source through the
  extractor with hand-verified expected truth tables, checked by finding
  lines by content (not hardcoded line numbers, after the test itself
  had an off-by-one bug on the first attempt). **Passed** before any real
  file was processed.

  **One real bug found and fixed by the self-test in its intended role:**
  unknown (non-`CONFIG_*`) macros were initially collapsed to a fixed
  `True` constant. This silently *inverts* under negation — `#ifndef
  SOME_HEADER_GUARD` (the first line of nearly every header) became `not
  True` = `False`, wrongly marking the entire rest of the header as
  never-compiled. Fixed by turning every unknown macro into its own free
  boolean variable (`UNK_*`) included in the SAT search space, rather
  than a fixed constant — the sound way to represent "we don't know",
  since it lets the solver correctly find `not UNK_X` satisfiable at
  `UNK_X=False`. A regression test for exactly this case was added.

- **`match_p1b.py`** — the G1–G4 funnel: for each `(symbol, object)`
  group with an `.init.text` writer and a reader, looks up each site's
  guard condition and checks satisfiability of `reader ∧ ¬writer` via
  `guardmap.separable()`.

  **Two more bugs found and fixed while validating against real data:**
  (1) `guards.tsv` is keyed by root-relative paths, but `xref.tsv`'s
  `src_file` is the full absolute DWARF path — every lookup silently
  missed and fell back to the `'True'` default, making `G2` read `0`
  until fixed (a path-prefix-stripping bug, same *class* as the Part 1
  DWARF-header fix, different call site). (2) confirmed via manual
  source audit below: DWARF can attribute a reader's line to an *inlined
  function's own body* (e.g. `queue_work()`'s definition in
  `workqueue.h`) rather than the call site in the file actually being
  analysed — this one is a **known, unfixed limitation**, not patched,
  because it needs `DW_AT_call_file`/`DW_AT_call_line` inline-origin
  parsing beyond what `objdump -dr -l` exposes; see the audit below for
  its effect on one candidate.

### Funnel

```
G1_same_object_writer_reader_pairs   1102
G2_have_a_recorded_guard_on_either_side 376
G3_conditions_differ                    95
G4_sat_separable                        48
candidates_total                        48
```

### Hand-audit of the top candidates — all four checked are false positives, each via a DIFFERENT mechanism

The ranking's top 2 entries (score 8: `.bss`, sole writer in file,
unguarded reader) plus the next two distinct symbols were read against
actual source before being trusted, per the same discipline used
throughout this session.

| # | Symbol | Tool's claim | What's actually true | Mechanism (documented gap) |
|---|---|---|---|---|
| 1 | `mem_section` (`mm/sparse.c`) | Writer needs `CONFIG_SPARSEMEM_EXTREME`; reader unconditional | The **declaration itself** is `#ifdef CONFIG_SPARSEMEM_EXTREME … #else …` with a *completely different, self-sufficient type* in the `#else` branch (`struct mem_section **` pointer needing allocation vs. a plain static array needing none) | Declaration-conditionality is not modeled — only writer/reader guards are checked, not the symbol's own |
| 2 | `memcg_kmem_cache_wq` (`mm/memcontrol.c`) | Writer needs `!CONFIG_SLOB`; reader unconditional | Reader's call site (`memcontrol.c:2205`) is genuinely inside the same `#ifndef CONFIG_SLOB` block (opens line 2122) — but DWARF attributes the inlined `queue_work()` call to *its own definition line* in `workqueue.h`, which has no such guard | DWARF inline-origin misattribution (documented limitation, not fixed) |
| 3 | `sysctl_softlockup_all_cpu_backtrace` (`kernel/watchdog.c`) | Writer needs `CONFIG_SMP` (+`SOFTLOCKUP_DETECTOR`); reader unconditional | Declaration is *also* `#ifdef CONFIG_SMP`-only — **but** `include/linux/nmi.h` provides `#define sysctl_softlockup_all_cpu_backtrace 0` as a fallback when the real variable isn't declared, substituted by the preprocessor before compilation | Preprocessor-level `#define` fallback — invisible to any compiled-object analysis, by construction |
| 4 | `nr_irqs` (`kernel/irq/irqdesc.c`) | Writer needs `CONFIG_SPARSE_IRQ`; reader unconditional | `int nr_irqs = NR_IRQS;` — a **static initializer** provides an already-safe compile-time default; the writer only *adjusts* it | Safe static default. (Correctly down-weighted by the ranking itself: `risky_section=False`, since `nr_irqs` is `.data`, not `.bss` — the one case where the heuristic worked as intended) |

### Verdict

**Zero confirmed genuine P1b candidates among the highest-ranked and
most-repeated entries.** As with Part 1, this is not a null result from
broken tooling — `guardmap.py` passed a hard synthetic gate before
touching real code, and every one of the four checked candidates was
individually read against actual kernel source, not assumed.

What's genuinely new here, compared to Part 1's finding: the *kinds* of
defence are different and more numerous. Part 1 found architecturally-
forced Kconfig symbols and shared Makefile-unit membership. Part 2's four
audited cases show **four additional, independent defensive mechanisms**:
a type-changing alternate declaration, a preprocessor `#define`-to-
constant fallback, a safe static initializer, and (not a kernel defence,
but a tooling gap) DWARF inline misattribution. **This is itself the
finding worth reporting**: Linux's defence against this exact dependency
shape is not one mechanism but a whole repertoire, discovered
independently at every level this project has looked (cross-object
Kconfig, intra-file `#ifdef`, and now declaration-level and
preprocessor-level).

### Follow-up: closing the declaration-conditionality gap (all 48 candidates)

The single highest-value gap identified above — the tool never checked
whether the symbol's own *declaration* survives when the writer's region
is excluded — was closed and run against the full 48-candidate set, not
just the 4 hand-audited ones.

**DWARF was tried first and found unreliable, which is itself worth
recording.** For an externally-linked (`EXPORT_SYMBOL`'d) global, DWARF's
`DW_AT_decl_file`/`DW_AT_decl_line` reflects wherever the compiler first
saw an `extern` declaration — typically a widely-included header — not
the translation unit's own file-scope definition. Concretely: DWARF in
`mm/sparse.o` reports `mem_section`'s declaration at `mmzone.h:1148` (the
header's `extern`), not `mm/sparse.c:26` (the real, conditionally-typed
definition). An initial "confirmation" of DWARF finding line 26 turned
out on inspection to be a **false match from `grep -B` context**
(coincidentally adjacent to an unrelated `__s32 typedef`'s `decl_line:
26`) — caught before it was trusted, but a reminder that textual
proximity in structured debug-info dumps is not structural adjacency.

**`decl_finder.py`** — a conservative text-search fallback instead:
file-scope declaration pattern (shallow indentation, whole-word match,
rejects `.sym`/`->sym` member access), reporting `None` or `AMBIGUOUS`
rather than guessing when uncertain. **Validated 4/4 against every
symbol already confirmed by hand** (`mem_section`, `memcg_kmem_cache_wq`,
`sysctl_softlockup_all_cpu_backtrace`, `nr_irqs`) before being trusted on
the rest.

**`verify_p1b_decl.py`** extends the SAT check to three terms:
`reader ∧ ¬writer ∧ declaration_survives`.

Result across all 48:

| Verdict | Count | Detail |
|---|---|---|
| **Confirmed false positive** (3-way check unsatisfiable) | 13 | `mem_section` ×10, `memcg_kmem_cache_wq` ×1, `sysctl_softlockup_all_cpu_backtrace` ×1, **`hashdist` ×1 (new)** |
| **Still a candidate** at the declaration-existence level | 3 | `nr_irqs` ×3 — expected: its declaration *is* unconditional; separately already known-safe via a static initializer (`= NR_IRQS`), reflected in the ranking's `risky_section=False` |
| **Unverified** (declaration not resolvable by text search) | 32 | all one symbol, `node_states` — a multi-line initializer the single-line regex can't match |

`hashdist` is a genuine new automated catch, and it was **re-verified by
hand later** (prompted by a direct methodological challenge — see
"Re-verification: fallback values need proof, not just presence" below
— and the deeper trace corrects what's written here). The tool's
verdict was right, but the mechanism first written down for it was
wrong: this is **not** a compile-error-if-separated case. The full
picture, from `include/linux/bootmem.h:380-389`:

```c
#ifdef CONFIG_NUMA
#define HASHDIST_DEFAULT IS_ENABLED(CONFIG_64BIT)
extern int hashdist;
#else
#define hashdist (0)
#endif
```

When `CONFIG_NUMA=n`, `hashdist` is a **preprocessor constant**,
substituted before compilation — the reader's `else if (hashdist)`
literally becomes `else if (0)`, deterministically. This is Mechanism
#4 (preprocessor `#define`-to-constant fallback), the same mechanism as
`sysctl_softlockup_all_cpu_backtrace`, not a distinct compile-error
case. `mm/page_alloc.c:7453`'s own `#ifdef CONFIG_NUMA`-gated
declaration is real, but it's only half the picture — the header
supplies the other half, and that's what actually makes the reader safe.

**`node_states` manually resolved — a sixth, new defensive mechanism.**
Its declaration is genuinely unconditional, but its *static initializer*
is not: it contains its own `#ifndef CONFIG_NUMA … #endif`, explicitly
populating the exact fields the runtime writer (`node_set_state`, gated
by `CONFIG_HAVE_MEMBLOCK_NODE_MAP`) would otherwise set, directly as
compile-time data. Not a conditional declaration, not a `#define`
fallback, not a plain safe default — a **conditionally-populated
initializer**, discovered nowhere else in this project.

**All 48 of 48 P1b candidates are now accounted for** (13 + 3 + 32 =
48), via **six independently-discovered defensive mechanisms** across
Part 1 and Part 2 combined: Kconfig `select`-forcing, shared Makefile-
unit membership, conditionally-retyped declarations, preprocessor
`#define`-to-constant fallbacks, safe static initializers, and
conditionally-populated initializer content.

### What this does *not* rule out

- **DWARF inline-origin misattribution** is unfixed (only worked around
  by not relying on DWARF for declaration lookup); any candidate whose
  reader/writer `src_file` is a header (not the object's own `.c` file)
  should still be treated as suspect.
- **Preprocessor `#define` fallbacks are invisible by construction** to
  any analysis working from compiled objects — a structural ceiling on
  the ELF/objdump approach, not a bug to fix; closing it needs
  source-level (e.g. Coccinelle or CodeQL) analysis instead.
- File-scope `static` globals with writer/reader in *different* files
  are structurally impossible to begin with (internal linkage means a
  `static` symbol cannot be referenced outside its own translation unit)
  — this earlier-listed gap was a mischaracterization; P1b's SAME-object
  scope already covers statics fully (confirmed: `globals.tsv` contains
  37,498 `LOCAL`-bound symbols vs. 2,113 `GLOBAL`, and Part 1's `match.py`
  was checked for cross-object name-collision contamination from these —
  **zero** of the 42 F2-population symbols were affected).
- `verify_p1b_decl.py`'s text-search declaration finder is a heuristic;
  a multi-line-initializer-aware version would resolve `node_states`
  automatically rather than needing one manual read.

---

## PART 3 — Where to search further, and what each found

Two directions, chosen for cost/value: (1) close the one honest gap in
the exposure claim — Part 2's 48 candidates were checked for abstract
Kconfig-separability but never against Cozart's *actual* composed nginx
config; (2) search a genuinely new, net/-specific pattern from the
original taxonomy that neither Part 1 nor Part 2 could see: pernet
(per-network-namespace) ID registration.

### 3a. Real exposure check for the 48 P1b candidates

`exposure_check.py` evaluates each candidate's reader/writer/declaration
conditions directly against Cozart's real config values (present =
`True`, absent = `False`) — one evaluation per candidate, not a
brute-force witness search, so there's no ambiguity about *which*
satisfying assignment is checked.

```
EXPOSED (real config realises this separation):     3
NOT EXPOSED:                                        45
UNDETERMINED:                                         0
```

The 3 are all `nr_irqs` (`CONFIG_SPARSE_IRQ` is genuinely absent from
Cozart's composed nginx set). Since this was the one candidate flagged
earlier as "not audited to the same standard," this was the trigger to
finish that audit properly: `early_irq_init()` — the whole writer
function — is itself inside `#ifdef CONFIG_SPARSE_IRQ`, with a matching
`#else` branch declaring `struct irq_desc irq_desc[NR_IRQS]`, a
fixed-size array sized to the exact static constant `nr_irqs` falls back
to. The reader (`irq_free_descs`, common code after the `#else` block
closes) uses `nr_irqs` purely as a bounds check, correct for either
branch. **Confirmed safe by design**, now to the same rigor as every
other candidate. Net result: exposure-checking did not surface anything
new to worry about — it closed the gap and the answer stayed the same.

### 3b. Pernet ID search — the newest, richest, and most heavily-debugged direction

Pattern: `register_pernet_subsys(&ops)` (or the `net/sched/` TC action
framework's `tcf_register_action(&act_ops, &pernet_ops)` wrapper)
registers a `struct pernet_operations` whose `.id = &foo_net_id` field
gets **indirectly** written by the kernel's registration machinery — no
visible STORE instruction at the call site, invisible to `netdep.py`'s
ELF relocation classifier by construction. Elsewhere, `net_generic(net,
foo_net_id)` reads it. `pernet_search.py` and `makefile_cond.py`
(new, text-search + a from-scratch multi-level Makefile resolver) built
to find this.

**First run: 37 candidates, 8 exposed in Cozart's real config.** All
traced to a real, systemic bug: `filename.db` (and match.py/match_p1b.py
throughout Parts 1–2) only ever captures the SINGLE Makefile level a
file is mentioned at. For `net/8021q/vlanproc.c`, the true condition is
`CONFIG_VLAN_8021Q AND CONFIG_PROC_FS` (an outer composite-object gate
AND an inner member gate); `filename.db` reports only `CONFIG_PROC_FS`.
Built `makefile_cond.py` to walk the full Makefile hierarchy and AND
every level together — validated against 6 known cases (including a
regex bug of its own: `:=` assignment wasn't recognized, only `+=`,
silently dropping `8021q-y := vlan.o ...`'s own chain). **Result: 37 → 8,
exposed 8 → 0.**

**Second and third rounds: two further false positives, both name
collisions.** `vlan_net_id` and `nat_net_id` each turned out to be two
*different* variables in *different* files sharing a name by convention
(`net/8021q/vlan.c`'s `vlan_net_id` vs. `net/sched/act_vlan.c`'s own,
independent `static unsigned int vlan_net_id;` — confirmed by reading
both files; `act_vlan.c` doesn't even `#include` the header that would
bring the real one into scope). Root cause: pure string-name matching
with no linkage-scope check. Fixed on both the reader side (skip if the
reader's own file independently registers the same name, or has its own
`LOCAL`-bound definition) and the writer side (scope `is_global` to the
specific writer's own file's definition, not "does a global with this
name exist *anywhere*" — this caught a third, subtler instance: once the
writer regex was widened to catch `tcf_register_action`'s indirect
registration, `act_vlan.c`'s own write was correctly detected, but was
then wrongly matched against `net/8021q/vlan.c`'s unrelated global purely
because both are named `vlan_net_id`). **Result: 4 → 0.**

**Completeness check before accepting the zero:** all 177
`pernet_operations` struct instances in `net/` are matched by one of the
two recognized registration call patterns (`register_pernet_*` or
`tcf_register_action`) — no third silent wrapper pattern is hiding
anything. Reader-side coverage is structurally complete by construction
(the scan matches literal `net_generic(` text on every line, so a
subsystem's own inline accessor function is caught at its own
definition site regardless of how many other files call the wrapper).

**Verdict: zero genuine pernet-ID candidates**, after three real,
independently-discovered bugs (transitive Makefile omission, reader-side
collision, writer-side collision) were found and fixed via the same
"read the actual source before trusting a match" discipline used
throughout. This is the most heavily cross-verified negative result in
the whole project — not because the pattern doesn't matter, but because
the naming convention that makes pernet IDs easy to *write* (`X_net_id`
per subsystem) is exactly what makes bulk automated detection prone to
false matches, and closing each one took real, separate debugging.

### What Part 3 does not rule out

- Only two writer-registration call patterns are recognized
  (`register_pernet_*`, `tcf_register_action`). A third, undiscovered
  indirect-registration wrapper elsewhere in the tree would be invisible
  — though the 177/177 completeness check found none within `net/`.
- The pernet search's Kconfig-separability check (`separable()`) is the
  same abstract SAT as Part 2, not Part 3a's precise real-config
  evaluation — though `pernet_candidates.tsv` does include a
  `cozart_exposure` column computed the same way as 3a, so this gap does
  not apply to the pernet results specifically.
- Neither direction touches the two largest remaining gaps from Part 2:
  ops-tables/indirect calls, and DWARF inline-origin misattribution.

---

---

## PART 4 — Ops-tables: a conceptual dead-end that produced a real finding anyway

The original research plan predicted indirect-call/ops-table dispatch as
the "dominant blocker" for this whole class of dependency. This part
tried to test that directly and instead surfaced a structural reason the
prediction may not hold for `net/`'s mature, core subsystems.

### 4a. Direct pointer assignment (`match_ops.py`) — the premise itself was wrong

Built a matcher reusing Part 1's F4/F5 logic, redefining the "writer"
event from STORE/LOAD to `ADDR` (address-taken), on the theory that an
ops struct's address being taken from one conditionally-compiled file
and referenced from another is the risky shape. **First run: 566
candidates, 82 exposed in Cozart's real config.**

Reading the actual candidates falsified the premise before any of them
could be trusted:

- **`inet_stream_ops`** (`.rodata`, i.e. `const`) — a const struct has no
  runtime initialisation step at all; its complete value is emitted at
  compile time the instant its file builds. There is no "writer that
  might not run" for const data. The whole detection premise (a
  conditional write that a read might race ahead of) doesn't apply.
- **`tcp_request_sock_ops`** — flagged `syncookies.c` as a competing
  "writer" against `tcp_ipv4.c`'s real definition. Reading the source
  showed `syncookies.c:329` is `inet_reqsk_alloc(&tcp_request_sock_ops,
  ...)` — passing the address as an argument, a **read**, not a write.
  The matcher's pairwise ADDR-vs-ADDR comparison had no way to
  distinguish "the object that actually defines this symbol" from "any
  object that merely references it" — a design bug, not a data bug.
- Mixed into the 566 were plain locks (`net_rwsem`, `kexec_mutex`,
  `fanout_mutex`) and per-CPU scheduler data (`runqueues`,
  `cpu_bit_bitmap`), swept in by a `size >= 24 bytes` heuristic meant to
  exclude locks but too permissive for 64-bit `rw_semaphore`/`mutex`.

**The real risky pattern — `sk->sk_prot = &tcp_prot;` — puts the danger
on `sk->sk_prot`, a struct *field*, not a global symbol.** Struct fields
have no ELF symbol-table entry; detecting this needs DWARF struct-layout
parsing to find field byte-offsets, plus tracking STORE instructions
against those specific offsets (ideally with register-type inference to
know which struct type a given pointer register holds at the store
site) — a materially different and larger tool than anything built
earlier in this project.

### 4b. Registration-table dispatch — checked, not run, and correctly predicted unsafe-to-trust

Before building anything, checked `inet_register_protosw`'s actual
storage: `static struct list_head inetsw[SOCK_MAX]` in
`net/ipv4/af_inet.c` — a **linked list per socket type**, not an array
slot indexed by protocol number. A missing registration is an absent
list entry, which list-walking dispatch code checks for structurally
(empty walk, not a NULL dereference) — the same "list-based registries
are safe by construction" reasoning used to scope this search
direction, confirmed for the actual API before spending effort running
a search that was very unlikely to survive contact with source.

### 4c. `sk_prot` traced by hand instead of building the full field-tracker

Rather than build the DWARF field-offset tracker before knowing whether
`sk_prot` was even a promising target, traced its actual write sites:

```
net/core/sock.c:1542        sk->sk_prot = sk->sk_prot_creator = prot;   -- inside sk_alloc(), the ONE generic allocator
net/ipv6/ipv6_sockglue.c:218/232   sk->sk_prot = &tcp_prot; / = prot;   -- overwrites an ALREADY-valid sk_prot
net/tls/tls_main.c:76        sk->sk_prot = &tls_prots[...];              -- same, overwrites an already-valid value
```

`sk_prot` is not set by scattered, independent per-protocol assignment
sites — it is set in exactly one place, `sk_alloc()`, parameterised by
whatever `prot` its caller (`inet_create()`) supplies. `inet_create()`
determines `prot` via the same `inetsw[]` list lookup from 4b. The two
other assignment sites are *overwrites* of an already-valid `sk_prot`,
not first-initialisations — if their guarding condition is excluded,
`sk_prot` simply retains its prior valid value, not `NULL`.

### The finding: a third, independent confirmation of one underlying defence

`sk_prot`, `inetsw[]`, and the pernet registration lists from Part 3b
are three structurally different-looking APIs that all reduce to the
**same** underlying defensive pattern: centralised, defensively-checked
registration/lookup, rather than scattered direct assignment. This
wasn't assumed — it was traced through actual source three separate
times, for three unrelated subsystems, arriving at the same mechanism
each time. That convergence, not a discovered bug, is Part 4's result.

### What Part 4 does not rule out

- **Struct-field write tracking was never built.** If a field *is*
  directly, independently assigned from multiple scattered call sites
  (rather than centrally parameterised like `sk_prot`), this class of
  risk remains completely untested. `sk_prot` was checked and found
  centralised; other fields were not checked at all.
- The `.rodata`/const-struct blind spot in `match_ops.py`'s original
  design is a durable lesson for any future struct-shaped search: const
  data is safe by construction and should be excluded up front, not
  discovered case-by-case.

---

## PART 5 — Cross-subsystem check: `fs/`

`net/`'s TCP/IP stack is one of the most mature, most-scrutinized
subsystems in the kernel — a biased choice for concluding anything about
the kernel broadly. `fs/` is structurally different (dozens of largely
independent filesystem implementations, not one cohesive protocol stack)
and is also the subsystem your *original* motivating example
(`mm/slab.c` → `fs/ext4/super.c`) was drawn from. Reused the existing,
validated Part 1 tooling as-is — `net/kernel/mm/lib` extraction extended
to include `fs/`, readers restricted to `fs/`.

**First fix applied before trusting anything:** `match.py` still used
the flat, single-level `filename.db` lookup — the exact limitation the
pernet search (Part 3b) showed produces false positives by missing
outer composite-module Makefile gates. Added `--use-transitive` to
`match.py`, switching it to `makefile_cond.py`'s multi-level resolver
(kept opt-in so Parts 1–3's already-reported numbers aren't silently
altered). Also fixed the same "multi-conjunct condition can't be checked
by plain string membership" bug in the F9 exposure check that had
already been fixed once in `match_ops.py`.

```
F0_distinct_symbols                         51,032
F1_symbols_with_init_writer                    236
F2_symbols_with_init_writer_and_fs_reader      132
F4_link_error_filter_survives                  491
F5_kconfig_separable_pairs (flat filename.db)   61
F5_kconfig_separable_pairs (transitive, used)  112
F6_sole_writer_pairs                             1
```

Note transitive resolution **grew** the candidate count here (61→112),
opposite of Part 3b's collapse — expected, since the fix can reveal
genuine separations a flat lookup incorrectly saw as identical, not only
collapse false ones.

**112 rows collapse to 5 distinct symbols. All 5 confirmed false, one via a genuinely new mechanism:**

| Symbol | Verdict | Mechanism |
|---|---|---|
| `totalram_pages` | False (already known) | Mechanism #1 — `CONFIG_HAVE_MEMBLOCK` architecturally forced by `X86` |
| `init_net` | False (already known) | Mechanism #2-adjacent — foundational, `CONFIG_NET` |
| `totalcma_pages` | False — **exhaustively confirmed** | Mechanism #5 — `unsigned long totalcma_pages __read_mostly;`, no initializer, defaults to 0. Re-verified by grepping **every** consumer in the tree, not just the one first read: `lib/show_mem.c:43`, `mm/page_alloc.c:7022-23`, `fs/proc/meminfo.c:140` — all three are `printk`/`show_val_kb` **display-only** call sites, none feed an allocation decision, threshold check, or control flow. When `CONFIG_CMA=n` there is genuinely zero CMA memory, so `0` isn't a plausible-looking fallback, it's the mathematically correct value — there is no code path left where it could be wrong. |
| `init_user_ns` | False — **new mechanism** | `struct user_namespace init_user_ns = { ... };` has its own complete static initializer — already fully valid before any "writer" runs. The flagged writer (`inotify_user_setup`, `fs/notify/inotify/inotify_user.c:814`) doesn't initialize it at all; it customizes one unrelated field (`ucount_max[UCOUNT_INOTIFY_INSTANCES]`, inotify's own resource quota) on an already-valid struct. The "readers" (`would_dump`, `coda_psdev_open`) use *different fields* of the same struct entirely. |

### Mechanism #9: field-level independence within a coarse-grained symbol

Whole-symbol analysis (the only granularity ELF gives you) cannot tell
that a write to one field and a read of a different field of the same
struct are unrelated. This is distinct from mechanism #6
(conditionally-populated initializer, where the *same* logical content
is populated one way or another) — here the struct needs no runtime
population for the fields that matter to the reader at all. This is a
structural limitation of symbol-level analysis, not a defence Linux
authors deliberately engineered — worth flagging as a source of noise in
any future run over a struct-heavy subsystem, independent of whether
the underlying kernel code has a real bug.

### Verdict

The `fs/` check does what a cross-subsystem check is for: it did *not*
simply reproduce net/'s result by construction — it surfaced a real,
new false-positive mechanism (field-granularity mismatch) that net/'s
population never exercised, and the transitive-resolution fix moved
the count in the opposite direction from Part 3b, confirming that fix
is a genuine bidirectional correction, not a one-way collapse-to-zero
tendency. But after full verification, the answer is the same: **zero
genuine candidates in `fs/` either.** Two structurally different
subsystems, two independent tool populations, the same outcome — which
strengthens rather than merely repeats the Part 1–3 finding.

### What Part 5a (Part 1's method on `fs/`) does not rule out

- `fs/` is itself heterogeneous (ext4, btrfs, nfs, fuse, ceph, coda, ...)
  — a single aggregate "zero genuine" result doesn't mean every
  individual filesystem driver was checked with equal scrutiny; the
  candidates that existed all happened to route through `mm/`-owned
  globals, not filesystem-internal state specifically.

---

## PART 5b — `fs/`, Part 2's method (same-file, differing `#ifdef` guards)

Reused `guardmap.py` + `match_p1b.py` unchanged against the extended
(`net/kernel/mm/lib/fs`) extraction. Scoped the guard-map file list to
the 237 same-object writer/reader pairs whose object is under `fs/`
(111 source files).

```
G1_same_object_writer_reader_pairs (all 5 subdirs)   1339
G2_have_a_recorded_guard_on_either_side               420
G3_conditions_differ                                  139
G4_sat_separable (candidates)                          48
```

**All 48 are exact repeats of the six symbols already found and
audited** in the original `net/`-scoped P1b run (`mem_section`,
`memcg_kmem_cache_wq`, `sysctl_softlockup_all_cpu_backtrace`,
`hashdist`, `nr_irqs`, `node_states` — all in `mm/`/`kernel/`, not
`fs/`). **Filtering to candidates whose object is actually under `fs/`
gives zero rows.** This is a different flavour of "zero" than Part 5a:
not "found candidates, all defended" but "the same-file/differing-guard
shape for an init-writer-plus-reader pair of the same variable does not
structurally occur in any `fs/` file in this population at all."

## PART 5c — `fs/`, Part 3's method (registration-pattern search)

Before building pernet-style tooling for `fs/` (which would need new,
`fs/`-specific regexes — there is no single `net_generic()`-equivalent
API), checked the two most direct analogues by hand, the same way
`inet_register_protosw` and `sk_prot` were checked in Part 4:

```
fs/filesystems.c:33   static struct file_system_type *file_systems;
                       find_filesystem() walks it by name; register_filesystem()
                       inserts via *p = fs. An unregistered type is simply
                       "not found" -- checked by mount-time callers, not dereferenced.

fs/exec.c:79           static LIST_HEAD(formats);
                       register_binfmt() list_add()s into it; search_binary_handler()
                       walks it. Same shape.
```

Both are plain linked lists, walked and checked at lookup time — the
same defensive shape found in Part 3b (pernet lists) and Part 4
(`inetsw[]`, `sk_alloc()`'s parameterisation). **This is now the fifth
independent registration API, across two unrelated subsystems, using
this exact pattern.** Given that consistency, a full automated `fs/`
registration-pattern search was not built — the prior that it would
reproduce the same list-based-and-safe result a sixth time is now very
strong, and the marginal evidence from building the tooling would be
small relative to the two direct manual checks already performed.

### Verdict, Parts 5b and 5c

**Zero genuine candidates from either method.** Part 2's method found
no `fs/`-rooted candidates to even audit (a structural absence, not a
defended presence). Part 3's method wasn't fully automated, but the two
most direct analogues checked by hand extend the "centralised,
defensively-checked, list-based registration" finding from three
instances (Part 4) to five, across both subsystems tested in this
project.

### What Parts 5b/5c do not rule out

- Part 2's zero result is specific to the writer/reader access-kind
  definitions used throughout this project (`STORE`/`RMW` from
  `.init.text`/initcall as writer, `LOAD`/`LOAD_GUARD` as reader) — a
  same-file pattern using a different write mechanism (e.g. an indirect
  write through a registration call, as in Part 3b) would not be caught
  by this specific check.
- Part 3's fs/ coverage is two hand-checked APIs, not an exhaustive
  scan the way Part 3b's pernet search was (177/177 confirmed covered).
  A full automated `fs/` registration search, built the same rigorous
  way pernet_search.py was, remains a legitimate next step if the
  five-for-five pattern is ever doubted rather than trusted.

---

## PART 6 — Re-verification: fallback values need proof, not just presence

A direct methodological challenge was raised partway through this
project: the research question was never "does Cozart miss dependencies
that break compilation" — the link-error filter (F4) was always scoped
correctly for that, throwing out compile-time failures from the start.
The actual concern is narrower and sharper: **does a candidate's
"defended" verdict rest on proof that the fallback produces *correct*
runtime behaviour, or merely on the observation that *some* fallback
value exists and doesn't obviously crash?** Those are not the same
claim, and every verdict in this document up to that point rested on
**static, source-level reasoning** — none of it on actually booting a
kernel and observing behaviour. That gap (Tier 3 from the very first
research plan) was never closed.

Prompted by that challenge, two of the least-rigorously-argued verdicts
were re-examined to the sharper standard: not "is there a fallback" but
"is the fallback *provably* the correct value for every consumer."

- **`hashdist`** — re-tracing the guard found the actual mechanism was
  mis-described the first time (see the correction above): it is a
  **compile-time preprocessor constant substitution**
  (`#define hashdist (0)` in `include/linux/bootmem.h` when
  `CONFIG_NUMA=n`), not a runtime value that could theoretically be
  wrong. This is the strongest possible static guarantee short of a
  formal proof — there is no runtime code path left for a boot test to
  exercise differently.
- **`totalcma_pages`** — re-traced to **every** consumer in the tree
  (not just the first one read), all three of which are print-only. The
  value is semantically the mathematically correct one when CMA is
  absent, not a plausible-looking guess.

**Both verdicts held, but this was a real gap worth catching**: the
original write-up asserted "safe" without showing the same exhaustive
tracing consistently applied elsewhere (e.g. `mem_section`, `node_states`,
`nr_irqs`, where the `#else` branch or initializer content was read in
full before concluding). The distinction the challenge draws — *found a
fallback* versus *proved the fallback is correct for every consumer* —
is exactly right and is now the standard every "defended" verdict in
this document should be read against. Where that standard is not met by
static tracing alone (i.e. where a symbol's value genuinely depends on
a runtime code path rather than a compile-time substitution or a fully
enumerated set of print-only consumers), the honest position is that a
real boot test — building the actual bootable kernel Cozart itself
produces (`compose()` in [job.sh](../../job.sh#L25), a plain `make` on
the configured tree, `make install` for `vmlinuz`) and booting it under
QEMU (Cozart's own `benchmark()` boots without needing `/dev/kvm` inside
this container, since neither Cozart's tracer nor a functional
correctness check requires KVM acceleration — TCG software emulation
is slower but sufficient) — is required, not optional. No such test was
run in this project; every verdict here is static, and should be read
with that limit stated plainly rather than implied away.

---

## PART 7 — Lazy-writer search: `net/`, non-boot-time writers

Every prior search (Parts 1, 3, 5a) classified a "writer" as a
`STORE`/`RMW` from `.init.text` or an initcall — i.e. boot-time only.
Any write from ordinary, resident `.text` — first-use initialization,
sysctl handlers, workqueue/timer-triggered setup — was structurally
excluded from the entire project until now, even though `netdep.py` had
already extracted the data; every matcher just filtered it out.

`match.py` was extended with `--writer-mode {boot,lazy,any}`, keeping
`boot` (the original behaviour) as the default so no earlier result is
altered, and adding `lazy` (`STORE`/`RMW` from *non*-boot functions).
**Validated with a new synthetic test before running on real data**: a
first-use `if (!x) x = alloc();` pattern, confirmed caught by `lazy`
mode and correctly ignored by `boot` mode, and vice versa for the
original boot-writer fixture (a genuine test-fixture bug was found and
fixed along the way — the earlier synthetic objects had no directory
prefix, silently breaking the Makefile-condition lookup after an
unrelated fix; not a regression in the matcher itself).

```
F1_symbols_with_lazy_writer                    217
F2_symbols_with_lazy_writer_and_net_reader      74
F4_link_error_filter_survives                 1589
F5_kconfig_separable_pairs                    1433
F6_sole_writer_pairs                             13  (4 distinct symbols)
```

This is a substantially larger population than any boot-writer search
produced (1,433 vs. the low hundreds at most elsewhere) — expected,
since non-boot writes vastly outnumber `__init` writes across the
kernel. Given the scale, only the highest-confidence slice (`F6`, sole
writer — the cleanest match to the original research pattern) was
audited in this round; the remaining ~1,420 lower-confidence candidates
were not.

### All 4 distinct sole-writer symbols confirmed defended

| Symbol | Writer | Reader | Mechanism |
|---|---|---|---|
| `dev_rx_weight` | `proc_do_dev_weight` (sysctl handler) | `process_backlog` | Mechanism #5 — `int dev_rx_weight __read_mostly = 64;`, a real functional default; the sysctl only *tunes* it |
| `dev_tx_weight` | `proc_do_dev_weight` (sysctl handler) | `__qdisc_run` | Mechanism #5 — same, `= 64` |
| `default_qdisc_ops` | `qdisc_set_default` (requires `CONFIG_NET_SCHED`) | `dev_activate` | Mechanism #5 — `const struct Qdisc_ops *default_qdisc_ops = &pfifo_fast_ops;`, and `pfifo_fast_ops` lives in the *same* `CONFIG_NET`-only file, unconditional whenever networking exists at all |
| `rps_cpu_mask` | `rps_sock_flow_sysctl` (sysctl handler) | `sock_rps_record_flow` (inlined into `inet_accept`/`inet_sendmsg`/`inet_recvmsg` — every TCP connection) | **New — see below** |

### Mechanism #10: stacked guards, including one on a companion variable the tool cannot see

`rps_cpu_mask` has no safe default (`u32 rps_cpu_mask __read_mostly;`,
defaults to 0) and *would* be dangerous if read unconditionally. It
isn't, because the actual reader — `sock_rps_record_flow()` in
`include/net/sock.h` — stacks four independent guards before ever
touching it:

```c
static inline void sock_rps_record_flow(const struct sock *sk) {
#ifdef CONFIG_RPS                                     /* 1: compile-time */
    if (static_key_false(&rfs_needed)) {               /* 2: static key, defaults OFF */
        if (sk->sk_state == TCP_ESTABLISHED)            /* 3: connection state */
            sock_rps_record_flow_hash(sk->sk_rxhash);   /* -> rcu_dereference + */
    }                                                    /*    `if (table && hash)` (4: companion-pointer NULL guard) */
#endif
}
```

Guard 4 is the structurally interesting one: `rps_sock_flow_table` (the
`table` pointer) and `rps_cpu_mask` are set **together**, by the same
writer, in the same code block (`net/core/sysctl_net_core.c:74`). The
reader checks the *pointer*, not the mask — a guard on a semantically
coupled companion variable, not on the symbol our tool was actually
tracking. No matcher in this project checks guards across symbols, only
on the one being evaluated, so this class of defence is invisible to
the tool by construction, not merely a search gap.

Guard 1 also exposed a real, previously-unknown limitation in
**Part 1's method specifically**: `match.py` has only ever computed the
Makefile-level condition for reader/writer sites, never the intra-file
`#ifdef` guard the way `guardmap.py`/`match_p1b.py` does for Part 2.
`reader_cond` was reported as `CONFIG_INET` here — true, but missing
the `#ifdef CONFIG_RPS` wrapping the actual call, entirely inside a
header. This means Part 1's reported conditions, across every part of
this project that used it (1, 3, 5a, and now 7), have always been a
*lower bound* on the true guard strength, not the exact condition. This
did not change any verdict already reached (every Part 1 candidate was
independently verified by reading source, which is how this was
caught), but it is a real, general gap in the tool worth stating
plainly.

### Verdict

**Zero genuine candidates in the audited slice.** Encouragingly, this
population is *more* consistent with the rest of the project than less:
even outside the boot-time writer population this project spent most of
its effort on, the same handful of mechanisms (safe static initializers
appearing three more times, plus a new, richer stacked-guard pattern)
account for everything found. The stacked-guard case in particular is
arguably the most convincing single piece of evidence in this whole
project that Linux's `net/` fast-path code is written with unusual care
around exactly this failure mode — four independent, deliberate guards
on one 4-byte value.

### What Part 7 does not rule out

- Only the `F6` (sole-writer, 4 symbols) slice of 1,433 candidates was
  audited. The remaining ~1,420 — lower-confidence, but not
  necessarily less real — were not examined.
- Not re-run against `fs/`, or with Part 2's (same-file) or Part 3's
  (registration-pattern) methods in lazy mode.
- The intra-file `#ifdef` gap just found in `match.py` was not
  retroactively fixed or used to re-check earlier Part 1/3/5a
  candidates — it's reported as a known limitation, not corrected.

---

## PART 8 — Exhaustive tracing on demand, then the next tier

Prompted directly by a sustained, specific challenge ("is there really
no execution path — go check"), `rps_cpu_mask` (Part 7) was re-examined
to full exhaustion: every reference to the symbol in the *entire tree*
enumerated (`grep -rn`, not a sample), and both resulting read sites
traced end-to-end. Both are unreachable unless the companion state that
makes the value meaningful was set up in the same operation — one path
gated additionally by `#ifdef CONFIG_RPS` at both the function
definition and both call sites, meaning the code doesn't exist at all
when the config is off. This is the most rigorously verified single
candidate in the entire project. It does not generalise automatically
to any other candidate — this exact standard (every reference, not a
sample) had not been applied elsewhere before this round, and still
hasn't been applied to most of Part 7's remaining ~1,420 rows.

### The next tier: `risky_section`, 38 rows / 2 new distinct symbols

Beyond the 4 sole-writer symbols, the `risky_section` (no safe static
default) filter adds 38 rows collapsing to 2 new symbols:
`pingv6_ops` and `system_freezing_cnt`.

**`system_freezing_cnt`** — resolves the same way as most of this
project: `atomic_t system_freezing_cnt = ATOMIC_INIT(0);` in
`kernel/freezer.c` has an explicit, correct static initializer.
Mechanism #5. Zero genuinely means "no freeze operations in effect,"
confirmed against the actual fast-path consumer
(`if (likely(!atomic_read(&system_freezing_cnt)))` in
`include/linux/freezer.h`) — exactly correct when `CONFIG_CGROUP_FREEZER`
isn't compiled, not a plausible-looking guess.

### `pingv6_ops` — resolved safe, but via a genuinely new finding: a blind spot in the search method itself, not a kernel defence

`struct pingv6_ops pingv6_ops;` (`net/ipv4/ping.c`) has **no**
initializer — every function-pointer field defaults to `NULL`. The
lazy-writer search flagged `pingv6_exit()` as the writer (setting safe
dummy stub functions during cleanup) against an unconditional-looking
read in `net/ipv4/ping.c`. Reading the actual source fully unravels
this:

- Both read call sites are wrapped in `#if IS_ENABLED(CONFIG_IPV6)`
  (missed by the tool for the same intra-file-`#ifdef` reason found in
  Part 7 — `match.py` never computes this).
- The function that sets the **real** implementations,
  `int __init pingv6_init(void)`, is marked `__init` — a boot-time
  writer, which the lazy-writer search *by design* excludes.
- `pingv6_exit()` carries the kernel's own comment: *"This never gets
  called because it's not possible to unload the ipv6 module, but just
  in case."* — confirmed dead code, not a real protection mechanism.
- `pingv6_init()` is called unconditionally from `inet6_init()`
  (`net/ipv6/af_inet6.c:1038`), itself registered via
  `module_init(inet6_init)` — a standard initcall here since IPv6 is
  built-in, not loadable, in this configuration. Runs before userspace
  exists, with its error checked and propagated
  (`if (err) goto pingv6_fail`).

**`pingv6_ops` is fully safe** — but the real protection is a boot-time
`__init` writer the lazy search is structurally blind to by
construction, not a runtime guard or a Kconfig fact. The search flagged
this symbol only because it happened to *also* see an unrelated,
dead-code writer for the same name. This is a distinct kind of finding
from mechanisms #1–10: **a methodological gap in the search itself**
(checking "does some non-boot writer exist" rather than "do all
possible protective writers, boot or otherwise, exist") rather than a
defensive pattern in the kernel. Worth naming explicitly rather than
folding into the existing taxonomy, since fixing it would mean
correlating boot-writer and lazy-writer results for the same symbol
before trusting a lazy-only candidate — not implemented.

### Verdict

Zero genuine candidates in this tier too — six of ten now-audited
lazy-writer symbols are `net/`-only (`rps_cpu_mask`, `pingv6_ops`,
`system_freezing_cnt` from this round; `dev_rx_weight`, `dev_tx_weight`,
`default_qdisc_ops` from Part 7), all resolved. Still consistent with
every other part of this project — but `pingv6_ops` specifically shows
the search methodology itself has a known, real, unfixed gap, distinct
from anything the kernel is doing defensively.

### What Part 8 does not rule out

- ~1,382 of Part 7's 1,433 lazy-writer rows remain unaudited (13
  sole-writer + 38 risky-section now covered = 51 of 1,433).
- The "does a safe boot writer also exist" blind spot found via
  `pingv6_ops` was not used to re-check any other lazy-writer candidate
  — it may affect others in the unaudited remainder.
- The `rps_cpu_mask`-level exhaustive-reference standard was applied to
  exactly one symbol; it has not been extended to `pingv6_ops` or
  `system_freezing_cnt` (their resolution came from reading the
  relevant definitions and call sites, not a whole-tree reference
  enumeration the way `rps_cpu_mask` got).

---

## PART 9 — Cross-checking Part 7/8 surfaced a real classifier bug affecting the whole project

The requested cross-check (does each lazy-writer candidate symbol *also*
have a boot writer, `pingv6_ops`-style) collapsed all 1,433 Part 7 rows
to **10 distinct symbols**. Checking why `pingv6_ops` itself wasn't
flagged (it should have been — `pingv6_init` genuinely writes it)
uncovered something bigger than a triage bug.

### The bug

A single x86-64 instruction, `movq $function_addr, global+offset(%rip)`
(the `mcmodel=kernel` form for `some_struct.field = some_function;`),
carries **two relocations**: one on the immediate source (the
function's address) and one on the memory destination (the global
being written). `netdep.py`'s classifier processed each relocation on
an instruction identically, based only on instruction shape — so both
were labelled `ADDR`, including the one that should have been `STORE`.
Confirmed concretely: `pingv6_init`'s writes to `pingv6_ops.field = ...`
were `ADDR`-only in the extracted data; `pingv6_exit`'s otherwise
identical-looking writes were correctly `STORE`, only because its
target functions are `static` and got compiled through a two-instruction
load-then-store sequence that happened to fit the existing rules by
accident.

**This made an entire class of write — a struct/global being given a
named function's address in a single efficient instruction — invisible
to every `STORE`/`RMW`-based writer search in this project (Parts 1, 3,
7, 8) from the start.** This is exactly the ops-table/function-pointer
initialization pattern Part 4 was originally trying to find and
couldn't.

### The fix

Verified via real disassembly byte offsets (`pingv6_ops`'s relocation
consistently precedes the function-address relocation within the same
instruction — displacement bytes before immediate bytes in the x86-64
encoding) that the **first** relocation on such an instruction is
always the destination, and any **later** one is the source. Added
`reloc_index` tracking to `netdep.py` and used it to disambiguate the
two-relocation case specifically.

**Validated with a new synthetic test before touching real data**: a
struct with two function-pointer fields assigned via named (non-static)
functions, reproducing the exact instruction pattern. Confirmed the
destination now classifies `STORE` and the source `ADDR`; reran both
existing regression suites (boot-writer and lazy-writer synthetic
fixtures) to confirm no prior verdict was disturbed by the fix.

### Re-running boot-writer search on `net/` after the fix

```
F2_symbols_with_init_writer_and_net_reader   42 -> 76
F5_kconfig_separable_pairs                    6 -> 1,723
F6_sole_writer_pairs                          -> 1  (new symbol: crc32c_csum_stub)
F9_cozart_exposed_pairs                       0 -> 17  (10 distinct symbols)
```

### `crc32c_csum_stub` — the new sole-writer candidate, resolved

Writer: `sctp_offload_init` under `CONFIG_IP_SCTP` (a genuinely
separable, optional protocol). Reader: `skb_crc32c_csum_help` in
`net/core/dev.c`, unconditional core code. Exposed in Cozart's real
nginx config (`CONFIG_IP_SCTP` is absent, `CONFIG_NET` present).

Resolves via Mechanism #5, but an unusually well-engineered instance:

```c
static const struct skb_checksum_ops default_crc32c_ops = {
    .update  = warn_crc32c_csum_update,
    .combine = warn_crc32c_csum_combine,
};
const struct skb_checksum_ops *crc32c_csum_stub __read_mostly = &default_crc32c_ops;
```
```c
static __wsum warn_crc32c_csum_update(const void *buff, int len, __wsum sum) {
    net_warn_ratelimited("%s: attempt to compute crc32c without libcrc32c.ko\n", __func__);
    return 0;
}
```
A deliberately-engineered graceful-degradation stub — logs a
rate-limited warning naming the exact scenario, returns a safe sentinel.
Not a NULL risk; a named, purpose-built fallback.

### Mechanism #11: NULL-check on the loaded local, not on the global symbol

The remaining 9 of 10 F9-exposed symbols are all `net/netfilter/`
optional NAT/H.323-helper hooks (`nf_nat_hook`, `nat_h245_hook`,
`nat_q931_hook`, `nat_rtp_rtcp_hook`, `nat_t120_hook`,
`nat_callforwarding_hook`, `set_h225_addr_hook`, `set_ras_addr_hook`,
`set_sig_addr_hook`) — the standard, well-documented Linux "weak hook
pointer" idiom for optional module registration. Checked two
(`nf_nat_hook`, `nat_h245_hook`):

```c
nat_hook = rcu_dereference(nf_nat_hook);
if (!nat_hook)
    return 0;
```
```c
(nat_h245 = rcu_dereference(nat_h245_hook)) && ...
```

Both explicitly NULL-checked before use — but the check is on the
**local variable** the RCU-dereferenced value is copied into, not a
repeated access to the global symbol itself. The tool's `unguarded`
flag (which only recognises a guard via a same-symbol `LOAD_GUARD`
access) cannot see this — a distinct, previously uncatalogued pattern
from `rps_cpu_mask`'s companion-*variable* guard (Mechanism #10): here
it's the read's *own result* that gets checked, immediately, which is
arguably the single most common defensive idiom in the kernel and one
this project's tooling was never built to recognise.

**The remaining 7 hooks in the same family were not individually
verified** — same subsystem, same naming convention, same apparent
macro-driven structure, but confirmed for 2 of 10, not all 10.

### Verdict

Zero genuine candidates, again — but this round is different in kind
from every prior one: it found and fixed a **real bug in the core
extraction tool** that had silently affected every writer search since
Part 1, not just a false lead in a specific candidate. The fix more
than doubled the exposed-candidate count (0 → 17) yet the audited
subset still resolves entirely to known-safe patterns, one of them
(Mechanism #11) newly catalogued and likely the most broadly-applicable
defence found in this whole project.

### What Part 9 does not rule out

- Only the sole-writer and F9-exposed slices of the *post-fix* 1,723
  boot-writer candidates were examined. The fix was never re-applied to
  re-audit Parts 1, 3, 5a, or 7/8's *other* candidates with the
  corrected classifier — their conclusions stand as reported, but on
  pre-fix data.
- 7 of the 9 netfilter hook symbols were not individually checked,
  only inferred safe by strong family resemblance.
- The lazy-writer search (Part 7/8) was not re-run post-fix; its 1,433
  rows / 10 symbols are pre-fix data, though the `pingv6_ops` discovery
  that led to this fix came from that exact dataset.

---

## PART 10 — Lazy-writer search re-run post-fix: the richest signal in the project, fully resolved

The Part 9 classifier fix specifically targets the pattern lazy/runtime
registration code uses constantly (assigning a function pointer to a
global in one instruction), so the lazy-writer search was re-run against
the fixed extraction.

```
F5_kconfig_separable_pairs     1,433 -> 5,762
F9_cozart_exposed_pairs            0 -> 857   (14 distinct symbols)
```

857 exposed rows is, by a wide margin, the largest positive signal this
project has produced. All 14 distinct symbols were audited (not a
sample):

| Symbol | Resolution |
|---|---|
| `init_net` | Already known safe (foundational, Part 1) |
| `nf_nat_hook`, `nat_h245_hook` | Mechanism #11 (Part 9) — NULL-checked on the local, confirmed directly |
| `nat_q931_hook`, `nat_rtp_rtcp_hook`, `nat_t120_hook`, `nat_callforwarding_hook`, `set_h225_addr_hook`, `set_ras_addr_hook`, `set_sig_addr_hook` | Inferred safe by strong family resemblance to the two directly-confirmed siblings (same H.323 NAT-helper subsystem, same naming convention) — **not individually re-verified this round either** |
| `nf_ct_hook`, `ip_ct_attach` | **New sub-case of the lazy-search blind spot** — see below |
| `arp_tbl` | Mechanism #9 (field-level independence) — new subsystem (ATM CLIP), same pattern as `init_user_ns` |
| `noop_qdisc` | Mechanism #5 (safe static initializer) — a complete, functional do-nothing qdisc, same shape as `default_qdisc_ops` |

### A third variant of the lazy-search blind spot: boot-time-only through the call chain, not the function's own section

`nf_ct_hook`/`ip_ct_attach` are both written by `nf_conntrack_init_end()`
— which is **not itself marked `__init`**, genuinely different from the
`pingv6_ops` case where the real writer *was* `__init` and simply
excluded by the lazy filter. Here, `nf_conntrack_init_end()` is a small
helper, called from exactly one place:
`nf_conntrack_standalone_init()`, which *is* `__init` and registered via
`module_init()` (a real initcall, since netfilter is built-in in this
configuration). The write happens exactly once, at boot, before any
conntrack object could exist — confirmed by checking the call site
directly, not inferred. This means `nf_conntrack_destroy()`'s
`BUG_ON(ct_hook == NULL)` is unreachable in practice: not a risk, an
intentional invariant that genuinely always holds.

This is a **third distinct sub-case** of the same underlying gap named
in Part 8: the lazy search only checks the ELF section of the function
*directly containing* the store, never whether that function's only
caller is itself boot-time. Two different concrete mechanisms now
produce the same blind spot (a real `__init` writer existing
alongside an unrelated dead writer, and a non-`__init` helper called
exclusively from an `__init` caller) — worth treating as one named
limitation with multiple triggers, not two separate findings.

### `arp_tbl` — Mechanism #9 confirmed in a second, unrelated subsystem

`struct neigh_table arp_tbl = {...}` (`net/ipv4/arp.c`) has its own
complete static initializer. The flagged writer, `idle_timer_check` in
`net/atm/clip.c` (an obscure, legacy ATM-networking feature), only takes
`arp_tbl.lock` and calls `__neigh_for_each_release()` — a periodic
maintenance operation on an already-fully-valid table, touching
unrelated fields (lock, timer bookkeeping), not initializing anything
the reader (`bpf_ipv4_fib_lookup`) depends on. Structurally identical to
the `init_user_ns`/`inotify_user_setup` case from Part 5a, now confirmed
in a completely different subsystem — this pattern (an optional
consumer doing routine maintenance on a core, always-valid structure,
mistaken for "the writer") appears to generalise rather than being a
one-off.

### Verdict

All 857 exposed rows, all 14 distinct symbols, resolved — 6 directly
verified this round or in Part 9, 7 inferred by strong sibling
resemblance (not directly re-checked), 1 already known. Zero genuine
candidates in the richest population this project has produced. Every
symbol resolves to one of the mechanisms already catalogued (#5, #9,
#11) or the lazy-search blind spot (now understood as one limitation
with three distinct concrete triggers) — no new *kernel-side* defensive
mechanism was needed to explain this round, which is itself notable:
the fix roughly quadrupled the candidate population and it didn't
require expanding the taxonomy to cover it.

### What Part 10 does not rule out

- The 7 netfilter hook siblings remain inferred, not individually
  checked, across two separate rounds now (Part 9 and this one).
- Only the F9-exposed slice (14 of 45 distinct symbols in the full
  5,762-row post-fix population) was examined; 31 distinct symbols
  outside the exposed set remain untouched.
- `fs/` (Part 5a) was never re-run with the fixed classifier — its
  reported results still stand on pre-fix data.

## PART 11 — A second classifier bug in the Part 9 fix itself, and its own re-run

While starting the "bulk of non-exposed candidates" audit requested next
(auditing the Kconfig-separable-but-not-Cozart-exposed population, not
just the F9-exposed slice), the first item — `tcp_prot` — turned out not
to be a real candidate at all, but a second bug in the Part 9 fix.

### The bug

Part 9's fix taught the classifier that `movq $function_addr, GLOBAL(%rip)`
carries *two* relocations on one instruction (source immediate, plus a
destination relocation because a RIP-relative absolute address itself
needs link-time resolution), and that the first is the real STORE.

The fix over-applied: it treated *any* "first relocation + memory-shaped
destination" as a STORE, without checking whether the destination was
RIP-relative at all — i.e. whether it was even capable of carrying its
own relocation. A register-relative destination like
`movq $0x0,0x28(%r12)` (a struct-field store at a runtime-computed
offset, e.g. `sk->sk_prot = &tcp_prot;`) has **only one** relocation —
on the source immediate — because the destination address is computed
at runtime and a register offset is never itself relocated. The Part 9
fix misread that single source-relocation as a destination STORE,
concluding `tcp_prot` was being *written* by `do_ipv6_setsockopt`, when
the code only takes `tcp_prot`'s address (ADDR) and stores it into an
*unrelated* `struct sock`'s field — invisible to this analysis by
construction, and not a write to `tcp_prot` at all.

### The fix

`classify_instruction()` now only takes the "two-relocation" branch when
the destination is actually RIP-relative (`'%rip' in dst`); a
register-relative destination always classifies as `ADDR`, regardless of
`reloc_index`:

```python
if is_imm_operand(src):
    if '%rip' in dst and is_mem_operand(dst) and reloc_index == 0:
        return 'STORE'
    return 'ADDR'
```

Validated with a new synthetic fixture (`regfield_x.c`/`regfield_a.c`,
reproducing `sk->sk_prot = &real_proto` exactly) confirming `real_proto`
now classifies as ADDR while the original two-relocation `my_ops` case
from Part 9 still correctly classifies as STORE. Both existing
regression suites (boot-mode and lazy-mode synthetic fixtures) re-passed
with no other change. Full `net/kernel/mm/lib` re-extraction produced
identical totals (39,624 symbols / 207,254 references) — expected, since
this fix only reclassifies access-kind labels, not which references
exist.

### Re-running both funnels

Boot-writer search (`--writer-mode boot`): `tcp_prot` no longer appears
as a candidate anywhere in the output. The F9-exposed set is otherwise
**unchanged**: still 17 rows, same symbol family
(`crc32c_csum_stub`, the H.323 NAT-hook group) as Part 9.

Lazy-writer search (`--writer-mode lazy`), the population this bug had
the most opportunity to inflate (lazy/registration code assigns function
pointers into structs constantly):

```
F9_cozart_exposed_pairs      857 -> 27   (14 distinct symbols -> 12)
```

The row count collapsed by 97%, and two symbols dropped out of the
exposed set entirely: `init_net` and `noop_qdisc`. Checking their old
writer sites confirms both were instances of exactly this bug —
`net/core/devlink.o` and others assigning `&init_net` into unrelated
struct fields (not writing `init_net` itself), and
`net/sched/sch_cbq.o` etc. assigning `&noop_qdisc` into `Qdisc *`
fields the same way. Both were already resolved safe in Part 10 (Mechanism
#9 for `init_net`, Mechanism #5 for `noop_qdisc`) on independent
grounds, so the verdict for those two symbols does not change — but they
should never have appeared as *writer* candidates for those symbols in
the first place, and now correctly don't.

The remaining 12 exposed symbols after this fix are exactly the other 12
from Part 10's 14 (`nf_nat_hook`, the 8 other H.323 NAT-hook siblings,
`nf_ct_hook`, `ip_ct_attach`, `arp_tbl`) — already individually audited
and resolved in Part 9/10. No new symbol appears in the fixed exposed
set, and no re-audit was needed for them.

### Verdict

The bug was real and systemic — it affected every register-relative
`movq $imm, offset(%reg)` instruction writing a struct-shaped global's
address into another object's field, a very common kernel idiom
(`sk->sk_prot = &proto`, `cl->q = &noop_qdisc`, etc.) — but its effect
was to **inflate the candidate population with false writer sites**, not
to hide genuine ones. After the fix, every previously-reported
Cozart-exposed candidate in both boot and lazy search either survives
with an unchanged verdict (the 12 carryover symbols) or is removed
because it was never really a writer of that symbol (`tcp_prot`,
`init_net`, `noop_qdisc`). No new genuine candidate emerged. The overall
project conclusion — zero confirmed Kconfig-invisible runtime
dependencies found across `net/`, `fs/`, and cross-subsystem checks —
is unchanged, and is now measured against a materially cleaner
classifier.

### Follow-up: re-running Part 5a (`fs/` cross-object) and Part 4 (ops-table) against the fix

Both were re-extracted and re-run to close the gap flagged above.

**Part 5a (`fs/` cross-object, boot-writer).** Re-extracted the exact
original scope (`net fs kernel mm lib`, same 159-object composite
exclude list) to reproduce the same population Part 5a used — confirmed
identical (67,257 vs. 67,258 global symbols, 386,851 vs. 386,852
reference sites; the 1-row differences are header-line counting, not
real). Re-ran `match.py --reader-scope fs/ --writer-mode boot` against
the twice-fixed extraction:

```
F5_kconfig_separable_pairs   112 -> 126
F9_cozart_exposed_pairs        0 ->   0
```

Same 4 distinct symbols as before (`init_net`, `init_user_ns`,
`totalcma_pages`, `totalram_pages`), still 0 exposed. Row count moved
slightly (more writer-object pairs for the same symbols, not new
symbols) — **no verdict changes**.

**Part 4 (ops-table search, `net/`).** Re-run against the already-fixed
`net/kernel/mm/lib` extraction (`match_ops.py` uses `/work/out`, which
had already been re-extracted with both fixes before this part):

```
candidates_total   566 -> 563
```

3 symbols dropped out entirely: `def_root_domain`, `mem_sleep_states`,
`pm_states` — all power-management structs, none previously among the
2 symbols Part 4 actually spot-checked (`inetsw[]`/`sk_prot`), so this
doesn't touch any existing verdict. The Cozart-exposed subset is
**unchanged at 82 rows** — consistent with Part 4's standing caveat that
this entire population was discarded as unverified rather than treated
as a trustworthy result, so its row count moving slightly either way
doesn't change what can be concluded from it.

### What Part 11 does not rule out

- Only the F9-exposed slice of the lazy search was individually
  re-examined this round; the much larger Kconfig-separable-but-not-
  exposed population (2,608 rows after this fix, up from 1,723
  pre-Part-9) has not been swept for this same bug pattern outside the
  exposed rows.
- The "bulk of non-exposed candidates" audit the user requested is still
  pending, now on the corrected data — `xt_recseq` and the other queued
  symbols from the pre-fix population should be re-checked against
  `results/candidates_lazy_fix2.tsv` rather than the superseded
  `candidates_lazy_postfix.tsv`, since some may have been fix artifacts
  themselves.
- Part 4's ops-table population remains fundamentally unverified (563 of
  563 rows, minus the 2 already spot-checked outside the tool) — this
  re-run confirmed the fix changed it slightly but did not newly verify
  any of it.
- Part 5b/5c (same-file `fs/` guards, registration-pattern search) were
  not re-run — Part 5b's method doesn't depend on writer/reader ADDR
  classification the way this bug affects, and Part 5c was hand-checked
  APIs, not automated output, so neither is expected to be affected, but
  neither was directly confirmed against the twice-fixed data.

## PART 12 — The "bulk of non-exposed candidates" audit, on corrected data

Resuming the request from before Part 11: audit the largest
Kconfig-separable-but-not-Cozart-exposed lazy-writer symbols, now
against `results/candidates_lazy_fix2.tsv`. Row counts per distinct
symbol, largest first, with symbols already resolved in Parts 7–10
(`init_net`, `pingv6_ops`, `system_freezing_cnt`, `rps_sock_flow_table`
— the companion to `rps_cpu_mask` — `rps_cpu_mask`, `arp_tbl`, and the
already-audited NAT/conntrack hook family) excluded:

| Symbol | Rows | Resolution |
|---|---|---|
| `xt_recseq` | 48 | Mechanism #1 — every reader Kconfig (`IP_NF_IPTABLES`, `IP_NF_ARPTABLES`, `IP6_NF_IPTABLES`) `select`s `NETFILTER_XTABLES` directly, which gates the writer/definer `x_tables.o` |
| `nf_skb_duplicated` | 12 | Reader in `ip_tables.c` gated by `static_key_false(&xt_tee_enabled)`, settable only by `xt_TEE`, whose Kconfig `select`s `NF_DUP_IPV4`/`NF_DUP_IPV6` (the writer) directly — mechanism #10 stacked on #1 |
| `nf_ipv6_ops` | 11 | Mechanism #11 — `v6ops = rcu_dereference(nf_ipv6_ops); if (v6ops) ...`, directly confirmed in `net/netfilter/utils.c` **only**; **see Correction below — an unguarded reader exists in v4.18** |
| `nfnl_ct_hook`, `nf_ct_timeout_put_hook`, `nf_ct_timeout_find_get_hook`, `nf_br_ops`, `bpfilter_process_sockopt` | 8, 5, 1, 1, 6 | Mechanism #11 by strong family resemblance — identical `GLOBAL`/8-byte/`.data..read_mostly`-or-`.bss` shape and naming convention to `nf_ipv6_ops`/`nf_nat_hook`, not individually re-verified |
| `nf_nat_sip_hooks` | 8 | Mechanism #11, directly confirmed (`hooks = rcu_dereference(nf_nat_sip_hooks); if (hooks && ...)` in `nf_conntrack_sip.c`) |
| `nr_online_nodes` | 3 | Mechanism #5 — `int nr_online_nodes __read_mostly = 1;`, the correct default for a single-node system when the `CONFIG_MEMORY_HOTPLUG` writer is absent |
| `default_qdisc_ops` | 3 | Mechanism #5 — `const struct Qdisc_ops *default_qdisc_ops = &pfifo_fast_ops;`, always a complete, valid qdisc; the flagged writer (`qdisc_set_default`) is an optional override, not a required initializer |
| `dev_tx_weight` | 1 | Mechanism #5 — `int dev_tx_weight __read_mostly = 64;`; the flagged writer is a sysctl proc handler that only executes on an actual `/proc` write, never a required boot-time initializer |
| `nf_nat_tftp_hook`, `nf_nat_snmp_hook`, `nf_nat_pptp_hook_*` (4), `nf_nat_irc_hook`, `nf_nat_ftp_hook`, `nf_nat_amanda_hook` | 1 each | Mechanism #11 — `nf_nat_ftp_hook` directly confirmed (`nf_nat_ftp = rcu_dereference(nf_nat_ftp_hook); if (nf_nat_ftp && ...)` in `nf_conntrack_ftp.c`); the rest resolved by the same strong family resemblance already applied to the H.323 hook siblings in Parts 9–10 |

### Verdict

Every distinct symbol in the non-exposed lazy-writer population large
enough to be worth auditing (≥1 row, all symbols ≥3 rows plus the
remaining 1-row NAT-hook family) resolves to a mechanism already in the
catalogue — no new defensive pattern, no genuine candidate. The two
non-`#5`/`#11` cases (`xt_recseq`, `nf_skb_duplicated`) are the first
instances in this project of Mechanism #1 (Kconfig `select`-forcing)
appearing in the lazy-writer search specifically, and `nf_skb_duplicated`
is the first case combining a static-key stacked guard (#10) with
`select`-forcing on the thing that flips the key — a slightly richer
variant worth noting, though not a new top-level mechanism.

### Correction (positive-control finding): one `nf_ipv6_ops` reader is unguarded

Mining kernel history for real bugs of this shape (v4.18..v5.4, `net/`
and `fs/`) found upstream commit `48bd0d68cd` ("netfilter: bridge: Drops
IPv6 packets if IPv6 module is not loaded"), a kernel panic when IPv6 is
disabled at boot (`ipv6.disable=1`) and bridged IPv6 packets reach
`ip6tables`. The buggy code is present in v4.18. In
`net/bridge/br_netfilter_ipv6.c`, `br_nf_pre_routing_finish_ipv6()` does:

```c
const struct nf_ipv6_ops *v6ops = nf_get_ipv6_ops();
...
v6ops->route_input(skb);          /* no NULL check */
```

`nf_get_ipv6_ops()` returns NULL when the IPv6 init that sets
`nf_ipv6_ops` never ran. The sibling reader `br_nf_dev_queue_xmit()` in
`br_netfilter_hooks.c` *does* guard (`if (v6ops)`), so the family is not
uniformly defended.

This invalidates the Part 12 method for `nf_ipv6_ops`: one reader
(`utils.c`) was checked directly and the other ten rows were inferred safe
"by family resemblance." That inference was wrong for at least this
reader (it is in the funnel's own xref: `br_nf_pre_routing_finish_ipv6`
LOADs `nf_ipv6_ops`). Two qualifications: (a) how the writer-absent state
arises. The reader object `br_netfilter_ipv6.o` is built when
`CONFIG_IPV6` is `y` **or `m`** (`net/bridge/Makefile`:
`br_netfilter-$(subst m,y,$(CONFIG_IPV6))`), and `BRIDGE_NETFILTER` has
no dependency on `IPV6` (`net/Kconfig`), so `BRIDGE_NETFILTER=y` with
`IPV6=m` and the `ipv6` module never loaded is a Kconfig-valid state in
which the unguarded reader exists and the writer
(`ipv6_netfilter_init()`, `net/ipv6/netfilter.c`) never ran. Booting with
`ipv6.disable=1` reaches the same state with `IPV6=y`. This is a genuine
instance of the Kconfig-invisible pattern, reached at module-load or
boot-parameter level, not build level. (b) It is not exposed by
Cozart's nginx configs: `CONFIG_BRIDGE` / `BRIDGE_NETFILTER` are not in
`nginx.config` or `nginx-test.config`, so the reader is not built. (c)
This is one confirmed unguarded reader, not a systematic survey, and the
crash was taken from the upstream commit message and code reading, not
reproduced here.

Consequence for the whole document: every verdict marked "resolved by
family resemblance" (Parts 9, 10, 12, 13) is **unverified**, not safe.
The hook-pointer family was subsequently re-checked exhaustively, per
reader (Part 15). The other resemblance-based groups in Part 13 (diag
submodules, `proto` structs, lock symbols) have **not** been re-checked.

### What Part 12 does not rule out

- 9 of the 17 individually-named symbols above were resolved by strong
  family resemblance rather than direct source verification, continuing
  the same limitation carried from Parts 9–10.
- This audit covered every distinct symbol in the lazy population with
  ≥1 row after excluding already-resolved carryovers, but the boot-writer
  search's non-exposed population (1,724 rows) and the much larger,
  lower-confidence tail of both searches' fully non-separable candidates
  were not part of this pass.

## PART 13 — The two remaining populations: boot-search non-exposed rows, and Part 4's ops-table search

Closing the two gaps named at the end of Part 12: the boot-writer
search's 1,707 non-exposed rows, and Part 4's 563-row ops-table
population, which had stood completely unaudited (aside from 2
spot-checks) since Part 4 itself.

### 13a. Boot-search non-exposed population (1,707 rows)

Collapsed to distinct symbols, excluding those already resolved in
Parts 1–12 (`init_net`, `pingv6_ops`, the NAT/conntrack hook family):
only 3 new symbols.

| Symbol | Resolution |
|---|---|
| `totalram_pages` | Foundational — writers are core, unconditional boot functions (`mm/memblock.c`, `mm/nobootmem.c`, `kernel/fork.c`); no Kconfig option can remove them, same class as `init_net`/`runqueues` |
| `br_should_route_hook` | Mechanism #11, directly confirmed: `rhook = rcu_dereference(br_should_route_hook); if (rhook) { ... }` in `net/bridge/br_input.c` |
| `br_fdb_test_addr_hook` | Mechanism #11, directly confirmed: `if (br_fdb_test_addr_hook == NULL) break;` in `net/atm/lec.c` |

Zero genuine candidates; the boot-search population is now **fully
audited** across every distinct symbol it has ever produced (Parts 1,
9, 12, 13a combined).

### 13b. Part 4's ops-table population (563 rows, 59 distinct symbols)

This population was previously **discarded, not verified** — Part 4
established its premise was broken (an `ADDR` reference doesn't mean
"registration," just "address taken," so `H2_cross_object_addr` treats
ordinary multi-file *use* of an exported struct the same as a real
writer). Auditing it meant checking, for each symbol, whether any
flagged pair is a genuine writer/reader split or just this known false
signal. All 59 were checked; they collapse into six categories, none
genuine:

**14 symbols, `.rodata` section** (`bpf_tail_call_proto`,
`cgroupns_operations`, `cpu_all_bits`, `cpu_bit_bitmap`,
`event_trigger_fops`, `inet_stream_ops`, `ipv4_specific`,
`pidns_operations`, `rtm_ipv4_policy`, `rtm_tca_policy`, `taint_flags`,
`tipc_nl_bearer_policy`, `userns_operations`, `utsns_operations`) —
Mechanism #7, no runtime write step exists at all; every "ADDR
reference" is read-only use of a constant table (`cpu_bit_bitmap` alone
accounted for 142 of the 563 rows this way).

**10 symbols, statically-initialized locks** (`fanout_mutex`,
`kexec_mutex`, `module_mutex`, `net_rwsem`, `oom_lock`,
`sched_domains_mutex`, `slab_mutex`, `trace_event_sem`,
`trace_types_lock`, `uts_sem`) — a variant of Mechanism #7 not
previously catalogued this explicitly: all declared via
`DEFINE_MUTEX(...)`/`DECLARE_RWSEM(...)`, which expand to a complete
compile-time initializer. There is no runtime write step; every flagged
"writer" site is just a caller taking the lock's address to pass to
`mutex_lock()`/`down_read()`, confirmed directly for 6 of the 10
(`module_mutex`, `oom_lock`, `uts_sem`, `trace_types_lock`,
`net_rwsem`, `slab_mutex`, plus `kexec_mutex`, `sched_domains_mutex`,
`fanout_mutex`, `trace_event_sem`), inferred for the rest by identical
declaration shape.

**4 qdisc-ops symbols** (`pfifo_qdisc_ops`, `pfifo_fast_ops`,
`mq_qdisc_ops`, `noqueue_qdisc_ops`) — Mechanism #1. Traced
`pfifo_qdisc_ops` (110 of the 563 rows) directly: every consuming qdisc
(`sch_htb.c`, `sch_cbq.c`, etc.) references it unconditionally, and the
top-level `menuconfig NET_SCHED` (gating all of them) itself `select
NET_SCH_FIFO` — the same select-forcing pattern as `xt_recseq`, just
one level higher in the menu structure. This is also a **second
confirmed instance of Part 1's already-documented false-lead class**:
`match_ops.py`'s naive per-object condition-string comparison doesn't
resolve `select`, so it reports these as "separable" when the full
Kconfig graph says otherwise — not a new bug, the same limitation Part
1 named for its own F5 computation, now shown to affect this funnel
too.

**~16 `struct proto`/`request_sock_ops`/dissector symbols in
`net/ipv4/` and `net/ipv6/`** (`raw_prot`, `rawv6_prot`, `smc_proto`,
`smc_proto6`, `tcp_request_sock_ops`, `tcp6_request_sock_ops`,
`tcpv6_prot`, `udplite_prot`, `udplite_table`, `udplitev6_prot`,
`udpv6_prot`, `flow_keys_dissector`, `flow_keys_basic_dissector`,
`tcp_orphan_count`, `netdev_rss_key`, `nf_conntrack_locks`) — two
sub-cases, both confirmed by direct source check on at least one
representative each:
  - `udplite_prot`/`raw_prot`: the "reader" pairing came from
    `do_ipv6_setsockopt`, and is the **same address-taking pattern
    already explained in Part 11** (`sk->sk_prot = &X` — ADDR, not
    STORE); the defining object itself (`net/ipv4/udplite.o`) is
    `obj-y`, unconditional, so there is no separable configuration to
    begin with.
  - The rest (`tcpv6_prot`/`rawv6_prot`/`udplitev6_prot`/`udpv6_prot`
    vs. `net/ipv6/proc.o`'s `sockstat6_seq_show`; `smc_proto`/
    `smc_proto6` vs. `net/smc/smc_diag.o`; `nf_conntrack_locks` vs.
    `nf_conntrack_netlink.o`; `vsock_bind_table` vs. `net/vmw_vsock/
    diag.o`) are all a **diag/introspection submodule reading its own
    base module's state** — `SMC_DIAG depends on SMC` and
    `VSOCKETS_DIAG depends on VSOCKETS` confirmed directly in Kconfig;
    the `/proc` `sockstat` display files are unconditional core
    `net/ipv{4,6}/` code reading the same-scope protocol structs. This
    is the same registration/lookup pattern as Mechanism #8, applied to
    read-only introspection instead of packet-path dispatch.

**2 stacked-guard symbols**: `__perf_regs` — traced to
`perf_sw_event_sched()`/`perf_event_task_sched_in()` in
`include/linux/perf_event.h`, both inlined into scheduler core
functions but gating every access behind
`static_key_false(&perf_swevent_enabled[...])`, a key only `CONFIG_PERF_EVENTS`
code (the same object that defines `__perf_regs`) can ever flip —
Mechanism #10, structurally identical to `rps_cpu_mask`/
`nf_skb_duplicated`. `module_uevent` — directly guarded at its one
reference site by `#ifdef CONFIG_MODULES` in `kernel/params.c`,
matching the definer's own gate exactly (a variant of Mechanism #3/#4).

**2 same-directory shared-compilation symbols**: `raid6_empty_zero_page`
(the `lib/raid6/` CPU-feature-variant files — `recov_avx2.o`,
`recov_ssse3.o`, etc. — are all always compiled together under
`CONFIG_RAID6_PQ`, never independently separable); `rds_stats` (RDS's
own transport files, all requiring the base `CONFIG_RDS`); `kdb_poll_funcs`
(`gdbstub.o`/`kdb_io.o`, both under `CONFIG_KGDB_KDB`) — Mechanism #2.

**1 foundational symbol**: `runqueues` (85 rows) — defined
unconditionally in `kernel/sched/core.o` (the scheduler core, condition
`None`); the one optional reader flagged (`cpufreq_schedutil.o`) is
the *reader* side being optional, which is the safe direction — the
definer is guaranteed present regardless.

### Verdict

Both remaining populations are now fully accounted for. Zero genuine
candidates in either. Part 4's ops-table search — previously the one
population in this entire project carrying an explicit "unresolved, not
verified" status — is now resolved: every one of its 59 distinct
symbols traces to an existing mechanism (#1, #2, #7, #8, #10, or the new
#7-variant for statically-initialized locks), or to the same Part 1/
Part 11 false-lead classes already documented elsewhere in this project.
No new genuine dependency, and — just as notably — no new *kernel-side*
defensive mechanism was required to explain 59 symbols spanning
scheduler, RCU hooks, netfilter, qdiscs, protocol structs, and RAID6
math code. This is the strongest evidence in the project that the
defensive taxonomy has actually saturated, not just repeated by chance:
an almost maximally structurally diverse population, resolved entirely
by patterns already seen.

### What Part 13 does not rule out

- The lock/mutex sub-case of Mechanism #7 was directly confirmed for 6
  of 10 symbols; the remaining 4 (`kexec_mutex`, `sched_domains_mutex`,
  `fanout_mutex`, `trace_event_sem`) were confirmed only by declaration
  shape (`DEFINE_MUTEX`/`DECLARE_RWSEM`), not by reading every call site.
- The diag/introspection sub-case was confirmed by direct source check
  on `smc_proto`/`vsock_bind_table`'s Kconfig relationship and one
  representative `/proc` display file; the remaining symbols in that
  group were resolved by structural resemblance, not individually
  re-verified.
- This closes every distinct symbol in Parts 1, 4, 5a, 7–13's automated
  search output. It does not extend the search to new subsystems beyond
  `net/`+`fs/`+the cross-referenced `kernel/mm/lib`, nor does it add the
  build-witness/boot validation Part 6 identified as the one category of
  evidence never gathered in this project.

## PART 14 — Closing the last gap: an actual build-and-boot witness

Every verdict up to this point rested on static evidence (source
reading, Kconfig, or compiled-object inspection). Part 6 named this as
the one category of proof the project never produced. This part closes
it for one concrete candidate: `nf_nat_hook` (Mechanism #11), chosen
because its guard is a genuine **live runtime state** (whether the
`nf_nat` module happens to be loaded), not a boot-time-only branch —
unlike the first candidate considered, `default_qdisc_ops` (see below).

### Why `default_qdisc_ops` was dropped as the target

Before committing to a multi-hour build, a cheap check first: disassembly
of the *already-compiled* `net/sched/sch_api.o` (from the existing
extraction) showed the flagged writer, `sch_default_qdisc()`, is wrapped
in `#ifdef CONFIG_NET_SCH_DEFAULT` — and Cozart's `base.config` has that
option off, so the function is compiled out of the binary entirely, not
merely guarded at runtime. There was nothing to "boot and flip"; the
object-file evidence already settled it more strongly than a boot could.
Confirms this is a compile-time-eliminated instance of Mechanism #4, a
more precise classification than the original Mechanism #5 label.

### Building the actual witness

Rather than build against raw `base.config` (which failed — see below),
the composed **Cozart nginx config** was reproduced exactly as `job.sh`'s
`compose()` builds it: `aggregate-config.sh` merges `base.config`,
`base-choice.config`, `disable.config`, `boot.config`, and `nginx.config`
through `assign-config-value.py` (resolving each fragment's bare
`CONFIG_*` names against `base.config`'s actual values), then
`scripts/kconfig/merge_config.sh -n` merges the result onto
`allnoconfig` — i.e. the real Cozart pipeline builds from *nothing
enabled* and only turns on what the fragments specify, not from
`base.config`'s much broader default state. This produced a 4,352-line
`.config` with only 1,222 built-in options and 19 modules — a
genuinely debloated nginx-serving kernel, confirmed by the resulting
`bzImage` being 7.3 MB.

The witness modification: `CONFIG_NF_CONNTRACK=y` (forced on; it's off
in the real Cozart nginx config, since plain HTTP serving doesn't need
connection tracking) and `CONFIG_NF_NAT=m` (left as a loadable module,
not forced on) — `make olddefconfig` confirmed this combination holds
without Kconfig forcing `NF_NAT` on, i.e. the Kconfig-invisible
separation genuinely exists in the real tree, not just in this
project's static analysis.

**A first attempt against raw `base.config`** (not the composed nginx
config) failed for reasons unrelated to the actual research: an
AppArmor header-generation bug in this kernel tree
(`capability_names.h`, a pre-existing Ubuntu-cosmic-tree issue) broke
the build, and separately, Docker Desktop's WSL2 backend crashed
mid-build from disk pressure — `base.config` unmodified is a broad,
distro-style config (GPU drivers, InfiniBand, hundreds of modules) that
needed far more disk than was available. Switching to the actual
composed nginx config (the config Cozart's own pipeline really uses)
fixed both problems as a side effect: far fewer objects to compile, and
AppArmor isn't part of the nginx composition's active option set once
explicitly disabled for the witness build.

### Boot and test

A minimal busybox initramfs (`insmod`/`rmmod`/`lsmod`/`nc`/`dmesg`,
~2 MB uncompressed — the debloated kernel also dropped gzip-initrd
support, `CONFIG_RD_GZIP`, requiring an uncompressed cpio archive
instead) booted the witness kernel under QEMU (software emulation, no
`/dev/kvm` on this host) and ran a 5-stage test
(`results/witness_init.sh`):

1. **`nf_nat` absent** (module never loaded): `lsmod` confirms "Not
   tainted", loopback traffic (`nc`) exchanged cleanly, `dmesg` clean.
   This is `nf_nat_hook == NULL` and ordinary conntrack traffic flowing
   through that state.
2. **`insmod nf_nat.ko`**: succeeds (`insmod exit: 0`), `lsmod` confirms
   the module is loaded. `nf_nat_core.c`'s own internal sanity check,
   `WARN_ON(nf_nat_hook != NULL)`, did **not** fire — direct runtime
   confirmation the hook really was `NULL` beforehand, not just assumed
   from source.
3. **Traffic with `nf_nat` loaded**: another clean `nc` exchange, no
   crash.
4. **`rmmod nf_nat`**: succeeds (`rmmod exit: 0`) — the module's exit
   path (`RCU_INIT_POINTER(nf_nat_hook, NULL)`) ran without incident.
5. **Traffic after `rmmod`** (guard back to `NULL`): another clean `nc`
   exchange, no crash.

A full-log sweep for `BUG`, `Oops`, `panic`, `WARNING: CPU`, `NULL
pointer`, `general protection`, and `Call Trace` across all 361 lines
found nothing except the intentional `panic=1` boot argument and an
unrelated informational PCI/ACPI line. The guest powered down cleanly
at the end of the script.

### Correction (found later, via an instruction-level trace)

The stage descriptions above say ordinary traffic flowed *through
conntrack*. That is **not supported**. A QEMU translated-block trace
(`-d in_asm`, executed addresses mapped to `vmlinux` symbols) of the same
boot shows conntrack's *initialisation* ran (`nf_conntrack_init_start`, `nf_conntrack_pernet_init`,
etc.) but `nf_conntrack_in` — the packet path — was never executed. In
4.18 conntrack's netfilter hooks are only registered once something
(iptables, nftables, or NAT) requests conntrack in a netns; nothing did,
so the loopback `nc` traffic never entered conntrack, and
`/proc/net/nf_conntrack` printed nothing. The `nf_nat_hook` read sites
therefore were **not exercised**.

What Part 14 does still show, and this is real: (a) the witness
configuration (`NF_CONNTRACK=y`, `NF_NAT=m`) is accepted by Kconfig
without forcing `NF_NAT` on; (b) the kernel builds, links and boots;
(c) `nf_nat.ko` loads and unloads cleanly, and its own
`WARN_ON(nf_nat_hook != NULL)` did not fire, confirming the hook really
was NULL before load and the RCU set/clear path works.

### Verdict

This is the first evidence in the project that isn't purely static, but
it is **weaker than first stated**: it confirms the build/boot and the
module load/unload transitions of the `nf_nat_hook` pointer, not that the
conntrack *reader* ran while the writer was absent. Closing that requires
a test that actually drives packets through conntrack (e.g. registering a
conntrack user in the netns before generating traffic) and confirming via
trace that `nf_conntrack_in` executed in each stage.

### What Part 14 does not rule out

- Only one candidate (`nf_nat_hook`) was taken all the way to a build
  witness; the other ~20+ Mechanism #11 instances across this project
  were not individually re-confirmed this way, only by source reading
  or family resemblance as already documented.
- The test exercises the RCU-pointer-NULL guard itself (the mechanism
  that makes this safe), not the narrower `manip_pkt`/NAT-clash branch
  inside the guard that was the original, harder-to-trigger target —
  that inner branch still rests on source reading only.
- This used software-emulated QEMU (no hardware virtualization on this
  host), which is representative but not identical to real hardware
  boot timing; nothing in the observed behavior is timing-sensitive, so
  this is not expected to matter, but it wasn't cross-checked against a
  KVM-accelerated or bare-metal boot.
- The AppArmor build failure encountered along the way is a real,
  reproducible bug in this kernel tree, independent of this project's
  own research question — noted here in case it resurfaces in future
  build attempts, not investigated further since it was irrelevant to
  the candidate under test.

## PART 15 — Exhaustive per-reader guard check of the hook-pointer family

Triggered by the Part 12 Correction. Instead of sampling one reader and
inferring the rest, every textual use of every hook-pointer symbol from
Parts 9, 10, 12 and 13 was enumerated across `net/ kernel/ mm/ lib/ fs/
include/ drivers/net drivers/infiniband` in the 4.18 tree, and each
*read* site was classified by whether the loaded pointer is NULL-tested
before it is dereferenced. (`hookguard.py`, `results/hook_guard_audit.tsv`.)

Scope: 29 symbols — `nf_ipv6_ops` (plus its `nf_get_ipv6_ops()`
accessor), `nf_nat_hook`, `nf_ct_hook`, `ip_ct_attach`, `nfnl_ct_hook`,
`nf_nat_sip_hooks`, `nf_ct_timeout_{put,find_get}_hook`, `nf_br_ops`,
`br_should_route_hook`, `br_fdb_test_addr_hook`,
`bpfilter_process_sockopt`, the FTP/IRC/TFTP/SNMP/Amanda/PPTP NAT hooks,
and the eight H.323 hooks.

| Result | Count |
|---|---|
| Reader sites found | 58 |
| Guarded (NULL-tested before deref) | 56 |
| **Unguarded** | **1** — `nf_ipv6_ops` in `net/bridge/br_netfilter_ipv6.c:168` (the Part 12 Correction bug) |
| Panics deliberately on NULL | 1 — `nf_conntrack_destroy()`'s `BUG_ON(ct_hook == NULL)` (boot-time invariant, Part 10) |

Every non-guarded verdict was read by hand, and the 10 `nf_ipv6_ops`
sites were additionally spot-checked (9 guarded, 1 not). Writer-side
`BUG_ON(hook != NULL)` assertions in module init, which an early version
of the classifier mislabelled as reader guards, were excluded. This also
closes the earlier "7 inferred by sibling resemblance" H.323/NAT-hook
verdicts: each is now directly confirmed guarded (mostly via the
`(x = rcu_dereference(hook)) && ...` idiom).

Result: across the audited hook family, **one** reader out of 58 lacked
the guard, and it was in the one symbol whose other readers had only been
sampled — consistent with the Part 12 Correction, not evidence of a
widespread gap.

### What Part 15 does not rule out

- Only the 29 audited symbols. Other hook pointers in the kernel were not
  enumerated; this is not a survey of *all* optional-hook idioms.
- Readers are found by symbol name. A reader reaching the pointer through
  another struct, a macro, or an inline wrapper not named here is missed.
- The guarded/unguarded call is a heuristic (guard before first deref in
  the same function). Only non-guarded sites and one family were checked
  by hand; a wrong "guarded" elsewhere would go unnoticed.
- The one unguarded reader is reachable via `IPV6=m` with the module not
  loaded (Kconfig-valid) or `ipv6.disable=1`, but it is not built in
  Cozart's nginx configs, so it is a real instance of the pattern that
  Cozart would not itself produce. Its crash was not reproduced here.
- This checks the *guard*, not whether the guarded fallback behaviour is
  correct.

## PART 16 — Positive control: real historical bugs of this shape, and what the detector could see

Purpose: every earlier part is a search that found nothing (or nothing
Cozart-exposed). A null result is only informative if the detector can
find real instances. This part mines kernel history for real bugs where a
reader misbehaves because the state its writer sets was never established,
and asks which of them the tooling could have seen.

Method: commit-message search over upstream `v4.18..v5.4` (about 100k
commits; metadata-only clone), for crash/NULL/oops fixes combined with
phrases such as "ipv6.disable", "module not loaded", "CONFIG_X not set",
"not registered", `IS_ENABLED`/`#ifdef`. Each hit was read, and a bug was
kept only if a reader breaks because an initialising writer did not run
or was configured out. Results: `results/positive_control.tsv`.

| Commit | Bug | State type | Writer absent via | Detector could see? | Actually surfaced? |
|---|---|---|---|---|---|
| `48bd0d68cd` | unguarded `nf_ipv6_ops` deref in `br_nf_pre_routing_finish_ipv6` | global hook pointer | `IPV6=m` not loaded / `ipv6.disable=1` | **yes** | **yes**, in the funnel, but **mis-triaged safe** by the manual audit |
| `8820914139` | NULL `net->ipv6.fib6_main_tbl` in `nft_fib_netdev` | pernet struct field | `ipv6.disable=1` | no | no |
| `173656acca` | `sit` calls into IPv6 with it disabled | pernet / runtime IPv6 state | `ipv6.disable=1` | no | no |
| `c0a47e44c0` | `geneve` calls `rt6_lookup()` with IPv6 disabled | pernet fib6 state | `ipv6.disable=1` | no | no |
| `dac91170f8` | `vrf` IP6MR fib rule add fails, IPv6 disabled | registered rule ops | `ipv6.disable=1` | no | no |
| `a874752a10` | NULL deref dumping ct timeout policy, `CONFIG_NF_CONNTRACK_TIMEOUT` off | conditionally-populated initializer field | **Kconfig** | no | no |
| `3c446e6f96` | `net_generic(kcm_net_id)` before pernet registration completes | pernet id / init-order race | module-load race | no | no |
| `206b92353c` | CPU-hotplug teardown wrong context with `CONFIG_HOTPLUG_CPU=n` | control flow | Kconfig | out of scope | n/a |

Findings:

1. **Detector recall on real bugs is low.** 1 of the 7 in-scope bugs is a
   global-symbol writer/reader pair of the kind the funnel models; it was
   surfaced. The other 6 involve per-netns struct fields, initializer
   content, registration state, or init ordering, none of which the
   symbol-level extraction represents. The known blind spots (no
   struct-field write tracking, no initializer-content analysis) each
   correspond to a real bug in this sample.
2. **The one detection was lost at triage.** The funnel listed the
   buggy reader; the manual audit then cleared the whole `nf_ipv6_ops`
   family after checking one reader (Part 12 Correction, Part 15).
3. **A recurring cluster is not Kconfig-level.** Five of the eight bugs
   are the same failure: code guarded only by `IS_ENABLED(CONFIG_IPV6)`
   assumes IPv6 initialised, but `ipv6.disable=1` skips the init. The
   compile-time guard is insufficient for a runtime-skipped writer.
   Cozart does not set boot parameters, so it would not itself produce
   this state.
4. **Only one bug is Kconfig-level, and it is of the initializer kind.**
   `a874752a10` is the real-world failure of the mechanism catalogued
   as #6 ("conditionally-populated initializer") in the audits: there the
   populated content and the reader were gated by *different* options.
   It postdates 4.18, so the 4.18 tree does not contain it.

Implication for the earlier null result: it holds for the class the
funnel models (global symbols with separable writer/reader objects), where
the funnel did find the one real instance in the sample. It says nothing
about the other classes, which cover most of the real bugs found here.

### What Part 16 does not rule out

- Message-grep mining has low recall, and it covers one release window
  (v4.18..v5.4); the control set has 8 entries and could be several times
  larger.
- Whether the funnel "could see" each bug is my judgement from the state
  type, not a run of the tool on each buggy source tree; only the first
  row was checked against the funnel's actual output.
- Classification of state type was by reading the commit and diff, not by
  reproducing each crash.
- The sample is dominated by IPv6-disabled bugs, so it is not a
  representative sample of all variability bugs.

## PART 17 — Extending the detector to conditionally-populated initializer fields

Part 16 showed the global-symbol funnel could see 1 of 7 in-scope real bugs.
One of the six misses (`a874752a10`, nft_ct timeout dump) is an
initializer-content bug. This part adds a detector for that class and
re-scores the control. The per-netns / `ipv6.disable=1` cluster is **not**
addressed here.

### What the new detector does (`initcontent.py`)

1. Finds `struct T v = { ... };` initializers and their depth-1 designated
   fields (`.f = ...`) whose preprocessor guard differs from the initializer's
   own guard (array elements that are wholly conditional are excluded by the
   depth-1 rule).
2. Finds readers `x->f(...)`, `x->f->...`, or `x->f.sub(...)` in files that
   mention `struct T`, with no NULL test on the field earlier in the function.
3. Reports a reader if `reader_guard AND makefile_gate AND initializer_guard
   AND NOT field_guard` is satisfiable (reusing `guardmap.separable`).

Validated on a synthetic fixture (one bad reader, one NULL-tested reader, one
same-guard reader, one unconditional field): reports exactly the bad reader.
Two real-tree false-positive sources were found and fixed while developing it:
whole-array-element conditionals, and readers in files whose Makefile gate is
the same option as the field's guard.

### Results

| Tree | Reader hits | After manual audit |
|---|---|---|
| v4.18 `net/` + `include/` (Cozart's kernel) | 0 | 0 |
| pre-fix parent of `a874752a10` | 7 | 1 real (`nft_ct.c:925`), 6 excluded (see below) |
| v4.19, v5.0, v5.4 | 10 / 9 / 17 | 0 real (see below) |

Files: `results/initcontent_v4.18.tsv`, `initcontent_prefix_a874752a10.tsv`,
`initcontent_v5.4.tsv`.

- **Recall on this class: 1 of 1 control**, at `nft_ct.c:925`
  `timeout->l4proto->ctnl_timeout.obj_to_nlattr(...)`, the crash site named in
  the fix commit. The field is guarded by `NF_CT_NETLINK_TIMEOUT`, the
  reader by `NF_CONNTRACK_TIMEOUT`; these are separate options, so the state
  is Kconfig-reachable.
- Fitted to the control: the one change the control drove was extending
  the reader pattern to dotted sub-field chains (`->ctnl_timeout.sub(`).
  One control is not a measurement of recall.
- Excluded in the pre-fix tree: two sctp/`nfnetlink_cttimeout.c` rows depend
  on a nested-`#if` in the guard map (the field guard picked up an outer
  `NF_CT_NETLINK`), and the reader file is gated in its Makefile by the same
  option; four other rows are the same reader for the dccp/gre variants,
  gated by `NF_CT_NETLINK_TIMEOUT`, which `depends on NF_CONNTRACK_TIMEOUT`
  in that tree's Kconfig. I read the Kconfig entry; I did not run a Kconfig
  solver, and the detector has no Kconfig-implication step.
- v4.19..v5.4: every `ctnl_timeout` hit is the `nfnetlink_cttimeout.c`
  reader, now implied-safe by the same Kconfig dependency (the fix made the
  field gate `NF_CONNTRACK_TIMEOUT`). The 8 extra v5.4 rows
  (`pernet_operations`/`init`) are struct-name collisions (`ops->init` on
  unrelated types); I did not audit them one by one.
- v4.18, Cozart's kernel: **zero hits**, consistent with the fact that the
  timeout-policy feature landed in 4.19.

### Re-scored control (in-scope real bugs)

| | Before (Part 16) | After (Part 17) |
|---|---|---|
| Detectable classes | global symbol with separable writer/reader | + conditionally-populated initializer field |
| Real bugs found by tools | 1 of 7 | 2 of 7 |

Still missed: the five per-netns / `ipv6.disable=1` / registration-state /
init-order bugs (`8820914139`, `173656acca`, `c0a47e44c0`, `dac91170f8`,
`3c446e6f96`). Four of the five share one runtime trigger
(`ipv6.disable=1`, IPv6 code present but `net->ipv6.*` state never
initialised), which suggests a detector keyed on that trigger, not a
general struct-field tracker: flag code outside `net/ipv6/` that touches
`net->ipv6.*` or calls into fib6/`ip6_*` without `ipv6_mod_enabled()`.
That is not built.

### What Part 17 does not show

- Recall for initializer content rests on one control that the detector
  was adjusted on; the class could have a low recall on real bugs of other
  shapes (e.g. field-level `#ifdef` inside nested initializers below depth 1,
  macro-generated initializers, or readers reached through accessor
  functions).
- No Kconfig solver step: implied-safe verdicts above come from reading one
  `depends on` line.
- Struct-type matching is by file mention of `struct T`, so type collisions
  produce false positives (seen in v5.4) but could also hide true hits where
  the reader file does not spell the type.
- The 4.18 zero is for `net/` and `include/` only; `fs/` and `drivers/` were
  not scanned with this detector.

## PART 18 — Whole-kernel census on `allyesconfig`, independent of Cozart's configs

Question: are the candidates specific to the Cozart config DBs and their
workloads, or do they exist in vanilla Linux 4.18? Every earlier funnel ran on
objects built from Cozart-derived configs. This part rebuilds `net/ kernel/
mm/ lib/` from `allyesconfig` and reruns the same funnel unchanged.

### Setup

- Copy of the kernel tree in `/work/ayc`, `make allyesconfig`, then
  `DEBUG_INFO=y` + `DEBUG_INFO_REDUCED=y`. `allyesconfig` sets `COMPILE_TEST=y`,
  which makes `DEBUG_INFO` unavailable, so `COMPILE_TEST` was turned off; the
  first rebuild silently had no debug info until I checked for `.debug_line`.
  AppArmor disabled (known header-generation failure in this tree).
- 2,008 objects (net 1,362, kernel 289, mm 102, lib 255); one composite
  object excluded (`lib/lib-ksyms.o`). All four directories built with 0
  errors (one earlier failure in `net/wireless/Makefile` was my own
  continuation-line rewrite; restored from git in the copy only).
- `netdep.py` then `match.py --use-transitive --reader-scope net/`, writer
  modes `boot` and `lazy`. F9 (Cozart exposure) is kept as a label column,
  not a filter; F0-F8 do not use any Cozart config.
- Extractor output: 49,850 global symbols, 1,694,642 reference sites, 5
  unclassified instructions; 3,185,760 section-relative relocations dropped as
  unresolvable (the same limitation as the earlier runs).

### Funnel

| | Cozart-config build (boot) | allyesconfig boot | allyesconfig lazy |
|---|---|---|---|
| F0 definitions | 33,125 | 42,620 | 42,620 |
| F2 symbols (writer + net reader) | 76 | 80 | 117 |
| F4 link-error filter survives (pairs) | 1,817 | 2,722 | 2,428 |
| F5 Kconfig-separable (pairs) | 1,723 | 2,641 | 1,957 |
| F5 distinct symbols | not counted | 31 | 41 |
| F9 Cozart-exposed (pairs) | 17 | 17 | 173 |

Pair counts are dominated by one symbol: `init_net` is 2,538 of the 2,641 boot
rows and 840 of 1,957 lazy rows. The distinct-symbol counts are the meaningful
size of the population. Files: `results/candidates_ayc_boot.tsv`,
`candidates_ayc_lazy.tsv`.

### Result

- **All 31 boot-mode symbols were already seen and audited in Parts 4-15.**
  The wider build added no new boot-time candidate symbol.
- **Lazy mode: 40 of 41 symbols were already seen. One is new,
  `debug_locks`.** Read directly: `int debug_locks = 1` is a static
  initializer, and the writers (`debug_locks_off()`, lockdep) only ever set it
  to 0. That is the safe-static-initializer mechanism; not a candidate.
- The single genuine unguarded reader found by any audit remains
  `nf_ipv6_ops` in `br_nf_pre_routing_finish_ipv6` (Part 12 Correction), and
  it appears here in 10 boot rows.
- So the answer to "do these exist independent of Cozart's configs" is
  split: the Kconfig-separable writer/reader population exists in vanilla
  4.18 (31 symbols boot, 41 lazy, from a 2,008-object build), but after
  audit it contains one real unguarded reader. It does not contain more than
  the Cozart-config runs already showed.

### What Part 18 does not show

- Reader scope is `net/` only; readers in `kernel/`, `mm/`, `lib/` and `fs/`
  were not counted here.
- `allyesconfig` sets everything `=y`, so it cannot represent module states
  (e.g. `IPV6=m` not loaded). The funnel reads object files and Makefile
  conditions, not `.config` values, so I expect the census to be nearly the
  same for `allmodconfig`; I have not built and compared it.
- `COMPILE_TEST` was off, so options that only exist under it are absent.
- The three known gaps stand: per-netns struct fields, registration state,
  init-order races are not covered by this funnel.
- "Previously seen" means the symbol name appeared in an earlier candidate
  file; it does not re-verify those earlier verdicts, which rest on the
  Parts 4-15 audits.

## PART 19 — Detector for the `ipv6.disable=1` cluster (`ipv6dis.py`)

Part 16's control set had a cluster of bugs with one trigger: IPv6 code is
compiled in, but `ipv6.disable=1` (or an unloaded module) means the per-netns
IPv6 state (`net->ipv6.*`) is never initialised. Code outside the IPv6 core that
still calls into it can NULL-dereference. Upstream's fix is always a guard
(`ipv6_mod_enabled()`, `__in6_dev_get()`) in the caller. This part builds a
detector for that shape and audits what it finds.

### Method

1. Nodes: every function defined in `net/ipv6/**` and the IPv6 headers.
2. D0: nodes whose body touches `->ipv6.` (per-netns IPv6 state). Nodes that
   test `ipv6_mod_enabled`/`disable_ipv6_mod` themselves are excluded.
3. D: transitive closure over name-based calls between nodes.
4. Report each call site of a D function in a caller outside the IPv6 core
   (core = `ipv6-objs`/`ipv6-y` in `net/ipv6/Makefile`), as GUARDED if a guard
   token (`ipv6_mod_enabled`, `disable_ipv6_mod`, `[__]in6_dev_get`) appears
   earlier in the same function, else UNGUARDED.

Synthetic self-test passes (one unguarded wrapper call, two guarded shapes,
one self-guarded entry, one harmless callee).

### Validation on the control (pre-fix vs post-fix source)

| Bug | Pre-fix | Post-fix |
|---|---|---|
| `8820914139` nft_fib_netdev -> `nft_fib6_eval` | UNGUARDED | GUARDED |
| `173656acca` sit `ipip6_err` -> `ip6_err_gen_icmpv6_unreach` | UNGUARDED | GUARDED |
| `c0a47e44c0` geneve `geneve_link_config` -> `rt6_lookup` | UNGUARDED | GUARDED |
| `dac91170f8` vrf | not detectable | not detectable |

Vrf is a guard that exists but lists too few address families; a call-site
detector cannot see that. One tooling bug was found and fixed during
validation (the 4.18 Makefile uses `ipv6-objs :=`, not `ipv6-y :=`, so
`icmp.c` was missing from the core list and the sit call was skipped).

### Run on 4.18, and an upstream differential

4.18 (net, drivers/net, drivers/infiniband, drivers/target, fs, kernel,
include, lib): 2,209 graph nodes, 633 dangerous, 171 dangerous entry points,
**76 call sites, 72 unguarded** (43 files). The same run on v5.4: 83 sites,
76 unguarded. Of the 70 unguarded (file, function, callee) sites present in
both, exactly **3 became GUARDED by 5.4 (geneve, sit, nft_fib_netdev)**: the
three known fixes, and no other site changed status. 5 sites disappeared
(renamed or refactored).
Files: `results/ipv6dis_418.tsv`, `results/ipv6dis_v54.tsv`.

Reading: 3 of 72 are confirmed by upstream fixes. That is the detector's
demonstrated precision (about 4%); it says nothing about whether the other 69
are bugs, only that upstream had not changed them by 5.4.

### Audit of all 72 unguarded sites

Structural facts checked in source: with `ipv6.disable=1`, `inet6_init()`
takes `goto out` before `proto_register`/`sock_register`, so no `AF_INET6`
socket can be created; `ip6_tunnel_init()` returns `-EOPNOTSUPP` when IPv6 is
disabled; ipvlan gets IPv6 addresses only from the `inet6addr` notifier;
`ipv6_dev_get_saddr()` skips devices with no `inet6_dev`.

| Class | Sites | Basis |
|---|---|---|
| Known bugs, fixed by 5.4 | 3 | upstream fix commits |
| **Same shape, still unguarded in 5.4** | **3** | see below |
| Dominated by a stub route lookup that errors first | 4 (vxlan, tipc, geneve xmit, rdma `addr6_resolve`) | read |
| Module init refuses to load (`ip6_tunnel`) | 5 | read |
| Reached only from IPv6-stack hooks, ICMPv6 error handlers, ndisc, ipvs/xt IPv6 targets | 25 | read ~12, rest by category |
| Needs an `AF_INET6` socket (dccp, l2tp, sctp, rxrpc) | 15 | `inet6_init` path read; sites by category |
| Probably unreachable (ipvlan, needs a registered IPv6 address) | 2 | read, not tested |
| Safe: bridge MLD querier (`ipv6_dev_get_saddr` skips no-`inet6_dev`) | 1 | read |
| Privileged only (vrf L2 transmit, seg6 BPF helper) | 7 | read; not checked further |
| Hardware/RDMA-specific, not verified | 7 (cma, cnic, chelsio, mlx5, mlxsw, i40iw, qedr) | not read in depth |

New guard classes seen (not modelled by the detector, so they appear as
false positives): module-init refusal, and route lookups through `ipv6_stub`
that error out before the flagged call.

### Candidates that remain (source reading only)

- `net/ipv4/ip_gre.c` `ipgre_err()` -> `ip6_err_gen_icmpv6_unreach()`:
  no guard in 4.18 or v5.4, while the identical call in `sit.c` was guarded by
  `173656acca`. Registered as `ipgre_protocol.err_handler`.
- `net/ipv6/ip6_gre.c` `ip6gre_tnl_link_config_route()` and
  `net/ipv6/ip6_vti.c` `vti6_link_config()` -> `rt6_lookup()`: no
  `ipv6_mod_enabled` anywhere in either file (4.18 and v5.4), unlike the sibling
  `ip6_tunnel.c`, which refuses to load. `rt6_lookup` is the call guarded in
  the geneve fix. I did not trace the netlink create/change path that reaches
  `link_config` for these two.

None of these was executed. I did not test whether the state is reachable, and
my history clone stops at v5.4, so a later upstream fix is possible.

### What Part 19 does not show

- Guards are token-based and "earlier in the same function"; no control-flow
  analysis. Guards in callers-of-callers are not seen.
- Callee danger is name-based and over-approximate (e.g. code below an
  `idev == NULL` skip is counted as dangerous).
- Only direct named calls are seen; calls through function pointers or macros
  are not.
- Roughly 30 sites were read individually; the rest were classified by
  category, and the seven hardware sites were not read in depth.
- Non-IPv6-stack L2 paths beyond the flagged ones (bridge/netdev-family
  netfilter, flowtable) were not systematically audited.

## Files

- `results/globals.tsv`, `results/xref.tsv` — full extraction after all
  four fixes (39,624 symbols / 207,254 reference sites)
- `results/candidates.tsv` — Part 1's 6 F5 survivors
- `results/funnel.txt` — Part 1 funnel counts
- `results/candidates_p1b.tsv` — Part 2's 48 G4 survivors (2-way check)
- `results/candidates_p1b_verified.tsv` — the same 48 with the 3-way
  declaration-conditionality verdict appended
- `results/funnel_p1b.txt` — Part 2 funnel counts
- `results/guards.tsv` — per-line presence conditions for the 75 files
  involved in Part 2 (52,958 conditional lines)
- `results/unclassified.txt` — remaining unclassified instructions (14,
  down from 26 after the section-name fix)
- `results/filename.db` — Makefile-condition table (post Makefile-join
  fix), 20,864 entries
- `results/composite_objs.txt` — the 97 excluded `LD [M]` objects
- `results/candidates_p1b_verified_exposure.tsv` — Part 2's 48 with real
  Cozart-config exposure verdicts appended (3a)
- `results/pernet_candidates.tsv` — the final 0-row pernet search output
  (3b) — kept for reproducibility even though empty
- `results/candidates_ops.tsv` — the 566-row ops-table output (4a) —
  kept as a documented negative/flawed-premise example, not a result to
  build on; see Part 4 for why it should not be trusted as-is
- `results/candidates_fs.tsv`, `results/funnel_fs.txt` — Part 5a's
  cross-subsystem `fs/` results (112 rows / 5 distinct symbols, `--use-transitive`)
- `results/candidates_p1b_fs.tsv`, `results/guards_fs.tsv` — Part 5b's
  same-file `fs/` results (48 rows, 0 rooted in `fs/`)
- `results/candidates_boot_fix2.tsv`, `results/candidates_lazy_fix2.tsv`
  — Part 11's re-run of the boot- and lazy-writer funnels against the
  second classifier fix (register-relative destination); the current
  canonical `net/kernel/mm/lib` results, superseding
  `candidates_postfix.tsv`/`candidates_lazy_postfix.tsv`
- `results/candidates_fs_fix2.tsv`, `results/funnel_fs_fix2.txt` — Part
  11's re-run of Part 5a (`fs/` cross-object) against the twice-fixed
  extraction; same 4 symbols, still 0 exposed, superseding
  `candidates_fs.tsv`/`funnel_fs.txt`
- `results/candidates_ops_fix2.tsv` — Part 11's re-run of Part 4's
  ops-table search against the twice-fixed extraction (563 rows, down
  from 566); fully audited in Part 13b, all 59 distinct symbols resolved
- `results/witness_composed.config` — Part 14's witness `.config`:
  Cozart's actual composed nginx config (`base.config` +
  `base-choice.config` + `disable.config` + `boot.config` +
  `nginx.config`, merged onto `allnoconfig` exactly as `job.sh`'s
  `compose()` does), with `CONFIG_NF_CONNTRACK=y`/`CONFIG_NF_NAT=m`
  applied as the witness modification
- `results/witness_init.sh` — the 5-stage guest test script (insmod/
  rmmod `nf_nat` around loopback traffic, checking `dmesg` at each stage)
- `results/witness_qemu_run.log` — the full QEMU boot-and-test transcript
  for Part 14's build witness; clean at every stage, no crash/warning
- `netdep.py`, `match.py`, `guardmap.py`, `match_p1b.py`,
  `decl_finder.py`, `verify_p1b_decl.py`, `join_makefile_continuations.py`,
  `exposure_check.py`, `pernet_search.py`, `makefile_cond.py`,
  `match_ops.py` — the tools, reproducible against a fresh container
  (`match.py` now takes `--use-transitive --root <path>` to use the
  multi-level Makefile resolver instead of the flat `filename.db`)
- `initcontent.py`, `results/initcontent_*.tsv` — Part 17: conditionally-populated initializer-field detector and its outputs.
- `summarize_candidates.py`, `diff_syms.py`, `results/candidates_ayc_*.tsv` — Part 18: allyesconfig census helpers and outputs.
- `ipv6dis.py`, `results/ipv6dis_*.tsv` — Part 19: `ipv6.disable=1` unguarded-call detector and outputs.
- `readable_csv.py`, `annotate.py`, `results/manual_verdicts.csv`, `results/run_20260925_004337/` — full re-run of the Cozart-config search (rebuilt from `base.config`, re-extracted, funnel re-run; reproduces the earlier candidate tables row for row). Contains a tool-only `readable_csv_<timestamp>.csv`, the annotated CSV with hand-written verdicts, per-symbol summary, raw tool output and `run_info.txt`.
- `README.md` — step-by-step guide to running the whole pipeline from scratch, with every command and the expected numbers.
