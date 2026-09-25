# Sub-configuration debloating — working notes

Separate from the non-functional-dependency study in `research/netdep/`
(see `netdep/FINDINGS.md`). This directory covers a different question:

**Can trace-guided analysis remove code *inside* Kconfig-enabled regions
that Kconfig's coarse granularity cannot separate, safely?**

Motivation: Gunasekaran (2026) §2.6 shows Kconfig granularity leaves
~79% of a Dice-debloated kernel untraced. Cozart (Kuo et al., 2020) already
maps traced PCs to source lines and `#ifdef` guards, but only to decide
which whole options to keep.

## Proposed design

1. Stage 1 — Cozart/Kconfig: coarse, already-safe removal.
2. Stage 2 — work only on what remains: remove untraced code that passes a
   safety filter (no retained caller, not the sole writer of a global read
   by retained code, not reachable via ops tables/exports/syscall entries),
   with logging trap stubs as a safety net for anything removed by mistake.

## Measurement so far (function-level, one weak trace)

Kernel: Cozart nginx composed config + `NF_CONNTRACK=y`, `NF_NAT=m`
(7.3 MB bzImage, no debug info). Trace: QEMU `-d in_asm`, `nokaslr`,
boot + a trivial `nc` loopback loop (NOT nginx, NOT the nginx test suite).
Function inventory: `nm -S vmlinux` → 46,287 text functions, 8,949 KiB.

| Level | Meaning | Funcs | KiB | % of fn bytes |
|---|---|---|---|---|
| L1 | untraced, no direct callers, address never taken | 11,601 | 1,289 | 14.4 |
| L2 | L1 + closure: all callers already removed | 13,773 | 1,793 | 20.0 |
| L3 | L2 + stub untraced functions that traced code still calls | 26,757 | 5,205 | 58.2 |
| L4 | L3 + stub ops-table targets | 37,398 | 6,925 | 77.4 |

Only L1/L2 are candidates for provably-safe removal; L3/L4 need trap stubs
and are upper bounds (trace is far smaller than a real nginx run).

Files: `headroom.py`, `classify.py`, `traced_funcs.txt`,
`untraced_classes.tsv`.

## Known limitations of these numbers

- Trace is boot + trivial workload, not nginx + its test suite.
- Function-level only. The witness kernel has no debug info, so there is
  no source-line data; this was not done with Cozart's own tracing
  pipeline (`trace-kernel.sh`, `exec_tb_block`, `trace2line.sh`), which
  needs its custom QEMU build.
- Reference analysis misses computed jumps, runtime-built function
  pointers, assembly entry points, and symbols exported to the 19 modules
  (`__ksymtab` was excluded from the address-taken scan).
- Init text is freed after boot, so some bytes don't exist at runtime.
- Nothing has been validated by actually removing code and rebooting.
- Bugs found and fixed while measuring: binutils prints `callq` (my regex
  missed it); ftrace's `__mcount_loc` table (in `.init.data`) looked like
  38k function pointers.
- Tracer sanity-checked against known-run functions (start_kernel, tcp,
  IRQ, scheduler, conntrack init all traced; ip6_input untraced).

## Next steps

1. Real trace: run nginx + `nginx-tests` and the `ab` benchmark in the guest.
2. Rebuild with `CONFIG_DEBUG_INFO=y`; run trace addresses through
   `addr2line -e vmlinux` to store traced `file:line` pairs.
3. Join traced lines with per-line `#ifdef` guards (reuse
   `research/netdep/guardmap.py`) to measure, per Kconfig region, how much
   is traced vs untraced.
4. Prototype L1/L2 removal at link time; boot; rerun the workload.
5. Try L3 with logging trap stubs and record what fires.
6. Literature check on function-level / trace-guided kernel deletion
   before claiming novelty.
