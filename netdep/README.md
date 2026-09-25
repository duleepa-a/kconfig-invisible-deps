# netdep — searching the Linux kernel for "Kconfig-invisible" dependencies

This folder contains a set of scripts that analyse a compiled Linux kernel (version 4.18, Ubuntu "cosmic" tree)
and list places where one piece of code **writes** a global variable and another piece of code **reads** it,
but the kernel's build configuration (Kconfig) does not say that the two must be enabled together.

The goal is to find cases where a configuration tool (for example Cozart, which shrinks a kernel for one
application) could keep the reading code and remove the writing code, leaving the reader with a variable
that was never set up.

> **What the tools do and do not do.** They produce a ranked *shortlist* of suspicious spots. They do **not**
> prove a bug. Deciding whether a spot is really a problem (for example, "the reader checks for NULL first")
> is a manual step that this README also explains (Step 13). Read section 10 before quoting any result.

This README assumes you know nothing about the project. Every command is shown in full.

---

## Contents

1. [Plain-English overview](#1-plain-english-overview)
2. [Terms you will see](#2-terms-you-will-see)
3. [The pipeline at a glance](#3-the-pipeline-at-a-glance)
4. [Before you start](#4-before-you-start)
5. [Step-by-step: the main run](#5-step-by-step-the-main-run)
6. [Reading the results](#6-reading-the-results)
7. [Variants](#7-variants)
8. [The other detectors](#8-the-other-detectors)
9. [Numbers you should get](#9-numbers-you-should-get)
10. [Limits](#10-limits)
11. [Troubleshooting](#11-troubleshooting)
12. [File map](#12-file-map)

---

## 1. Plain-English overview

The Linux kernel is built from thousands of source files. Which files are compiled depends on a configuration
file (`.config`) made from options such as `CONFIG_IPV6=y`. Options can depend on each other ("`A` needs `B`"),
and Kconfig enforces those rules.

Sometimes code in file **W** sets up a global variable during boot, and code in file **R** later uses it, yet
Kconfig has no rule linking W's option to R's option. If a tool then builds a configuration with R on and W off,
R runs against an uninitialised variable. Nothing in the build catches it, because the variable itself is still
defined somewhere else.

These scripts find *candidate* W/R pairs by reading the compiled object files (`.o`) with standard binutils
(`readelf`, `objdump`) and matching them against the Makefile rules that decide which files get built.

---

## 2. Terms you will see

| Term | Meaning |
|---|---|
| **Kconfig / `CONFIG_X`** | The kernel's configuration system. `CONFIG_X=y` means built in, `=m` a loadable module, unset means absent. |
| **symbol** | A global variable (or global function pointer) in the kernel, for example `nf_ipv6_ops`. |
| **writer / reader** | Code that stores into / loads from a symbol. |
| **boot writer** | A writer inside a function marked `__init` (runs once at boot; lives in the `.init.text` section). |
| **lazy writer** | A writer in ordinary code, which can run at any time (for example on the first use of a feature). |
| **object file (`.o`)** | The compiled form of one `.c` file. |
| **composite object** | A module `foo.o` that is linked from several smaller `.o` files. It repeats their symbols, so the tool skips it. |
| **Makefile gate / condition** | The `CONFIG_*` option(s) that must be on for a file to be compiled, read from the kernel's Makefiles. |
| **hook pointer** | A global function pointer that one module fills in when it loads (for example `nf_nat_hook`). Callers must check it for NULL. |
| **guard** | A check that protects a read (for example `if (hook) ...`), a compile-time `#ifdef`, or a safe default value. |
| **Cozart** | The debloating tool this project studies. Its config files live in `config-db/`. |
| **F0 … F9** | The stages of the filter, explained in section 6. |

---

## 3. The pipeline at a glance

```
 Cozart repo ──► Docker image ──► Docker container
                                    │
   Kernel source (git) ──► join Makefile continuation lines ──► apply base.config
                                    │
                             build net/ kernel/ mm/ lib/ fs/         (make)
                                    │
                    netdep.py  ──►  globals.tsv, xref.tsv           (what writes/reads what)
                                    │
   filename.db (Makefile gates) + composed_nginx.txt (Cozart's option list)
                                    │
                    match.py   ──►  candidates.tsv, funnel.txt      (the filter, F0-F9)
                                    │
             readable_csv.py   ──►  readable_csv_<timestamp>.csv    (tool output only)
                                    │
             MANUAL AUDIT by a person  ──►  results/manual_verdicts.csv
                                    │
                annotate.py    ──►  annotated_<timestamp>.csv, by_symbol_<timestamp>.csv
```

Everything that starts with `python3 ...` below runs **inside the Docker container**. Only Steps 0 to 2 and
Step 15 run on your own computer.

---

## 4. Before you start

You need:

| Item | Notes |
|---|---|
| A computer with **Docker** | Linux, macOS or Windows. Tested with Docker 28 on Windows 11 (WSL2 backend). |
| **Free disk space** | Measured on the reference run: Docker image 1.2 GB, kernel source about 1.2 GB, the tree after building `net/ kernel/ mm/ lib/ fs/` was 3.1 GB, extraction output about 0.2 GB. Keep at least **10 GB** free. Docker's disk file never shrinks by itself. |
| **RAM** | The reference container had about 7 GB. |
| **Internet** | To download the kernel source and Ubuntu packages. |
| **Time** | The kernel build is the slow step: expect tens of minutes on a 12-core machine (not timed precisely). Extraction takes a few minutes. |

You do **not** need QEMU, a GPU, or any special hardware. Nothing in the main run boots a kernel.

Software inside the container (already installed by the provided Dockerfile): Ubuntu 18.04, gcc 7.5, GNU make,
binutils (`readelf`, `objdump`, `nm`), Python 3.6, git. All scripts use only the Python standard library
(no `pip install` needed).

---

## 5. Step-by-step: the main run

This reproduces the "Cozart-config" search: the kernel is built with Cozart's `base.config`, and the result is
labelled with the option list of Cozart's nginx configuration.

### Step 0 — Get this repository (on your computer)

Download or clone the Cozart repository so that you have a folder containing `Makefile`, `docker/`,
`config-db/` and `research/netdep/` (this README is `research/netdep/README.md`).

Below, `<REPO>` means the full path of that folder, for example `D:\Cozart\Cozart` or `~/Cozart`.

### Step 1 — Build the Docker image (on your computer)

```bash
cd <REPO>
docker build -f docker/Dockerfile -t cozart-env:latest .
```

This installs Ubuntu 18.04 with the compiler and tools the 4.18 kernel needs. Check it worked:

```bash
docker images cozart-env
```

### Step 2 — Create and enter the container (on your computer)

The container gets two mounts: your repository (read-only) at `/Cozart`, and a persistent volume at `/work`
where all big files go.

**Linux / macOS / Windows PowerShell:**

```bash
docker volume create ksrc
docker run -dit --name netdep -v "<REPO>:/Cozart:ro" -v ksrc:/work cozart-env:latest bash
```

On Windows write `<REPO>` as `D:\Cozart\Cozart` (with the drive letter).

**Windows Git Bash:** put `MSYS_NO_PATHCONV=1` in front of the command, or use PowerShell. Otherwise Git Bash rewrites
paths such as `/work/...` into `C:/Program Files/Git/work/...`.

Enter the container (all later commands are typed here unless stated otherwise):

```bash
docker exec -it netdep bash
```

Check the mounts:

```bash
ls /Cozart/research/netdep          # should list netdep.py, match.py, README.md, ...
df -h /work | tail -1               # should show plenty of free space
```

### Step 3 — Download the kernel source (inside the container)

```bash
cd /work
git clone --depth=1 https://kernel.ubuntu.com/git/ubuntu/ubuntu-cosmic.git linux-cosmic
cd /work/linux-cosmic
git log --oneline -1
```

Expected: `66e4c0b79 UBUNTU: Ubuntu-4.18.0-25.26`. This is the exact kernel the reported numbers come from.
(Cozart's own Makefile uses a `git://` address; that protocol is often blocked, so use `https://` as above.
This kernel is end-of-life, so the tip should not change, but check the printed commit against the one above.)

### Step 4 — Prepare the source tree (inside the container)

Two small preparations, both taken from Cozart's own `setup-linux` target:

```bash
cd /work/linux-cosmic
cp debian/scripts/retpoline-extract-one scripts/ubuntu-retpoline-extract-one
python3 /Cozart/research/netdep/join_makefile_continuations.py /work/linux-cosmic
```

* The first line copies a helper script the Ubuntu tree needs during a build.
* The second joins lines that end in `\` in every Makefile into single lines. The Makefile-reading scripts
  (`makefile_cond.py`, `extract-makefile.awk`) expect one rule per line. It prints how many Makefiles it
  changed. It edits the tree **in place**; run it once.
  It does the same job as Cozart's `make remove-makefile-escaped-newlines`.

Cozart's `setup-linux` also applies `patches/watchdog.patch`. The runs here did **not** apply it and everything built,
so you can skip it.

### Step 5 — Apply Cozart's base configuration (inside the container)

```bash
cd /work/linux-cosmic
cp /Cozart/config-db/linux-cosmic/cosmic/base.config .config
make olddefconfig
```

`make olddefconfig` fills in every option that `base.config` does not mention, using Kconfig's rules.
Sanity checks:

```bash
sha256sum /Cozart/config-db/linux-cosmic/cosmic/base.config | cut -c1-16    # expect aaaccf22ad049168
grep -E '^CONFIG_(DEBUG_INFO|IPV6|BRIDGE_NETFILTER)=' .config
# expect: CONFIG_IPV6=y  CONFIG_BRIDGE_NETFILTER=m  CONFIG_DEBUG_INFO=y
```

`DEBUG_INFO=y` matters: the extractor reads source file and line numbers from the debug information.

### Step 6 — Compile the parts of the kernel that are analysed (inside the container)

Only five directories are built, not the whole kernel:

```bash
cd /work/linux-cosmic
make -j8 prepare
make -k -j8 net/ kernel/ mm/ lib/ fs/ > /work/build.log 2>&1
echo "exit code: $?"
```

Use a smaller number than `8` if you have little RAM. `-k` keeps going after an error so you see all of them.

Checks:

```bash
tail -2 /work/build.log                    # last line of a good build mentions fs/built-in.a
grep -c '\*\*\*' /work/build.log           # expect 0 (no make errors)
for d in net kernel mm lib fs; do echo $d $(find $d -name '*.o' ! -name built-in.o | wc -l); done
# expect: net 1423, kernel 259, mm 88, lib 197, fs 1218
```

Lines such as `readelf: Warning: [NN]: Info field (NN) should index a relocatable section` are harmless.

### Step 7 — List the composite objects to skip (inside the container)

```bash
cd /work
grep -hE '^ +LD \[M\] +[^ ]+\.o$' build.log | awk '{print $3}' | sort -u > composite_all.txt
grep -E '^(net|kernel|mm|lib)/' composite_all.txt > composite_net.txt
wc -l composite_all.txt composite_net.txt      # expect 159 and 97
```

`LD [M]` lines are the build log's record of a module being linked from several parts. The extractor is told
to ignore those combined objects so their symbols are not counted twice.

### Step 8 — Extract writers, readers and definitions (inside the container)

`netdep.py` reads every `.o` file and writes two tables. Run it twice: once without `fs/` and once with it
(the original study did the same, because `fs/` adds definitions and readers).

```bash
cd /work
python3 /Cozart/research/netdep/netdep.py --root /work/linux-cosmic \
    --subdirs net kernel mm lib     --out /work/out_net --exclude-file /work/composite_net.txt

python3 /Cozart/research/netdep/netdep.py --root /work/linux-cosmic \
    --subdirs net kernel mm lib fs  --out /work/out_fs  --exclude-file /work/composite_all.txt
```

Each run prints progress (`200/1870 objects processed`, ...) and finishes with a line like
`done: 39624 global symbols, 207254 reference sites, 14 unclassified instructions, ...`.
It writes `globals.tsv` (every global variable and where it is defined), `xref.tsv` (every place that
reads or writes one) and `unclassified.txt` (instructions it could not classify; should be small).

Expected first lines: `97 composite objects excluded` / `1870 object files found`, and for the second run
`159 composite objects excluded` / `3026 object files found`.

### Step 9 — Build the Makefile-condition table (inside the container)

```bash
cd /work/linux-cosmic
find . -name Makefile | xargs awk -f /Cozart/extract-makefile.awk \
    | sort -u -t' ' -k2,2 -k1,1 -r \
    | awk -f /Cozart/postproc-fndb.awk | sed 's/^\.\///' > /work/filename.db
wc -l /work/filename.db          # expect 20864
```

(An `awk: escape sequence \. treated as plain .` warning is harmless.) This is the `build-db` recipe from Cozart's
Makefile, without the unrelated `directives.db` part. `filename.db` has two columns: a source file and the
`CONFIG_` option that gates it. `match.py` needs the argument even when it uses its own, more thorough Makefile
reader (`--use-transitive`).

### Step 10 — Make the list of options in Cozart's nginx configuration (inside the container)

This list is only used to **label** rows ("would Cozart's config keep the reader but drop the writer?").

```bash
cd /Cozart/config-db/linux-cosmic/cosmic
cat boot.config nginx.config base-choice.config disable.config \
    | tr -d '\r' | grep -oE 'CONFIG_[A-Za-z0-9_]+' | sort -u > /work/composed_nginx.txt
wc -l /work/composed_nginx.txt   # expect 984
```

This is the same union that Cozart's `compose` step in `job.sh` builds. A ready copy is in this folder
(`composed_nginx.txt`; it has Windows line endings and one blank first line, which the tool ignores).
To label for a different application replace `nginx.config` with, for example, `apache.config`.

### Step 11 — Run the filter (inside the container)

`match.py` reads `globals.tsv` and `xref.tsv` from the folder given by `--out` and writes `candidates.tsv` and
`funnel.txt` there, so each run gets its own folder.

```bash
cd /work
COMMON="--filename-db /work/filename.db --composed-config /work/composed_nginx.txt \
        --root-prefix /work/linux-cosmic/ --root /work/linux-cosmic --use-transitive"

# (a) boot-time writers, readers in net/
mkdir -p f_net_boot && cp out_net/globals.tsv out_net/xref.tsv f_net_boot/
python3 /Cozart/research/netdep/match.py --out f_net_boot $COMMON --writer-mode boot --reader-scope net/

# (b) run-time ("lazy") writers, readers in net/
mkdir -p f_net_lazy && cp out_net/globals.tsv out_net/xref.tsv f_net_lazy/
python3 /Cozart/research/netdep/match.py --out f_net_lazy $COMMON --writer-mode lazy --reader-scope net/

# (c) boot-time writers, readers in fs/
mkdir -p f_fs_boot && cp out_fs/globals.tsv out_fs/xref.tsv f_fs_boot/
python3 /Cozart/research/netdep/match.py --out f_fs_boot $COMMON --writer-mode boot --reader-scope fs/

cat f_net_boot/funnel.txt f_net_lazy/funnel.txt f_fs_boot/funnel.txt
```

Compare the numbers with section 9. Each folder now has `candidates.tsv`: one row per (writer, reader) pair that
passed the filter, best-scoring first.

### Step 12 — Make the readable CSV (inside the container)

```bash
TS=$(date +%Y%m%d_%H%M%S)
R=/work/results/run_$TS
mkdir -p $R
python3 /Cozart/research/netdep/readable_csv.py \
    --input boot=/work/f_net_boot/candidates.tsv \
    --input lazy=/work/f_net_lazy/candidates.tsv \
    --input fs=/work/f_fs_boot/candidates.tsv \
    --out $R/readable_csv_$TS.csv
echo $R
```

The file name carries the time the tool was run. This CSV contains **only tool-generated columns** (section 6).
Open it in a spreadsheet; the last column, `why_flagged`, explains each row in a sentence.

### Step 13 — The manual audit (done by a person)

The tool cannot tell a real problem from a harmless split, so someone must read the code. Work **per symbol**
(the `symbol` column), not per row: one symbol can appear in thousands of rows. Sorting the CSV by
`exposed_by_cozart_config` first, then by `score`, is a good order.

For a symbol, open the reader in the kernel source (`reader_function`, `reader_object`; the `reader_source`
column gives file:line, but for reads that happen inside a macro it may point at a header such as
`include/linux/compiler.h`, so also search by name):

```bash
cd /work/linux-cosmic
grep -rn "symbol_name" net/ include/ | head -30
```

Ask these questions in order. Any "yes" usually means the row is **not a bug**:

1. **Does the reader check before using the value?** For a pointer: `if (p)`, `p != NULL`, `if (!p) return`.
2. **Does the variable have a safe starting value?** For example `int x = 64;` or `= &default_ops`, so the
   missing writer only *replaces* a valid default.
3. **Does Kconfig force the writer on whenever the reader is on?** Look at the `Kconfig` entry of the reader's
   option for `select WRITER_OPTION` or `depends on`.
4. **Are writer and reader always compiled together?** Same `.o`, or the same composite module.
5. **Is the reader itself gated** by a compile-time `#ifdef`, a static key that stays off, or a state check?
6. **Is the writer really only optional?** (a sysctl handler that only tunes an existing default, a module
   that is never a prerequisite, dead code).

If none applies, check whether Kconfig can really produce the bad state. This safe experiment uses a
**separate copy** of the config, so your real `.config` is untouched:

```bash
cd /work/linux-cosmic
cp .config /work/test.config
scripts/config --file /work/test.config -e READER_OPTION -m WRITER_OPTION   # or -d to disable
make olddefconfig KCONFIG_CONFIG=/work/test.config
grep -E '^(# )?CONFIG_(READER_OPTION|WRITER_OPTION)[= ]' /work/test.config
```

If, after `olddefconfig`, the reader is on and the writer is off or a module, Kconfig allows the split.
(Example that works on this tree: `-e BRIDGE_NETFILTER -m IPV6` ends with `IPV6=m` and `BRIDGE_NETFILTER=m`.)

Record what you decided in **`results/manual_verdicts.csv`** (one row per symbol). Columns:

| Column | Content |
|---|---|
| `symbol` | The symbol name, exactly as in the CSV. |
| `reader_func_match` | Leave empty to apply to every row of the symbol. Put a reader function name to apply only to rows whose `reader_function` equals it (used when one reader is different from the rest). |
| `verdict` | `NOT_A_BUG`, `GENUINE_UNGUARDED_READER`, or `UNCERTAIN`. |
| `mechanism` | Short name of the defence, for example `NULL-check on loaded hook pointer`. |
| `reason` | One or two sentences, with file names, so someone else can re-check. |
| `depth` | How sure you are: `SRC` = you read the source, `HG` = `hookguard.py` checked it, `RES` = inferred from a similar symbol only. |
| `recorded_in` | Where the reasoning is written down. |

Rows for symbols with no entry are marked `NOT_AUDITED`, never silently blank.

### Step 14 — Join the tool output with your verdicts (inside the container)

```bash
python3 /Cozart/research/netdep/annotate.py \
    --input boot=/work/f_net_boot/candidates.tsv \
    --input lazy=/work/f_net_lazy/candidates.tsv \
    --input fs=/work/f_fs_boot/candidates.tsv \
    --verdicts /Cozart/research/netdep/results/manual_verdicts.csv \
    --out-annotated $R/annotated_$TS.csv \
    --out-summary   $R/by_symbol_$TS.csv
```

`annotated_<timestamp>.csv` keeps every tool column unchanged and appends `MANUAL_*` columns.
`by_symbol_<timestamp>.csv` has one line per symbol; that is the easiest file to read.
The script prints how many rows got each verdict and lists any symbol that has none.

### Step 15 — Copy the results to your computer (on your computer)

```bash
docker cp netdep:/work/results/run_<TS> <REPO>/research/netdep/results/
docker cp netdep:/work/f_net_boot/candidates.tsv .   # raw tool tables, if you want them
```

(Replace `<TS>` with the timestamp printed in Step 12.) The Docker volume is the only copy of everything in
`/work` until you do this.

---

## 6. Reading the results

### The filter stages (printed in `funnel.txt`)

The filter asks a series of yes/no questions. Some counts are **symbols**, others are **pairs** (one writer
paired with one reader of the same symbol), so a count can go up between stages.

| Stage | Question | Counts |
|---|---|---|
| **F0** | Global variables defined in the built objects (read-only constants excluded). | definitions, distinct symbols |
| **F1** | Does some writer (boot or lazy, per `--writer-mode`) store into it? | symbols |
| **F2** | Is it also read from code in the reader directory (`net/` or `fs/`)? | symbols |
| **F3** | Writer and reader are in **different** object files. | pairs |
| **F4** | The variable is **defined in a different object** than the writer's. Removing the writer's file then leaves the variable, so the build still links and nothing fails loudly. | pairs |
| **F5** | The **Makefile conditions differ** between the definition's file and the writer's file, so some configuration could drop one and keep the other. Every pair that reaches here becomes a row in `candidates.tsv`. | pairs |
| F6 | The writer is the only writer in the tree. | flag |
| F7 | The variable is in `.bss` (no starting value). | flag |
| F8 | No compare/test on the variable was seen in the reader function. **Weak:** guards elsewhere are invisible to it, and in this project every row it flagged in the Cozart-exposed slice turned out to be safe. | flag |
| **F9** | Cozart's option list turns the writer's option **off** and the reader's option **on**. | flag |

F6 to F9 do not remove rows. They add the flags and feed the `score` (higher = examine first).

### The readable CSV columns

| Column | Meaning |
|---|---|
| `run` | Which search produced the row: `boot`, `lazy` or `fs`. |
| `row` | Row number inside that run. |
| `symbol` | The global variable. |
| `defined_in`, `section`, `definition_built_when` | The object that defines it, its section (`.bss`, `.data`, ...), and the option(s) needed to compile that object. |
| `writer_function`, `writer_object`, `writer_source`, `writer_runs_at`, `writer_built_when` | Who stores into it, where, when (`boot (__init)` or `run time`), and what enables that file. |
| `reader_function`, `reader_object`, `reader_source`, `reader_built_when` | The same for the reader. |
| `only_one_writer`, `no_static_initializer_bss`, `no_compare_in_reader_function` | The F6, F7, F8 flags (`yes`/`no`). |
| `exposed_by_cozart_config` | F9: `yes` if Cozart's config would keep the reader and drop the writer. |
| `score` | Ranking score. |
| `why_flagged` | A generated sentence describing the row in plain words. |

### Which rows deserve attention

There are usually thousands of rows but only a few dozen distinct symbols, and one symbol (`init_net`) accounts
for most rows. Count and audit **distinct symbols**. Start with `exposed_by_cozart_config = yes`.

---

## 7. Variants

### Another application's configuration

Repeat Steps 10 to 14 with a different application file from `config-db/linux-cosmic/cosmic/`
(for example `apache.config`). Steps 3 to 9 do not change: the compiled kernel is the same, only the label differs.

### A census over the whole kernel (`allyesconfig`) — independent of Cozart

This builds nearly every option, so the result does not depend on any Cozart configuration. Work on a **copy** of
the tree (about 1.8 GB after the build):

```bash
cp -a /work/linux-cosmic /work/ayc
cd /work/ayc
make mrproper
make allyesconfig
scripts/config -d COMPILE_TEST -d SECURITY_APPARMOR -e DEBUG_INFO -e DEBUG_INFO_REDUCED
make olddefconfig
grep -E '^CONFIG_(COMPILE_TEST|DEBUG_INFO)' .config      # DEBUG_INFO=y must be present
git checkout net/wireless/Makefile
make -j8 prepare
make -k -j8 net/ kernel/ mm/ lib/ > /work/ayc_build.log 2>&1
```

Notes:
* `allyesconfig` turns on `COMPILE_TEST`, and `DEBUG_INFO` cannot be enabled while it is on, so it is switched off.
  Without this the objects have no line numbers (check with `readelf -SW net/socket.o | grep debug_line`).
* `git checkout net/wireless/Makefile` undoes the continuation-line join for that one file. The joined version
  breaks a shell recipe there when certificate options are on.
* AppArmor is disabled because its header generation fails in this tree.

Then list composites (in this build only one), extract and filter:

```bash
cd /work/ayc
for d in net kernel mm lib; do find $d -name '*.o' ! -name built-in.o | while read o; do
  [ -e ${o%.o}.c ] || [ -e ${o%.o}.S ] || echo $o; done; done > /work/ayc_composite.txt

cd /work
python3 /Cozart/research/netdep/netdep.py --root /work/ayc --subdirs net kernel mm lib \
    --out /work/out_ayc --exclude-file /work/ayc_composite.txt
for m in boot lazy; do
  mkdir -p f_ayc_$m && cp out_ayc/globals.tsv out_ayc/xref.tsv f_ayc_$m/
  python3 /Cozart/research/netdep/match.py --out f_ayc_$m --filename-db /work/filename.db \
      --composed-config /work/composed_nginx.txt --root-prefix /work/ayc/ --root /work/ayc \
      --use-transitive --writer-mode $m --reader-scope net/
done
```

`allyesconfig` sets everything to `=y`, so it cannot represent states such as "IPV6 built as a module that is
never loaded". Use Step 13's `olddefconfig` experiment for those.

---

## 8. The other detectors

These are independent of the main pipeline. Most read **source code only** and need no build.

| Script | Question it answers | Command |
|---|---|---|
| `hookguard.py` | For 29 known hook pointers (list at the top of the script), is every use protected by a NULL check? | `python3 /Cozart/research/netdep/hookguard.py` (reads `/work/linux-cosmic`; writes `/work/hookguard.json`; prints unguarded and unclear sites) |
| `initcontent.py` | Which struct-initializer fields exist only under some `#ifdef`, while a reader uses that field without a NULL test? | `python3 .../initcontent.py --self-test` then `python3 .../initcontent.py --root /work/linux-cosmic --dirs net include --out /work/ic.tsv` |
| `ipv6dis.py` | Which code outside the IPv6 core calls IPv6 functions that use per-namespace IPv6 state, without an `ipv6_mod_enabled()`-style check? (relevant when IPv6 is switched off at boot with `ipv6.disable=1`) | `python3 .../ipv6dis.py --self-test` then `python3 .../ipv6dis.py --root /work/linux-cosmic --out /work/ipv6dis.tsv` |
| `guardmap.py` | For every source line, which `#ifdef` conditions must hold for it to be compiled? | `python3 .../guardmap.py --self-test`; `python3 .../guardmap.py --root /work/linux-cosmic --files-list files.txt --out guards.tsv` |
| `match_p1b.py`, `verify_p1b_decl.py` | Writer and reader in the **same file** under different `#ifdef` conditions. | see the `Usage:` block at the top of each script |
| `pernet_search.py` | Per-network-namespace registrations. | `pernet_search.py --root /work/linux-cosmic --net-dir net --filename-db /work/filename.db --globals /work/out_net/globals.tsv --composed /work/composed_nginx.txt --out /work/pernet.tsv` |
| `match_ops.py` | Function-pointer tables (ops structs). | `match_ops.py --out <dir with globals.tsv/xref.tsv> --filename-db /work/filename.db --composed /work/composed_nginx.txt --root-prefix /work/linux-cosmic/` |
| `exposure_check.py` | Re-labels a candidate file against a config option list. | see the `Usage:` block |
| `summarize_candidates.py`, `diff_syms.py` | Small helpers used to summarise and compare candidate files. | read the top of each file |

Every script with `--self-test` checks itself against a tiny made-up example. Run that first.

Notes: `hookguard.py` prints raw classes only (`GUARDED`, `UNGUARDED`, `UNCLEAR`, `DECL`, `WRITE`). The published
table `results/hook_guard_audit.tsv` also contains hand-set overrides that are not part of the script. `ipv6dis.py`
uses names and text patterns, not a full C parser, so treat its output as a shortlist.

**Upstream-bug control set (not automated).** To check whether the tools can find real bugs, the study searched
Linux history for fixes of this kind. The history clone was a bare, filter-less clone:

```bash
git clone --bare --filter=blob:none https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git /work/hist
git -C /work/hist log --oneline --grep='ipv6.disable' v4.18..v5.4
git -C /work/hist show <commit>        # read a fix; blobs are fetched on demand
mkdir -p /work/before
git -C /work/hist archive <commit>^ net include/net | tar -x -C /work/before   # source before the fix
```

The resulting table is `results/positive_control.tsv` (filled in by hand).

---

## 9. Numbers you should get

For the pinned kernel (commit `66e4c0b79`), Cozart's `base.config`, and the option list from Step 10.
If yours differ, first re-check the commit, the config hash (Step 5) and the object counts (Step 6).

| | boot, `net/` | lazy, `net/` | boot, `fs/` |
|---|---|---|---|
| F0 definitions / distinct symbols | 33,125 / 31,046 | 33,125 / 31,046 | 53,847 / 51,032 |
| F1 symbols with a writer | 212 | 315 | 340 |
| F2 also read in reader dir | 76 | 117 | 151 |
| F3 cross-object pairs | 4,103 | 3,561 | 2,396 |
| F4 pairs surviving | 1,817 | 2,764 | 611 |
| F5 pairs = rows in `candidates.tsv` | 1,723 | 2,608 | 126 |
| F6 / F7 / F8 flagged pairs | 1 / 54 / 690 | 13 / 82 / 1,098 | 1 / 0 / 36 |
| F9 exposed pairs | 17 | 27 | 0 |

Extraction: 39,624 symbols and 207,254 reference sites (net/kernel/mm/lib), 67,257 and 386,851 (with `fs/`).

The `allyesconfig` variant (section 7) gives: 2,008 objects; boot F5 = 2,641 pairs (31 distinct symbols);
lazy F5 = 1,957 pairs (41 distinct symbols).

A complete reference run, with hashes and the exact commands, is in `results/run_20260925_004337/`
(see its `run_info.txt`).

---

## 10. Limits

Read these before drawing conclusions.

* The tools list **structural possibilities** (a writer and a reader that a build configuration could separate).
  They do not show that any of them fails at run time.
* F5 compares Makefile conditions **as text**. It ignores Kconfig `depends on` / `select`. Two options that look
  independent may in fact be forced together. Step 13's `olddefconfig` experiment, or reading the Kconfig
  entries, is the real check. No script solves Kconfig for you.
* F8 (no guard seen) is weak and produced only false alarms in the Cozart-exposed rows.
* Only global variables and function pointers that appear as ELF symbols are seen. Per-namespace struct fields,
  registration state, initialisation-order races and calls through function pointers are **not** covered.
* `hookguard.py` only knows its 29 listed hook pointers.
* The manual verdicts in `results/manual_verdicts.csv` are one person's reading of the source at the time. Some are
  marked `RES` (inferred from a similar symbol) and were not individually checked.
* Results are for Linux 4.18 (Ubuntu cosmic). Other kernel versions need a rebuild and may give different numbers.

---

## 11. Troubleshooting

| Problem | What to do |
|---|---|
| Windows Git Bash turns `/work/...` into `C:/Program Files/Git/work/...` | Put `MSYS_NO_PATHCONV=1` before the command, use PowerShell, or wrap the command: `docker exec netdep bash -c "..."`. |
| Passing a here-document to a container fails or hangs | Use `docker exec -i netdep bash` (with `-i`). |
| `git clone git://...` hangs or is refused | Use the `https://` address as in Step 3. |
| Docker Desktop stops working, or the machine runs out of disk during a build | Docker's disk file only grows. Free space on the drive that holds it, or move it (Docker Desktop: Settings, Resources, Advanced, "Disk image location"). Rebuilds are safe to repeat. |
| `python3: text=True` or similar type errors | The container has Python 3.6. Run the scripts inside the container, not on your host Python. |
| Build stops in `net/wireless` about `extra-certs.c` | `cd /work/<tree> && git checkout net/wireless/Makefile` (see section 7). |
| `capability_names.h` / AppArmor error | Only appears when building the whole tree. This README builds five directories, so it should not appear; if it does, `scripts/config -d SECURITY_APPARMOR` then `make olddefconfig`. |
| Objects have no line numbers (`readelf -SW x.o` shows no `.debug_line`) | `DEBUG_INFO` is off. See the `COMPILE_TEST` note in section 7. |
| `match.py` complains that a file is not found | It needs `globals.tsv` and `xref.tsv` inside the folder given by `--out`, and `--filename-db` must exist (Step 9). |
| Different numbers from section 9 | Check, in order: kernel commit (Step 3), `base.config` hash (Step 5), object counts (Step 6), composite counts (Step 7), `filename.db` line count (Step 9), option count (Step 10). |

---

## 12. File map

| Path | What it is |
|---|---|
| `netdep.py` | Reads `.o` files; writes `globals.tsv`, `xref.tsv`, `unclassified.txt`. |
| `match.py` | The F0 to F9 filter; writes `candidates.tsv`, `funnel.txt`. |
| `makefile_cond.py` | Works out which `CONFIG_*` options gate a source file, following the Makefile hierarchy. Used by `match.py`. |
| `join_makefile_continuations.py` | Joins `\`-continued Makefile lines (Step 4). |
| `readable_csv.py` | Turns `candidates.tsv` into the readable CSV (tool output only). |
| `annotate.py` | Adds the manual verdicts to that CSV and writes the per-symbol summary. |
| `hookguard.py`, `initcontent.py`, `ipv6dis.py`, `guardmap.py`, `match_p1b.py`, `verify_p1b_decl.py`, `pernet_search.py`, `match_ops.py`, `exposure_check.py`, `decl_finder.py`, `summarize_candidates.py`, `diff_syms.py` | Other detectors and helpers (section 8). |
| `composed_nginx.txt` | A ready copy of the option list from Step 10. |
| `FINDINGS.md` | The full write-up of every search, audit, correction and result, in numbered Parts. |
| `results/manual_verdicts.csv` | The hand-written verdicts (input to `annotate.py`). |
| `results/run_<timestamp>/` | One complete run: readable CSV, annotated CSV, per-symbol summary, raw tool output, extraction tables, `run_info.txt`. |
| `results/candidates_*.tsv`, `results/funnel*.txt`, `results/*.tsv` | Tool outputs from the earlier Parts of the study. |
| `results/positive_control.tsv` | The upstream-bug control set (hand-made). |

For the reasoning behind each result and every correction made along the way, read `FINDINGS.md`.
