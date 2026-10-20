# Removed from the `netdep` container (2026-10-14)

Done to free space. Everything below was **deleted from `/work` inside the container**. Small result
files and the kernel `.config` files were saved first (archives in this folder). Large trees were not
saved because they can be rebuilt; the way to rebuild each is given.

## What was kept (in this folder)

| Archive | Contents |
|---|---|
| `removed_results.tar.gz` (0.9 MB, 45 files) | `candidates.tsv` + `funnel.txt` from every removed `f_*`, `try_*`, `vx_*` directory; `run_info.txt`, `distinct_variables.csv`, per-mode `funnel.txt` (and `candidates.tsv` for `run_test2`) from `run_test`, `run_test2`; `vx_boot/globals.tsv` |
| `removed_configs.tar.gz` (0.1 MB) | `ayc.config`, `igmp_test.config`, `linux-cosmic.config` (the `.config` of each removed tree) |

Not archived: `globals.tsv` / `xref.tsv` of the scratch runs (large; regenerate with `netdep.py`),
`run_test*/raw`, and the kernel source/object trees.

## What was removed, and how to get it back

| Removed (`/work/...`) | Size | What it was | How to recreate |
|---|---|---|---|
| `ayc/` | 1.8 GB | `allyesconfig` build tree of Ubuntu 4.18.0-25 (commit `66e4c0b79`), `DEBUG_INFO=y`, 8,547 options `=y` | Clone `https://kernel.ubuntu.com/git/ubuntu/ubuntu-cosmic.git`, copy `ayc.config` to `.config`, `make olddefconfig`, build the same directories (README section 7). Hours of build time. |
| `linux-cosmic/` | 1.5 GB | README step-3 tree; Makefile continuation lines joined in place (659 modified files); config had `CONFIG_IPV6=y`. Used for the witness builds | README steps 3 to 6 (clone, step 4 script, `linux-cosmic.config`, build). |
| `igmp_test/` | 1.5 GB | Same 4.18.0-25 source with `CONFIG_IPV6=m` (experiment) | Clone as above, copy `igmp_test.config`, build. |
| `hist/` | 411 MB | History clone of `https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git` with tags `v4.18` and `v5.4`, used by `mine_*.py` | `git clone` the URL above (a bare or `--filter=blob:none` clone is enough for `git log v4.18..v5.4`). |
| `run_test/` | 143 MB | Run of `run_all.sh` **without** the composite-object exclusion list, so its pair counts are inflated. Do not use. | Not needed. |
| `run_test2/` | 100 MB | Run of `run_all.sh` with `/work/cz_composite_net.txt`; matches the report (F1 212/315 ... F5 1,739/2,610) | `bash research/netdep/run_all.sh` on `/work/cz` (about 50 s). |
| `vx_raw/`, `vx_boot/`, `vx_lazy/`, `vx_build.log` | about 150 MB | Test of `net kernel mm lib drivers/net` with `drivers/net/vxlan.o` added; **no composite exclusion**, so the overall counts are inflated (the five `ipv6_stub` VXLAN reader rows are the finding) | `make drivers/net/vxlan.o` in `/work/cz`, then `run_all.sh --subdirs "net kernel mm lib drivers/net" --reader-scope ''` |
| `f_all_*`, `f_ayc_fix_*`, `f_fix_*`, `f_fs_fix`, `f_net_fix_*`, `f_union_*` | about 1.1 GB | Funnel outputs from earlier runs (after the Makefile-parser fix; all-modes, allyesconfig, fs, net, union runs) | `candidates.tsv` and `funnel.txt` are in `removed_results.tar.gz`. Raw tables regenerate with `netdep.py` + `match.py`. |
| `try_fs_boot`, `try_net_boot`, `try_net_lazy` | about 130 MB | Trial funnel outputs | Same as above. |

## Still in `/work` (not touched)

`cz/` (the tree the funnel runs on), `filename.db`, `composed_nginx*.txt`, `*composite*.txt`,
`out*/`, `my_*`, `snap/`, `val/`, `clang*.json`, the witness artifact and rootfs directories, and the logs.

## Note on disk space

Deleting files inside the container does not shrink the Docker data disk on the host
(`F:\DockerWSL\disk\docker_data.vhdx`). It only frees space inside the virtual disk.
