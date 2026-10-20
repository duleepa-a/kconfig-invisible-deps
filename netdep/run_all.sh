#!/usr/bin/env bash
# run_all.sh -- extraction + funnel (boot and lazy) + distinct-variable CSV, in one go.
#
# Run it INSIDE the container, after the kernel is built (README steps 1-10).
#
# Usage:
#   bash /Cozart/research/netdep/run_all.sh [options]
#
# Options (all optional; defaults match the main study):
#   --root DIR          built kernel tree                 (default /work/cz)
#   --subdirs "A B C"   directories to extract            (default "net kernel mm lib")
#   --reader-scope P    only readers whose object path starts with P
#                       ('' = all readers)                (default net/)
#   --filename-db F     Makefile-condition table          (default /work/filename.db)
#   --composed F        option list (Cozart composed set) (default /work/composed_nginx.txt)
#   --exclude-file F    composite objects to skip         (default /work/cz_composite_net.txt;
#                       "none" disables it -- NOT recommended, it double-counts)
#   --out DIR           results directory                 (default /work/run_<timestamp>)
#
# Example, with the VXLAN reader included (after `make drivers/net/vxlan.o`):
#   bash /Cozart/research/netdep/run_all.sh --subdirs "net kernel mm lib drivers/net" --reader-scope ''
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT=/work/cz
SUBDIRS="net kernel mm lib"
SCOPE="net/"
FNDB=/work/filename.db
COMPOSED=/work/composed_nginx.txt
EXCLUDE=/work/cz_composite_net.txt
OUT=""

while [ $# -gt 0 ]; do
  case "$1" in
    --root)         ROOT="$2"; shift 2;;
    --subdirs)      SUBDIRS="$2"; shift 2;;
    --reader-scope) SCOPE="$2"; shift 2;;
    --filename-db)  FNDB="$2"; shift 2;;
    --composed)     COMPOSED="$2"; shift 2;;
    --exclude-file) EXCLUDE="$2"; shift 2;;
    --out)          OUT="$2"; shift 2;;
    -h|--help)      sed -n '2,22p' "$0"; exit 0;;
    *) echo "unknown option: $1" >&2; exit 2;;
  esac
done

[ -n "$OUT" ] || OUT="/work/run_$(date +%Y%m%d_%H%M%S)"

# --- check inputs before spending time ---------------------------------------
[ -d "$ROOT" ]     || { echo "ERROR: kernel tree not found: $ROOT" >&2; exit 1; }
[ -f "$FNDB" ]     || { echo "ERROR: missing $FNDB (README step 9)" >&2; exit 1; }
[ -f "$COMPOSED" ] || { echo "ERROR: missing $COMPOSED (README step 10)" >&2; exit 1; }
[ "$EXCLUDE" = none ] && EXCLUDE=""
[ -z "$EXCLUDE" ] || [ -f "$EXCLUDE" ] || { echo "ERROR: missing $EXCLUDE (README step 7), or pass --exclude-file none" >&2; exit 1; }

mkdir -p "$OUT/raw"
START=$(date +%s)
echo "== output directory: $OUT"

# --- 1. extraction -----------------------------------------------------------
echo "== [1/3] extraction: $SUBDIRS under $ROOT"
EXARGS=()
[ -z "$EXCLUDE" ] || EXARGS=(--exclude-file "$EXCLUDE")
python3 "$HERE/netdep.py" --root "$ROOT" --subdirs $SUBDIRS --out "$OUT/raw" "${EXARGS[@]}"

# --- 2. funnel, one directory per writer mode ---------------------------------
# match.py writes candidates.tsv into --out, so each mode gets its own copy of the tables.
echo "== [2/3] funnel (scope: '${SCOPE}')"
for MODE in boot lazy; do
  D="$OUT/$MODE"
  mkdir -p "$D"
  cp "$OUT/raw/globals.tsv" "$OUT/raw/xref.tsv" "$D/"
  python3 "$HERE/match.py" --out "$D" \
      --filename-db "$FNDB" --composed-config "$COMPOSED" \
      --root-prefix "$ROOT/" --root "$ROOT" --use-transitive \
      --writer-mode "$MODE" --reader-scope "$SCOPE" > "$D/match_stdout.txt" 2>&1
  echo "-- $MODE:"
  sed 's/^/   /' "$D/funnel.txt"
done

# --- 3. distinct variables ----------------------------------------------------
echo "== [3/3] distinct variables"
python3 "$HERE/distinct_variables.py" \
    --input "boot=$OUT/boot/candidates.tsv" \
    --input "lazy=$OUT/lazy/candidates.tsv" \
    --out "$OUT/distinct_variables.csv"

{
  echo "date:          $(date)"
  echo "root:          $ROOT"
  echo "subdirs:       $SUBDIRS"
  echo "reader-scope:  '$SCOPE'"
  echo "filename-db:   $FNDB"
  echo "composed:      $COMPOSED"
  echo "exclude-file:  ${EXCLUDE:-none}"
  echo "elapsed:       $(( $(date +%s) - START )) s"
} > "$OUT/run_info.txt"

echo
echo "Done in $(( $(date +%s) - START )) s. Results in $OUT:"
echo "  boot/candidates.tsv  boot/funnel.txt"
echo "  lazy/candidates.tsv  lazy/funnel.txt"
echo "  distinct_variables.csv   run_info.txt"
