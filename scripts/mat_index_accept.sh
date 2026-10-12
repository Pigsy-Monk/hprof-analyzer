#!/usr/bin/env bash
# Small-dump acceptance harness for `hprof-analyzer mat caches`.
#
# Answers ONE question in seconds-to-minutes: does Eclipse MAT *accept* the
# `.index` files this build emits, or does it throw them away and re-parse?
#
# Why a small dump: when MAT rejects a cache it immediately re-parses the dump.
# On a multi-GB dump that costs tens of GiB of RSS (and it deletes the .index
# files sitting next to the dump). On a 3.5 MB dump the whole thing is cheap and
# the failure is identical, because the failure is structural, not size-driven.
#
# Usage (on a box that has MAT + the small dump):
#   scripts/mat_index_accept.sh [-b BIN] [-d DUMP] [-g GOLDEN_DIR] [-m MAT_HOME] [-w WORK]
#   scripts/mat_index_accept.sh -i <dir-with-index>      # skip generation, verify these
#
# -i is the cross-machine workflow: build the analyzer on your dev box, generate
# the index there, copy just the small .index files over, and verify them here.
#
# Defaults follow one particular box's layout (override with -b/-d/-g/-m/-w):
#   BIN     ~/hprof-analyzer/hprof-analyzer
#   GOLDEN  /tmp/mathelp/heapdump     MAT's own 12 .index files + HeapDumpSample.hprof
#   MAT     /tmp/mat                  MAT install (MemoryAnalyzer, ParseHeapDump.sh)
#   WORK    /tmp/matsmall             scratch; never touches GOLDEN
#
# Three checks, cheapest first:
#   1. byte diff  — every emitted file vs MAT's golden (size + first diff offset)
#   2. probe      — IndexProbe replays SnapshotImpl.readFromFile's read sequence
#                   with the JDK ObjectInputStream + MAT's model classes; prints
#                   ACCEPT, or REJECT at the exact byte offset MAT would die on
#   3. MAT        — real MAT parse application on throwaway copies: once with the
#                   GOLDEN index (positive control; must NOT re-parse) and once
#                   with OURS.  Verdict is PASS only if neither re-parses AND MAT
#                   finishes without throwing — "it reused the cache" is not
#                   enough, MAT can read a cache and then NPE building the
#                   snapshot from it.
set -uo pipefail

BIN="${BIN:-$HOME/hprof-analyzer/hprof-analyzer}"
GOLDEN="${GOLDEN:-/tmp/mathelp/heapdump}"
MAT="${MAT:-/tmp/mat}"
WORK="${WORK:-/tmp/matsmall}"
DUMP=""
INDIR=""
XMX="${XMX:-2g}"

while getopts "b:d:g:m:w:i:h" o; do
  case "$o" in
    b) BIN="$OPTARG";; d) DUMP="$OPTARG";; g) GOLDEN="$OPTARG";;
    m) MAT="$OPTARG";; w) WORK="$OPTARG";; i) INDIR="$OPTARG";;
    h) sed -n '2,36p' "$0"; exit 0;;
    *) echo "usage: $0 [-b BIN] [-d DUMP] [-g GOLDEN_DIR] [-m MAT_HOME] [-w WORK] [-i INDIR]" >&2; exit 2;;
  esac
done

die() { echo "FATAL: $*" >&2; exit 2; }

# ---------------------------------------------------------------- setup ------
[ -d "$GOLDEN" ] || die "golden dir missing: $GOLDEN"
[ -x "$MAT/MemoryAnalyzer" ] || die "MAT not found at $MAT (need MemoryAnalyzer)"
[ -z "$INDIR" ] || [ -d "$INDIR" ] || die "index dir missing: $INDIR"
[ -n "$INDIR" ] || [ -x "$BIN" ] || die "binary not executable: $BIN"

if [ -n "$DUMP" ]; then
  DUMP_NAME="$(basename "$DUMP")"
else
  DUMP_NAME="${DUMP_NAME:-HeapDumpSample.hprof}"
  DUMP="$GOLDEN/$DUMP_NAME"
fi
[ -f "$DUMP" ] || die "dump missing: $DUMP"
PREFIX="$(basename "$DUMP")"; PREFIX="${PREFIX%.hprof}"

mkdir -p "$WORK"
OURS="$WORK/ours"
[ -n "$INDIR" ] || { rm -rf "$OURS"; mkdir -p "$OURS"; }

# ------------------------------------------------------- 0. build the probe --
# IndexProbe.java lives next to this script; seed it into WORK if absent so a
# fresh WORK directory (or a box that only received this script) still works.
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[ -f "$WORK/IndexProbe.java" ] || cp -f "$HERE/IndexProbe.java" "$WORK/IndexProbe.java" 2>/dev/null
CP="$MAT/plugins/*"
if [ ! -f "$WORK/IndexProbe.class" ]; then
  if [ -f "$WORK/IndexProbe.java" ]; then
    javac -nowarn -cp "$CP" -d "$WORK" "$WORK/IndexProbe.java" >/dev/null 2>&1 \
      || echo "note: could not build IndexProbe (javac/MAT jars missing) - skipping check 2"
  else
    echo "note: $WORK/IndexProbe.java not found - skipping check 2"
  fi
fi

# ------------------------------------------------ 1. generate + byte diff ----
if [ -n "$INDIR" ]; then
  echo "=== 1. using pre-generated index dir: $INDIR ==="
  OURS="$INDIR"
else
  echo "=== 1. generate index: $BIN mat caches $DUMP $OURS ==="
  t0=$SECONDS
  "$BIN" mat caches "$DUMP" "$OURS" >"$WORK/gen.out" 2>&1
  echo "    rc=$? in $((SECONDS - t0))s"
  [ -s "$WORK/gen.out" ] && tail -3 "$WORK/gen.out" | sed 's/^/    | /'
fi

echo "    file                              ours        mat        verdict"
for g in "$GOLDEN/$PREFIX".*.index "$GOLDEN/$PREFIX.index"; do
  [ -f "$g" ] || continue
  n="$(basename "$g")"
  o="$OURS/$n"
  if [ ! -f "$o" ]; then
    printf '    %-32s %-11s %-11s MISSING\n' "$n" "-" "$(stat -c%s "$g")"
    continue
  fi
  printf '    %-32s %-11s %-11s ' "$n" "$(stat -c%s "$o")" "$(stat -c%s "$g")"
  python3 -c '
import sys
a = open(sys.argv[1], "rb").read(); b = open(sys.argv[2], "rb").read()
n = min(len(a), len(b))
d = next((i for i in range(n) if a[i] != b[i]), n)
print("IDENTICAL" if d == n and len(a) == len(b) else "first-diff@%d" % d)
' "$o" "$g"
done

# ------------------------------------------------------------ 2. probe ------
echo "=== 2. read-sequence probe on $PREFIX.index ==="
probe_rc="n/a"
if [ -f "$WORK/IndexProbe.class" ]; then
  java -Xmx2g -cp "$WORK:$CP" IndexProbe "$OURS/$PREFIX.index" 2>&1 | sed 's/^/    /'
  probe_rc="${PIPESTATUS[0]}"
  echo "    probe exit=$probe_rc (0 = MAT's read sequence gets all the way through)"
else
  echo "    (skipped - no IndexProbe.class)"
fi

# ------------------------------------------------------------- 3. MAT -------
# Run MAT's parse application on a throwaway dir; MAT deletes/rewrites the index
# it cannot read, so never point this at the golden dir itself.
run_mat() { # $1 = dir holding dump + index, $2 = workspace, $3 = log
  rm -rf "$2"; mkdir -p "$2"
  ( cd "$1" && timeout 900 "$MAT/MemoryAnalyzer" -consolelog -nosplash \
      -data "$2" -application org.eclipse.mat.api.parse "$1/$DUMP_NAME" \
      -vmargs --add-exports=java.base/jdk.internal.org.objectweb.asm=ALL-UNNAMED -Xmx"$XMX" ) \
      >"$3" 2>&1
  echo $?
}

mat_dir() { # $1 = source dir of *.index, $2 = dest
  rm -rf "$2"; mkdir -p "$2"
  cp -f "$DUMP" "$2/"
  cp -f "$1/$PREFIX.index" "$2/" 2>/dev/null
  for f in "$1/$PREFIX".*.index; do [ -f "$f" ] && cp -f "$f" "$2/"; done
  return 0
}

echo "=== 3. real MAT (positive control first) ==="
mat_dir "$GOLDEN" "$WORK/matgold"
rc=$(run_mat "$WORK/matgold" "$WORK/ws-gold" "$WORK/gold.log")
gold_reparse=$(grep -c "Reparsing" "$WORK/gold.log")
echo "    control (MAT's own index): rc=$rc reparse=$gold_reparse"
if [ "$gold_reparse" != "0" ]; then
  echo "    !! control re-parsed - harness is not measuring what we think"
fi

mat_dir "$OURS" "$WORK/matours"
rc=$(run_mat "$WORK/matours" "$WORK/ws-ours" "$WORK/ours.log")
ours_reparse=$(grep -c "Reparsing" "$WORK/ours.log")
# "no re-parse" is necessary but NOT sufficient: MAT can read the cache and then
# blow up building the snapshot from it (e.g. a null ClassImpl.staticFields
# throws NPE inside setSnapshot). Treat any exception as a failure.
ours_err=$(grep -cE 'Exception|!ENTRY org.eclipse' "$WORK/ours.log")
echo "    ours                     : rc=$rc reparse=$ours_reparse errors=$ours_err"
grep -nE 'Reparsing|invalid type code|StreamCorrupted|Exception' "$WORK/ours.log" | head -5 | sed 's/^/    | /'

echo
echo "probe=$probe_rc  mat(control)=$gold_reparse  mat(ours)=$ours_reparse  ours-errors=$ours_err"
if [ "$gold_reparse" = "0" ] && [ "$ours_reparse" = "0" ] && [ "$ours_err" = "0" ]; then
  if [ "$probe_rc" != "0" ] && [ "$probe_rc" != "n/a" ]; then
    echo "VERDICT: PASS (but the probe rejected it - probe and MAT disagree; investigate)"
  else
    echo "VERDICT: PASS - MAT reopened our index and built the snapshot without re-parsing"
  fi
  exit 0
elif [ "$ours_reparse" = "0" ]; then
  echo "VERDICT: PARTIAL - MAT reused the cache (no re-parse) but then failed on it"
  echo "         (see $WORK/ours.log; $ours_err error lines)"
  exit 1
else
  echo "VERDICT: FAIL - MAT re-parsed the index we generated (see $WORK/ours.log)"
  exit 1
fi
