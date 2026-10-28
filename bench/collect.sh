#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Measure every build and write the results to one TSV.
#
#   collect.sh OUT.tsv
#
# Run inside `nix develop`. A build is one kernel, one flag set and one
# parameter set; each is measured by ./measure on both ISAs.
#
# Each build's rows are kept in build/collect/<revision>/ as soon as they are
# measured, and a build already there is not measured again, so a run that
# was stopped resumes where it stopped. The directory is per revision, so rows
# from different source trees never mix.
#
# OUT.tsv is written only when every build has its rows: a build that fails to
# build or verify is reported, the rest still run, and the exit status is 1.
#
# Rows are ordered as in pqsca's measurements/snova3-r2.tsv: by kernel, then
# flag set, then ISA, then parameter set, then op.
#
# Environment, for a partial run:
#   KERNELS  default "ref mem opt tinymem"
#   SETS     default all nine
#   FLAGS    default the table below
#   JOBS     builds measured at once, default 4
#   REV      the revision column, as ./measure -r
set -eu

[ $# -eq 1 ] || { echo "usage: collect.sh OUT.tsv" >&2; exit 2; }
case $1 in
/*) out=$1 ;;
*) out=$PWD/$1 ;;
esac

cd "$(dirname "$0")"

KERNELS=${KERNELS:-ref mem opt tinymem}
SETS=${SETS:-l1-k l1-b l1-s l3-k l3-b l3-s l5-k l5-b l5-s}
JOBS=${JOBS:-4}

# The flag sets, one per line as NAME|DEFS. The first, with no name and no
# DEFS, is stock.
FLAGS=${FLAGS:-'|'}

if [ -z "${REV:-}" ]; then
  REV=$(git log -1 --format=%h -- ../src)
  git diff --quiet HEAD -- ../src || REV="$REV+dirty"
fi

parts=build/collect/$REV
mkdir -p "$parts"

# The part file for one build.
part() {
  echo "$parts/$1-${2:-stock}-$3.tsv"
}

# Every measure run shares the HAL objects and the baseline, so build them
# once here rather than racing to build them from several jobs at once.
for isa in arm riscv; do
  make -s ISA="$isa" baseline >/dev/null
done

# One line per build still to measure: kernel, flag name, DEFS, set.
todo=$(mktemp)
trap 'rm -f "$todo"' EXIT
for kernel in $KERNELS; do
  echo "$FLAGS" | while IFS='|' read -r name defs; do
    for set in $SETS; do
      [ -f "$(part "$kernel" "$name" "$set")" ] ||
        printf '%s\t%s\t%s\t%s\n' "$kernel" "$name" "$defs" "$set"
    done
  done
done >"$todo"

echo "collect: $(wc -l <"$todo" | tr -d ' ') builds to measure, $REV" >&2

# Each job writes its rows to a temporary file and renames it into place, so a
# part file exists only once its build is complete.
export parts REV
[ ! -s "$todo" ] || tr '\t' '\n' <"$todo" | tr '\n' '\0' | xargs -0 -n 4 -P "$JOBS" sh -c '
  kernel=$1 name=$2 defs=$3 set=$4
  part="$parts/$kernel-${name:-stock}-$set.tsv"
  if ./measure -r "$REV" ${name:+-n "$name"} -D "$defs" "$kernel" "$set" >"$part.tmp"; then
    mv "$part.tmp" "$part"
    echo "collect: done $kernel ${name:-stock} $set" >&2
  else
    rm -f "$part.tmp"
    echo "collect: FAILED $kernel ${name:-stock} $set" >&2
  fi
' sh || true

missing=0
for kernel in $KERNELS; do
  for set in $SETS; do
    echo "$FLAGS" | while IFS='|' read -r name defs; do
      [ -f "$(part "$kernel" "$name" "$set")" ] || echo "collect: missing $kernel ${name:-stock} $set" >&2
    done
  done
done 2>&1 | grep . >&2 && missing=1

if [ "$missing" -ne 0 ]; then
  echo "collect: not writing $out; rerun to retry the missing builds" >&2
  exit 1
fi

{
  echo '# snova3 -- space in bytes, time in instructions retired'
  printf 'flags\trevision\tisa\tlevel\top\tspace\ttime\n'
  for kernel in $KERNELS; do
    echo "$FLAGS" | while IFS='|' read -r name defs; do
      for isa in arm riscv; do
        for set in $SETS; do
          awk -F'\t' -v isa="$isa" '$3 == isa' "$(part "$kernel" "$name" "$set")"
        done
      done
    done
  done
} >"$out.tmp"
mv "$out.tmp" "$out"
echo "collect: wrote $(($(wc -l <"$out") - 2)) rows to $out" >&2
