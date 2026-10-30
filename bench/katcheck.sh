#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Check that a variant's KATs match stock's and upstream's.
#
#   katcheck.sh [-k KERNELS] [-D DEFS]
#
#   -D       the -D flags that turn the variant on, e.g. '-DNARROW_GF16=1'
#   -k       kernels to check, default "ref opt mem tinymem"
#
# Runs on the host, not in `nix develop`: it builds with upstream's own
# src/Makefile, which wants the host compiler and OpenSSL (src/rng.c is the
# NIST DRBG over it). Needs `openssl dgst -shake256 -xoflen`.
#
# For every kernel and all nine sets, it builds stock and the variant in
# copies of src/ and runs PQCgenKAT_sign in each, then checks
#
#   1. the variant's .req and .rsp are byte-identical to stock's,
#   2. the variant's .rsp hashes to the digest dist/KATs records for the set,
#      the way dist/digests.sh computes it, and
#   3. at least one of the variant's objects differs from stock's. A flag the
#      kernel does not know, misspelt or not yet written, builds stock again
#      and would pass 1 and 2 without testing anything.
#
# AESCTR selects upstream's other public-key expansion, with KATs of its own.
# When DEFS holds -DAESCTR, stock is built with it too and the set is named
# <set>_AES, as dist/makesnova.py names it, so all checks are against the
# AES KATs.
#
# With no -D the variant is stock itself, which checks stock against
# dist/KATs. Check 3 is skipped then, and when DEFS is -DAESCTR alone, since
# the variant is stock in both cases. Exits 1 if any check fails.
set -eu

usage() {
  echo "usage: katcheck.sh [-k KERNELS] [-D DEFS]" >&2
  exit 2
}

kernels="ref opt mem tinymem"
defs=
while getopts k:D: opt; do
  case $opt in
  k) kernels=$OPTARG ;;
  D) defs=$OPTARG ;;
  *) usage ;;
  esac
done
shift $((OPTIND - 1))
[ $# -eq 0 ] || usage

root=$(cd "$(dirname "$0")/.." && pwd)

aes=
case " $defs " in
*" -DAESCTR "* | *" -DAESCTR="*) aes=_AES ;;
esac

# Check 3 runs when DEFS holds anything besides -DAESCTR.
compare=
for d in $defs; do
  case $d in
  -DAESCTR | -DAESCTR=*) ;;
  *) compare=1 ;;
  esac
done

# Succeed when every object stock built is byte-identical in the variant.
same_objects() {
  for o in "$1"/build/*.o; do
    cmp -s "$o" "$2/build/${o##*/}" || return 1
  done
}

# The nine recommended sets, as dist/makesnova.py lists them: name v o q l r m1.
SETS='SNOVA_I_K 29 3 16 4 8 5
SNOVA_I_B 27 4 16 4 6 5
SNOVA_I_S 27 5 16 4 4 5
SNOVA_III_K 38 4 16 4 8 7
SNOVA_III_B 38 5 16 4 6 7
SNOVA_III_S 38 6 16 4 5 7
SNOVA_V_K 40 4 16 5 8 6
SNOVA_V_B 40 5 16 5 6 6
SNOVA_V_S 40 6 16 5 5 6'

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# Build one kernel at one set in a fresh copy of src/ and generate its KATs
# there. Arguments: directory, kernel, set's -D flags, extra DEFS.
kat() {
  rm -rf "$1"
  cp -R "$root/src" "$1"
  # An in-place make in src/ leaves build/ and KAT files behind, and the copied
  # objects look up to date, so make would reuse a binary built for other flags.
  make -C "$1" clean >/dev/null
  opt=$(echo "$2" | tr '[:lower:]' '[:upper:]')
  if ! make -C "$1" OPT="$opt" P="$3 $4" kat >"$1/make.log" 2>&1; then
    echo "katcheck: build or KAT run failed in $1" >&2
    tail -20 "$1/make.log" >&2
    return 1
  fi
}

# Every (kernel, set, stock|variant) is built in the background; the checks
# wait for all of them.
for kernel in $kernels; do
  echo "$SETS" | while read -r name v o q l r m1; do
    p="-DSNOVA_v=$v -DSNOVA_o=$o -DSNOVA_q=$q -DSNOVA_l=$l -DSNOVA_r=$r -DSNOVA_m1=$m1 -DSNOVA_NAME=$name$aes"
    stock_defs=
    [ -z "$aes" ] || stock_defs=-DAESCTR
    kat "$work/$kernel-$name-stock" "$kernel" "$p" "$stock_defs" &
    kat "$work/$kernel-$name-variant" "$kernel" "$p" "$defs" &
    wait
  done &
done
wait

fail=0
for kernel in $kernels; do
  for name in $(echo "$SETS" | cut -d' ' -f1); do
    set_name=$name$aes
    stock=$work/$kernel-$name-stock
    variant=$work/$kernel-$name-variant
    for ext in req rsp; do
      f=PQCsignKAT_$set_name.$ext
      if [ ! -f "$stock/$f" ] || [ ! -f "$variant/$f" ]; then
        echo "FAIL $kernel $set_name: no $f" >&2
        fail=1
        continue 2
      fi
      if ! cmp -s "$stock/$f" "$variant/$f"; then
        echo "FAIL $kernel $set_name: $ext differs from stock" >&2
        fail=1
      fi
    done
    if [ -n "$compare" ] && same_objects "$stock" "$variant"; then
      echo "FAIL $kernel $set_name: DEFS change none of its objects" >&2
      fail=1
    fi
    want=$(awk -v f="$set_name.rsp" '$1 == f { print $2 }' "$root/dist/KATs")
    got=$(openssl dgst -shake256 -xoflen=24 "$variant/PQCsignKAT_$set_name.rsp" | awk '{ print $NF }')
    if [ "$got" != "$want" ]; then
      echo "FAIL $kernel $set_name: rsp digest $got, dist/KATs has $want" >&2
      fail=1
    else
      echo "ok   $kernel $set_name $got"
    fi
  done
done

[ "$fail" -eq 0 ] || { echo "katcheck: FAILED for DEFS='$defs'" >&2; exit 1; }
echo "katcheck: all match for DEFS='$defs'"
