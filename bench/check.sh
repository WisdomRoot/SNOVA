#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Check every flag set in ./flags with katcheck.sh.
#
#   check.sh [-k KERNELS]
#
#   -k   kernels to check, passed on to katcheck.sh; default katcheck.sh's own
#
# Runs on the host, like katcheck.sh. Stock, the line with no DEFS, is checked
# against dist/KATs; every other line against stock and dist/KATs, and must
# change the build. Every line is checked even after one fails. Exits 1 if any
# did.
set -eu

usage() {
  echo "usage: check.sh [-k KERNELS]" >&2
  exit 2
}

kernels=
while getopts k: opt; do
  case $opt in
  k) kernels=$OPTARG ;;
  *) usage ;;
  esac
done
shift $((OPTIND - 1))
[ $# -eq 0 ] || usage

cd "$(dirname "$0")"

failed=
while IFS='|' read -r name defs; do
  ./katcheck.sh ${kernels:+-k "$kernels"} ${defs:+-D "$defs"} </dev/null ||
    failed="$failed ${name:-stock}"
done <<EOF
$(grep -v '^#' flags)
EOF

[ -z "$failed" ] || { echo "check: FAILED for$failed" >&2; exit 1; }
echo "check: every flag set passes"
