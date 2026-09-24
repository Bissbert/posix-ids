#!/bin/sh
# measure.sh - Repeatable repository and syntax measurements for the docs.

set -eu

REPO=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$REPO"

bytes=$(git ls-files | awk '!/^README/ && !/^docs\// && !/^tools\// &&
    ($0 ~ /\.sh$/ || $0 ~ /\.j2$/)' | while IFS= read -r file; do
    wc -c < "$file"
done | awk '{total += $1} END {print total + 0}')
checks=$(awk '/^check_[A-Za-z0-9_]+\(\) \{/ {count++} END {print count + 0}' \
    bin/monitor.sh)

printf 'implementation shell and Jinja bytes: %s\n' "$bytes"
printf 'monitor check functions: %s\n' "$checks"

for file in $(git ls-files '*.sh'); do
    sh -n "$file"
done
for file in tools/*.sh; do
    sh -n "$file"
done
printf 'shell syntax: pass\n'

printf 'monitor checks:\n'
awk '/^check_[A-Za-z0-9_]+\(\) \{/ {sub(/\(\) \{/, ""); print "  " $0}' \
    bin/monitor.sh
