#!/bin/bash
set -u
LIST="${1:?usage: acquire-licenses.sh <file-with-bundle-ids> [delay_seconds]}"
DELAY="${2:-10}"
IPATOOL="${IPATOOL:-$(cd "$(dirname "$0")/.." && pwd)/Sources/ISAT/Resources/ipatool}"
ok=0; owned=0; fail=0; n=0
total=$(grep -c . "$LIST")
while read -r bid; do
  [ -z "$bid" ] && continue
  n=$((n+1))
  out=$("$IPATOOL" purchase -b "$bid" 2>&1 | sed 's/\x1b\[[0-9;]*m//g')
  if grep -q "alreadyOwned=true" <<<"$out"; then
    owned=$((owned+1)); printf '[%3d/%3d] = %s (already owned)\n' "$n" "$total" "$bid"
  elif grep -q "success=true" <<<"$out"; then
    ok=$((ok+1));    printf '[%3d/%3d] + %s\n' "$n" "$total" "$bid"
  else
    fail=$((fail+1)); printf '[%3d/%3d] ! %s: %s\n' "$n" "$total" "$bid" \
      "$(grep -o 'error="[^"]*"' <<<"$out" | head -1)"
  fi
  sleep "$DELAY"
done < "$LIST"
echo "DONE: $ok acquired, $owned already owned, $fail failed (of $total)"
