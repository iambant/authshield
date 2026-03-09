#!/usr/bin/env sh
set -eu

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
OUTPUT_FILE="$ROOT_DIR/src/data/disposableDomains.ts"
TMP_FILE="${TMPDIR:-/tmp}/authshield_disposable_domains.txt"
LOCAL_OVERRIDES_FILE="$ROOT_DIR/src/data/disposableDomains.local.txt"

curl -sL "https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/main/disposable_email_blocklist.conf" \
  | tr -d '\r' \
  | sed 's/#.*$//' \
  | sed '/^\s*$/d' \
  | awk '{print tolower($0)}' \
  | sort -u > "$TMP_FILE"

if [ -f "$LOCAL_OVERRIDES_FILE" ]; then
  cat "$LOCAL_OVERRIDES_FILE" >> "$TMP_FILE"
  sort -u "$TMP_FILE" -o "$TMP_FILE"
fi

{
  echo "export const DISPOSABLE_EMAIL_DOMAINS = ["
  sed "s/'/\\\\'/g; s/.*/  '&',/" "$TMP_FILE"
  echo "] as const;"
} > "$OUTPUT_FILE"

echo "Updated $OUTPUT_FILE with $(wc -l < "$TMP_FILE") domains"
