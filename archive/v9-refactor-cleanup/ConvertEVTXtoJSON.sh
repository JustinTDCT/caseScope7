#!/usr/bin/env bash
set -euo pipefail

# ConvertEVTXtoJSON.sh — EVTX -> JSONL using evtx_dump
# Recursively scans ROOTDIR for *.evtx (case-insensitive),
# converts each to JSONL, and writes to ROOTDIR/json as SUBDIR_filename.jsonl.
# If the EVTX is directly in ROOTDIR, prefix with ROOT_.
#
# macOS Bash 3.2 compatible
# Requires: evtx_dump  (brew install evtx)
#
# Usage:
#   ./ConvertEVTXtoJSON.sh [ROOTDIR]
# Example:
#   ./ConvertEVTXtoJSON.sh "/path/to/ROOTDIR"

ROOTDIR="${1:-"$(pwd)"}"
OUT_DIR="${ROOTDIR%/}/json"

# require evtx_dump
if ! command -v evtx_dump >/dev/null 2>&1; then
  echo "ERROR: evtx_dump not found. Install with: brew install evtx" >&2
  exit 1
fi

mkdir -p "$OUT_DIR"
echo "[*] ROOTDIR:          $ROOTDIR"
echo "[*] Output directory: $OUT_DIR"

# Count how many EVTX files we'll process (any depth, excluding OUT_DIR)
total_files=$(
  find "$ROOTDIR" \( -path "$OUT_DIR" -o -path "$OUT_DIR/*" \) -prune -o \
       -type f -iname "*.evtx" -print0 | tr -cd '\0' | wc -c | tr -d ' '
)
if [ "$total_files" -eq 0 ]; then
  echo
  echo "No .evtx files found under: $ROOTDIR"
  echo "Tip: This script now searches ANY depth (recursively)."
  exit 0
fi

file_idx=0
file_count=0
event_total=0

# Process each EVTX (any depth)
while IFS= read -r -d '' evtx; do
  file_idx=$(( file_idx + 1 ))

  # Work out a prefix based on the top-level subfolder under ROOTDIR
  rel="${evtx#$ROOTDIR/}"
  if printf '%s' "$rel" | grep -q '/'; then
    top="${rel%%/*}"
    [ "$top" = "json" ] && continue  # safety
  else
    top="ROOT"
  fi

  base="$(basename "$evtx")"
  stem="${base%.*}"
  out_jsonl="${OUT_DIR}/${top}_${stem}.jsonl"

  echo "➡️  ($file_idx/$total_files) ${rel}  →  json/$(basename "$out_jsonl")"

  if evtx_dump -t 1 -o jsonl -f "$out_jsonl" "$evtx" >/dev/null 2>&1; then
    count=$(wc -l < "$out_jsonl" | tr -d ' ')
    echo "   [✓] $count events exported"
    event_total=$(( event_total + count ))
    file_count=$(( file_count + 1 ))
  else
    echo "   [!] evtx_dump failed, skipping: ${rel}" >&2
    rm -f "$out_jsonl" 2>/dev/null || true
  fi

done < <(
  find "$ROOTDIR" \( -path "$OUT_DIR" -o -path "$OUT_DIR/*" \) -prune -o \
       -type f -iname "*.evtx" -print0
)

echo
echo "✔ Done. JSONL files are in: $OUT_DIR"
echo "   Files exported: $file_count"
echo "   Total events:   $event_total"
