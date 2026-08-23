#!/usr/bin/env bash
set -euo pipefail

INPUT=$(cat)
FILE_PATH=$(echo "$INPUT" | jq -r '.tool_input.file_path // empty')

[[ "$FILE_PATH" == *.go ]] || exit 0

if ! command -v jq &>/dev/null; then
  echo "jq is required but not found." >&2
  exit 2
fi

if ! command -v goimports &>/dev/null; then
  echo "goimports is required but not found." >&2
  echo "Install: go install golang.org/x/tools/cmd/goimports@latest" >&2
  exit 2
fi

# Don't fail on syntax errors — lint hook catches those
goimports -w "$FILE_PATH" 2>/dev/null || true
