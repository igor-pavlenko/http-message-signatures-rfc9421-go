#!/usr/bin/env bash
set -euo pipefail

INPUT=$(cat)
FILE_PATH=$(echo "$INPUT" | jq -r '.tool_input.file_path // empty')

[[ "$FILE_PATH" == *.go ]] || exit 0

if ! command -v jq &>/dev/null; then
  echo "jq is required but not found." >&2
  exit 2
fi

if ! command -v golangci-lint &>/dev/null; then
  echo "golangci-lint is required but not found." >&2
  echo "Install: https://golangci-lint.run/welcome/install/" >&2
  exit 2
fi

PKG_DIR=$(dirname "$FILE_PATH")
LINT_OUTPUT=$(golangci-lint run "$PKG_DIR/..." 2>&1) || true

if [[ -n "$LINT_OUTPUT" ]]; then
  jq -n --arg issues "$LINT_OUTPUT" '{
    hookSpecificOutput: {
      hookEventName: "PostToolUse",
      additionalContext: ("golangci-lint violations found — fix these before continuing:\n" + $issues)
    }
  }'
fi
