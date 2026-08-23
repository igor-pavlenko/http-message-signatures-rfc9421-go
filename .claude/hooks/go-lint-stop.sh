#!/usr/bin/env bash
set -euo pipefail

# Don't block stop if tools are missing
if ! command -v golangci-lint &>/dev/null; then
  echo "Warning: golangci-lint not found, skipping stop verification" >&2
  exit 1
fi

if ! command -v jq &>/dev/null; then
  echo "Warning: jq not found, skipping stop verification" >&2
  exit 1
fi

# Only run if this is a Go project
[[ -f "go.mod" ]] || exit 0

# If git is available, skip when no Go files were touched
if command -v git &>/dev/null && git rev-parse --is-inside-work-tree &>/dev/null 2>&1; then
  CHANGED=$(git diff --name-only -- '*.go' 2>/dev/null || true)
  STAGED=$(git diff --cached --name-only -- '*.go' 2>/dev/null || true)
  UNTRACKED=$(git ls-files --others --exclude-standard -- '*.go' 2>/dev/null || true)
  if [[ -z "$CHANGED" && -z "$STAGED" && -z "$UNTRACKED" ]]; then
    exit 0
  fi
fi

LINT_EXIT=0
LINT_OUTPUT=$(golangci-lint run ./... 2>&1) || LINT_EXIT=$?

if [[ $LINT_EXIT -ne 0 && -n "$LINT_OUTPUT" ]]; then
  jq -n --arg issues "$LINT_OUTPUT" '{
    decision: "block",
    reason: ("golangci-lint found issues that must be fixed before finishing:\n" + $issues)
  }'
fi
