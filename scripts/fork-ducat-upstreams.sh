#!/usr/bin/env bash
# Explicit, opt-in GitHub CLI step. Requires authenticated gh. Never changes Ducat upstream.
set -euo pipefail
if ! command -v gh >/dev/null 2>&1; then
  echo "Install and authenticate GitHub CLI: https://cli.github.com/" >&2
  exit 2
fi
login="$(gh api user --jq .login)"
if [[ -z "$login" ]]; then echo "Missing GitHub login" >&2; exit 2; fi
for upstream in DUCAT-UNIT/ducat-snap DUCAT-UNIT/app; do
  name="${upstream#*/}"
  if gh repo view "${login}/${name}" >/dev/null 2>&1; then
    echo "Existing fork/repository: https://github.com/${login}/${name}"
  else
    echo "Forking https://github.com/${upstream}"
    gh repo fork "$upstream" --clone=false
  fi
done
echo "Next: port the reviewed prototype to new fork branches; enable no signing paths by default."
