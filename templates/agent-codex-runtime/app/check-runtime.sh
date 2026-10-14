#!/bin/bash
set -euo pipefail
if [ "$#" -ne 1 ]; then
  printf '%s\n' 'Usage: check-runtime.sh NODE' >&2
  exit 64
fi
"$1" --version
printf '%s\n' 'Runtime check passed. No agent client is installed; see SETUP.md.'
