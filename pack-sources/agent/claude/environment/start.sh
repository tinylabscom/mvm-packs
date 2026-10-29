#!/bin/sh
set -eu
umask 077

state=$(mktemp -d /tmp/agent-environment.XXXXXX)
export HOME="$state/home"
export CLAUDE_CONFIG_DIR="$state/config"
mkdir -p "$HOME" "$CLAUDE_CONFIG_DIR" "$state/work"
cd "$state/work"

export DISABLE_AUTOUPDATER=1
export CLAUDE_CODE_DISABLE_OFFICIAL_MARKETPLACE_AUTOINSTALL=1
export CLAUDE_CODE_IDE_SKIP_AUTO_INSTALL=1
export DISABLE_TELEMETRY=1
export DISABLE_ERROR_REPORTING=1
export CLAUDE_CODE_DISABLE_TERMINAL_TITLE=1
export CLAUDE_CODE_ENABLE_PROMPT_SUGGESTION=false
if [ -n "${SSL_CERT_FILE:-}" ]; then
    export NODE_EXTRA_CA_CERTS="$SSL_CERT_FILE"
fi

if [ -t 0 ] && [ -t 1 ]; then
    exec /app/bin/claude
fi

prompt=$(cat)
if [ -z "$prompt" ]; then
    printf '%s\n' 'Use a terminal, or pipe a prompt for an explicitly authorized bounded request.' >&2
    exit 64
fi
export CLAUDE_CODE_MAX_RETRIES=0
export CLAUDE_CODE_NONSTREAMING_TIMEOUT_RETRIES=0
export CLAUDE_CODE_DISABLE_NONSTREAMING_FALLBACK=1
export CLAUDE_CODE_DISABLE_REFUSAL_FALLBACK=1
export CLAUDE_CODE_MAX_OUTPUT_TOKENS=128
export API_TIMEOUT_MS=30000
printf '%s' "$prompt" | /app/bin/claude --bare --print --model haiku \
    --max-turns 1 --max-budget-usd 0.10 --tools "" \
    --strict-mcp-config --mcp-config '{"mcpServers":{}}' \
    --no-session-persistence --output-format json \
    --system-prompt 'Reply with exactly READY. Do not use tools.'
