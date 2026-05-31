#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

APP_URL="http://localhost:5173"
API_URL="http://localhost:4000/api/health"
RUN_DIR="$ROOT/.webmask"
SERVER_LOG="$RUN_DIR/server.log"
CLIENT_LOG="$RUN_DIR/client.log"
PIDS=()

require_bash
setup_node
require_node_version

cleanup() {
  local code=$?
  printf '\n'
  info "Stopping WebMask…"
  for pid in "${PIDS[@]}"; do
    kill "$pid" 2>/dev/null || true
  done
  wait 2>/dev/null || true
  ok "Stopped."
  exit "$code"
}

trap cleanup INT TERM EXIT

printf '\n\033[1mWebMask — starting app\033[0m\n\n'

if ! deps_installed; then
  err "Dependencies are not installed yet."
  info "Run first: ./Install\\ WebMask.command  or  npm run setup"
  exit 1
fi

if port_in_use 4000; then
  warn "Port 4000 is already in use. Stop the other process or close the previous WebMask window."
fi
if port_in_use 5173; then
  warn "Port 5173 is already in use. Stop the other process or close the previous WebMask window."
fi

mkdir -p "$RUN_DIR"

info "Starting API server on :4000…"
(cd "$ROOT/server" && "$NPM_BIN" run dev >"$SERVER_LOG" 2>&1) &
PIDS+=($!)

info "Starting UI on :5173…"
(cd "$ROOT/client" && "$NPM_BIN" run dev >"$CLIENT_LOG" 2>&1) &
PIDS+=($!)

wait_for_url "$API_URL" "API server" 90 || {
  err "Server failed to start. Last log lines:"
  tail -n 20 "$SERVER_LOG" >&2 || true
  exit 1
}

wait_for_url "$APP_URL" "Web UI" 90 || {
  err "Client failed to start. Last log lines:"
  tail -n 20 "$CLIENT_LOG" >&2 || true
  exit 1
}

open_browser "$APP_URL"

printf '\n'
ok "WebMask is running"
printf '  UI:  %s\n' "$APP_URL"
printf '  API: http://localhost:4000\n'
printf '  Logs: %s\n' "$RUN_DIR"
printf '\nPress Ctrl+C in this window to stop both servers.\n\n'

wait
