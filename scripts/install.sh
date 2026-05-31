#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

require_bash
setup_node
require_node_version

printf '\n\033[1mWebMask — install dependencies\033[0m\n\n'

info "Project folder: $ROOT"

if deps_installed; then
  warn "Dependencies already look installed. Re-running will refresh packages."
fi

info "Installing server packages…"
(cd "$ROOT/server" && "$NPM_BIN" install --no-audit --no-fund)
ok "Server packages installed"

info "Installing client packages…"
(cd "$ROOT/client" && "$NPM_BIN" install --no-audit --no-fund)
ok "Client packages installed"

info "Installing Playwright Chromium (optional login-flow scans)…"
if [[ -n "${NPX_BIN:-}" ]]; then
  (cd "$ROOT/server" && "$NPX_BIN" --yes playwright install chromium) || warn "Playwright browser install skipped (login-flow tests may fail)"
else
  warn "npx not found — skipped Playwright browser install"
fi

printf '\n'
ok "Setup complete."
printf '\nNext step:\n'
printf '  • Double-click \033[1mStart WebMask.command\033[0m (macOS)\n'
printf '  • Or run: \033[1mnpm run start:app\033[0m\n'
printf '  • Then open \033[1mhttp://localhost:5173\033[0m\n\n'
