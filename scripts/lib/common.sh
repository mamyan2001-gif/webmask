#!/usr/bin/env bash
# Shared helpers for WebMask install/start scripts.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

info()  { printf '\033[36m▸ %s\033[0m\n' "$*"; }
ok()    { printf '\033[32m✓ %s\033[0m\n' "$*"; }
warn()  { printf '\033[33m! %s\033[0m\n' "$*"; }
err()   { printf '\033[31m✗ %s\033[0m\n' "$*" >&2; }

require_bash() {
  if [[ -z "${BASH_VERSION:-}" ]]; then
    err "Run this script with bash: bash scripts/install.sh"
    exit 1
  fi
}

find_bundled_node_bin() {
  local tools_dir="$ROOT/.tools"
  [[ -d "$tools_dir" ]] || return 1

  local candidate
  for candidate in "$tools_dir"/node-*/bin; do
    if [[ -x "$candidate/node" && -x "$candidate/npm" ]]; then
      echo "$candidate"
      return 0
    fi
  done
  return 1
}

setup_node() {
  if command -v node >/dev/null 2>&1 && command -v npm >/dev/null 2>&1; then
    NODE_BIN="$(command -v node)"
    NPM_BIN="$(command -v npm)"
    NPX_BIN="$(command -v npx 2>/dev/null || true)"
    ok "Using Node $(node -v) from PATH"
    return 0
  fi

  local bundled
  if bundled="$(find_bundled_node_bin)"; then
    export PATH="$bundled:$PATH"
    NODE_BIN="$bundled/node"
    NPM_BIN="$bundled/npm"
    NPX_BIN="$bundled/npx"
    ok "Using bundled Node $($NODE_BIN -v) from .tools/"
    return 0
  fi

  err "Node.js 18+ is required."
  err "Install from https://nodejs.org or place a Node binary under .tools/node-*/bin/"
  exit 1
}

require_node_version() {
  local major
  major="$("$NODE_BIN" -p "process.versions.node.split('.')[0]")"
  if (( major < 18 )); then
    err "Node 18+ required (found $($NODE_BIN -v))."
    exit 1
  fi
}

deps_installed() {
  [[ -d "$ROOT/server/node_modules" && -d "$ROOT/client/node_modules" ]]
}

wait_for_url() {
  local url="$1"
  local label="${2:-$url}"
  local tries="${3:-60}"

  info "Waiting for $label…"
  for ((i = 1; i <= tries; i++)); do
    if curl -fsS "$url" >/dev/null 2>&1; then
      ok "$label is ready"
      return 0
    fi
    sleep 1
  done

  err "Timed out waiting for $label"
  return 1
}

open_browser() {
  local url="$1"
  case "$(uname -s)" in
    Darwin) open "$url" ;;
    Linux)
      if command -v xdg-open >/dev/null 2>&1; then
        xdg-open "$url" >/dev/null 2>&1 || true
      else
        warn "Could not auto-open browser. Visit $url"
        return 0
      fi
      ;;
    MINGW*|MSYS*|CYGWIN*)
      cmd.exe /c start "" "$url" >/dev/null 2>&1 || true
      ;;
    *)
      warn "Could not auto-open browser. Visit $url"
      return 0
      ;;
  esac
  ok "Opened $url in your browser"
}

port_in_use() {
  local port="$1"
  if command -v lsof >/dev/null 2>&1; then
    lsof -nP -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1
    return $?
  fi
  curl -fsS "http://127.0.0.1:$port" >/dev/null 2>&1
}
