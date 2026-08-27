#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
export PATH="$HOME/.local/share/pnpm/bin:$PATH"
export RUST_LOG="${RUST_LOG:-debug}"

die() {
    printf 'dev: %s\n' "$1" >&2
    exit 1
}

command -v pnpm >/dev/null 2>&1 || die "pnpm is required (looked in \$HOME/.local/share/pnpm/bin and \$PATH)"

cleanup() {
    if [[ -n "${VITE_PID:-}" ]] && kill -0 "$VITE_PID" 2>/dev/null; then
        kill "$VITE_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

printf '%s\n' 'Starting frontend dev server (vite)'
(
    cd "$ROOT_DIR/apps/desktop-ui"
    pnpm install
    pnpm dev &
    echo $! > /tmp/undercloud-vite.pid
)
VITE_PID="$(cat /tmp/undercloud-vite.pid)"

printf '%s\n' 'Waiting for vite on http://localhost:5173/'
until curl -s -o /dev/null "http://localhost:5173/"; do sleep 0.5; done

printf '%s\n' 'Starting Tauri (cargo build + run)'
cd "$ROOT_DIR/apps/desktop"
pnpm install
exec pnpm dev
