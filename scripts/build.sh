#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}"

die() {
    printf 'build: %s\n' "$1" >&2
    exit 1
}

command -v cargo >/dev/null 2>&1 || die "cargo is required"
command -v node >/dev/null 2>&1 || die "node is required"

if command -v corepack >/dev/null 2>&1; then
    PNPM=(corepack pnpm)
elif command -v pnpm >/dev/null 2>&1; then
    PNPM=(pnpm)
elif command -v npx >/dev/null 2>&1; then
    PNPM=(npx --yes pnpm@9.15.5)
else
    die "pnpm, corepack, or npx is required"
fi

run_pnpm() {
    "${PNPM[@]}" "$@"
}

printf '%s\n' 'Installing desktop UI dependencies'
(
    cd "$ROOT_DIR/apps/desktop-ui"
    run_pnpm install --frozen-lockfile
    run_pnpm run build
)

printf '%s\n' 'Installing Tauri dependencies'
(
    cd "$ROOT_DIR/apps/desktop"
    run_pnpm install --frozen-lockfile
)

printf '%s\n' 'Building Tauri application'
(
    cd "$ROOT_DIR/apps/desktop"
    run_pnpm exec tauri build
)

printf 'Build complete: %s/apps/desktop/src-tauri/target/release/bundle\n' "$ROOT_DIR"
