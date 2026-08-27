# Undercloud

Undercloud is a local-first desktop backup vault for protecting files across storage providers.

Files are split into chunks and encrypted on your device before they leave it. Storage providers receive only opaque encrypted objects; plaintext files, passwords, and encryption keys stay local. Undercloud keeps the encrypted catalog and provider credentials separate, verifies restored files with a content hash, and can repair missing replicas when another storage target is available.

## How it works

1. Select a local file in the desktop app.
2. Undercloud chunks and encrypts it locally.
3. Encrypted chunks are sent through provider adapters to one or more storage targets.
4. On restore, chunks are downloaded, decrypted locally, reassembled, and hash-verified before the destination file is written.

The current architecture is illustrated in [`docs/assets/undercloud-system-flow.html`](docs/assets/undercloud-system-flow.html) and [`docs/assets/undercloud-system-flow.svg`](docs/assets/undercloud-system-flow.svg).

## Project status

Undercloud is currently pre-alpha and under active development. Interfaces, provider support, and setup instructions will evolve.

## Development

Requirements:

- Rust 1.93+
- Node.js 22+
- pnpm 9+

Run the frontend with:

```bash
cd apps/desktop-ui
pnpm install --frozen-lockfile
pnpm dev
```

The full desktop build is available through `scripts/build.sh`.
