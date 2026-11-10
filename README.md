# Undercloud

Undercloud is a desktop backup vault for protecting files across storage providers.

Files are split into chunks and encrypted on your device before they leave it. Storage providers receive only opaque encrypted objects; plaintext files, passwords, and encryption keys stay local. Undercloud keeps the encrypted catalog and provider credentials separate, verifies restored files with a content hash, and can repair missing replicas when another storage target is available.

