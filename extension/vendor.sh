#!/bin/sh
# Re-vendors the built core from ../js/pkg-web and records its hash.
set -e
cd "$(dirname "$0")"
cp ../js/pkg-web/pact_identity_wasm.js ../js/pkg-web/pact_identity_wasm_bg.wasm vendor/
H=$(shasum -a 256 vendor/pact_identity_wasm_bg.wasm | cut -d' ' -f1)
B=$(wc -c < vendor/pact_identity_wasm_bg.wasm | tr -d ' ')
printf 'Vendored from ../js/pkg-web (wasm-pack --target web) on %s.\n\npact_identity_wasm_bg.wasm: sha256 %s, %s bytes — must equal ../js/manifest.json.\n' "$(date -u +%Y-%m-%d)" "$H" "$B" > vendor/VENDORED.md
cat vendor/VENDORED.md
