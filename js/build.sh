#!/bin/sh
# Builds the Wasm boundary for the browser and Node, then writes js/manifest.json with the SHA-256
# of every .wasm so a host that vendors the bytes (the gateway, whose build image has no Rust) can
# verify them with js/verify.mjs. wasm-opt is skipped when binaryen is not installed.
set -eu
cd "$(dirname "$0")/.."
CRATE=crates/pact-identity-wasm
# The bytes must not depend on where they were built. Without remapping, rustc embeds the absolute
# path of every dependency's source file in panic locations: the core pinned on 2026-09-16 carried
# its builder's home directory 76 times — a leak in an artifact every browser downloads, and the
# reason two checkouts of one commit could never agree on a hash. rustc applies the LAST matching
# remap, so the general prefix goes first and the specific ones after it.
CARGO_HOME_DIR="${CARGO_HOME:-$HOME/.cargo}"
export RUSTFLAGS="${RUSTFLAGS:-} --remap-path-prefix=$HOME=/home --remap-path-prefix=$(pwd)=/pact-identity --remap-path-prefix=$CARGO_HOME_DIR=/cargo"
for target in web nodejs; do
  dir=js/pkg-$( [ "$target" = nodejs ] && echo node || echo web )
  wasm-pack build "$CRATE" --release --target "$target" --out-dir "../../$dir" --out-name pact_identity_wasm --no-pack ${WASM_OPT:---no-opt} 2>&1 | grep -v '^\[INFO\]' || true
  [ -f "$dir/pact_identity_wasm_bg.wasm" ] || { echo "build failed for $target" >&2; exit 1; }
  # The Node package is CommonJS and the web package ESM; js/package.json says module, so each says its own.
  echo "{\"type\":\"$( [ "$target" = nodejs ] && echo commonjs || echo module )\"}" > "$dir/package.json"
done
node js/manifest.mjs
