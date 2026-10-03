#!/bin/sh
# Builds the Wasm boundary for the browser and Node: js/pkg-web and js/pkg-node. wasm-opt is
# skipped when binaryen is not installed.
#
# This is HOW the core is built, wherever it is built. It is not what pins it. The bytes depend on
# the machine that runs cargo — cargo gives each crate a different metadata hash on a different
# host, that hash is part of every symbol's name, and so a Mac and a Linux box lay the same code
# out differently (rust-lang/rust#117597; measured here on 2026-09-20) — so the pinned bytes are the ones js/reproduce.sh makes by running this script in
# one container, named by digest. A build made by running this directly is for working on the
# library: it behaves the same, and `node js/verify.mjs` will say its bytes are not the pinned ones.
set -eu
cd "$(dirname "$0")/.."
CRATE=crates/hdtp-identity-wasm
# The bytes must not depend on where they were built. Without remapping, rustc embeds the absolute
# path of every dependency's source file in panic locations: the core pinned on 2026-09-16 carried
# its builder's home directory 76 times — a leak in an artifact every browser downloads, and the
# reason two checkouts of one commit could never agree on a hash. rustc applies the LAST matching
# remap, so the general prefix goes first and the specific ones after it.
#
# The standard library is the other half. A toolchain installed with its sources (`rust-src`, which
# every rustup default has) makes rustc print the LOCAL path of a std file in a panic location —
# `~/.rustup/toolchains/stable-aarch64-apple-darwin/lib/rustlib/src/rust/library/...`, host triple
# and all — where a toolchain without them prints the canonical `/rustc/<commit>/library/...`. So a
# core built on a Mac and the same commit built in a Linux container differed by a thousand bytes,
# all of them paths (measured 2026-09-20, js/reproduce.sh). The local sources are remapped onto the
# canonical name, which is what makes the two builds one build.
CARGO_HOME_DIR="${CARGO_HOME:-$HOME/.cargo}"
RUST_SRC="$(rustc --print sysroot)/lib/rustlib/src/rust"
RUST_COMMIT="$(rustc -vV | sed -n 's/^commit-hash: //p')"
[ -n "$RUST_COMMIT" ] || { echo "build: rustc did not say which commit it was built from" >&2; exit 1; }
export RUSTFLAGS="${RUSTFLAGS:-} --remap-path-prefix=$HOME=/home --remap-path-prefix=$(pwd)=/hdtp-identity --remap-path-prefix=$CARGO_HOME_DIR=/cargo --remap-path-prefix=$RUST_SRC=/rustc/$RUST_COMMIT"
for target in web nodejs; do
  dir=js/pkg-$( [ "$target" = nodejs ] && echo node || echo web )
  wasm-pack build "$CRATE" --release --target "$target" --out-dir "../../$dir" --out-name hdtp_identity_wasm --no-pack ${WASM_OPT:---no-opt} -- --locked 2>&1 | grep -v '^\[INFO\]' || true
  [ -f "$dir/hdtp_identity_wasm_bg.wasm" ] || { echo "build failed for $target" >&2; exit 1; }
  # The Node package is CommonJS and the web package ESM; js/package.json says module, so each says its own.
  echo "{\"type\":\"$( [ "$target" = nodejs ] && echo commonjs || echo module )\"}" > "$dir/package.json"
done
