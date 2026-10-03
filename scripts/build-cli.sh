#!/bin/sh
# The `hdtp` CLI binaries of a release, built from a COMMIT (git archive of the ref), never the tree.
#
#   sh scripts/build-cli.sh <ref> <out-dir> <version> <target>...
#
# Targets, and how each is built on the machine releases are cut on (an arm64 Mac):
#   darwin-arm64  natively, with the toolchain rust-toolchain.toml names;
#   linux-arm64   natively in js/builder.json's image (the one the Wasm is pinned in), linux/arm64;
#   linux-amd64   cross-compiled in that same arm64 container (gcc-x86-64-linux-gnu and the amd64
#                 PC/SC library from Debian's multiarch), because under amd64 emulation on an arm64
#                 Mac rustc crashes (js/reproduce.sh says the same of the Wasm build).
# The PIV feature is on by default, so both Linux builds link libpcsclite dynamically: a machine
# that runs them needs libpcsclite1 installed (Debian/Ubuntu: `apt install libpcsclite1`).
#
# Each binary is written as <out-dir>/hdtp-<version>-<target>. Any target that fails fails the run.
# The Linux builds need docker and the network (apt, rustup); the binaries are not bit-reproducible.
set -eu
[ "$#" -ge 4 ] || { echo "usage: sh scripts/build-cli.sh <ref> <out-dir> <version> <target>..." >&2; exit 2; }
REF="$1"; OUT="$2"; VERSION="$3"; shift 3
cd "$(dirname "$0")/.."
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
mkdir "$WORK/src"
git archive --format=tar "$REF" | tar -x -C "$WORK/src"
IMAGE="$(node -p "require('./js/builder.json').image")"

linux() { # <rust-target> <asset-target> <setup>
  docker run --rm --platform linux/arm64 -v "$WORK/src":/src:ro -v "$OUT":/out -e OWNER="$(id -u):$(id -g)" \
    -e RT="$1" -e NAME="hdtp-$VERSION-$2" "$IMAGE" sh -euc "
    export DEBIAN_FRONTEND=noninteractive
    $3
    mkdir -p /build && cp -a /src/. /build/ && cd /build
    rustup target add \"\$RT\" >/dev/null
    cargo build --release --locked -p hdtp --target \"\$RT\"
    cp \"target/\$RT/release/hdtp\" \"/out/\$NAME\"
    chown \"\$OWNER\" \"/out/\$NAME\"
  "
}

for t in "$@"; do
  echo "build-cli: $t"
  case "$t" in
    darwin-arm64)
      [ "$(uname -s)-$(uname -m)" = "Darwin-arm64" ] || { echo "build-cli: darwin-arm64 builds only on an arm64 Mac" >&2; exit 1; }
      ( cd "$WORK/src" && cargo build --release --locked -p hdtp --target aarch64-apple-darwin --target-dir "$WORK/target" )
      cp "$WORK/target/aarch64-apple-darwin/release/hdtp" "$OUT/hdtp-$VERSION-darwin-arm64"
      ;;
    linux-arm64)
      linux aarch64-unknown-linux-gnu linux-arm64 \
        'apt-get update -qq && apt-get install -y -qq libpcsclite-dev pkg-config >/dev/null'
      ;;
    linux-amd64)
      linux x86_64-unknown-linux-gnu linux-amd64 \
        'dpkg --add-architecture amd64 && apt-get update -qq && apt-get install -y -qq gcc-x86-64-linux-gnu libc6-dev-amd64-cross libpcsclite-dev:amd64 pkg-config >/dev/null
         export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=x86_64-linux-gnu-gcc CC_x86_64_unknown_linux_gnu=x86_64-linux-gnu-gcc AR_x86_64_unknown_linux_gnu=x86_64-linux-gnu-ar
         export PKG_CONFIG_ALLOW_CROSS=1 PKG_CONFIG_PATH=/usr/lib/x86_64-linux-gnu/pkgconfig PKG_CONFIG_LIBDIR=/usr/lib/x86_64-linux-gnu/pkgconfig'
      ;;
    *) echo "build-cli: unknown target $t (darwin-arm64, linux-arm64, linux-amd64)" >&2; exit 2 ;;
  esac
  [ -s "$OUT/hdtp-$VERSION-$t" ] || { echo "build-cli: $t produced nothing" >&2; exit 1; }
done
