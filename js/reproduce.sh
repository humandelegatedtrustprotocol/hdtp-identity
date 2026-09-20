#!/bin/sh
# The canonical build of the Wasm core: in one container, named by digest, on one platform.
#
#   sh js/reproduce.sh          rebuild HEAD, and compare the bytes with js/manifest.json (exit 1 if not)
#   sh js/reproduce.sh --pin    rebuild HEAD, install the bytes as js/pkg-web and js/pkg-node, and write
#                               js/manifest.json from them — after a COMMIT has changed a build input
#
# js/manifest.json pins the SHA-256 of the core every host runs: the browser wallet, the cloud's
# Worker, the CLI. A pin is worth something only if somebody ELSE can make those bytes from the
# source, and "the same hash twice on my laptop" is not that. Measured on 2026-09-20, one commit:
#
#   a Mac, natively                     635,480 bytes   (the pin until that day)
#   the same Mac, toolchain without     635,160 bytes   rustc prints a std file's LOCAL path in a
#     its std sources                                   panic location when it has the sources
#   linux/arm64, this container         636,486 bytes   three fresh runs, one hash
#
# Two causes. The std paths are fixed in js/build.sh, by remapping them onto their canonical name.
# The other cannot be fixed from outside cargo: it gives each crate a different metadata hash on a
# different host (`libp256-8548…` on the Mac, `libp256-b7fd…` in the container; same compiler,
# same lockfile), that hash is part of every symbol's name, and so the same code is laid out
# differently per host (rust-lang/rust#117597). The
# usual remedy is to pin the build PLATFORM as well as the toolchain — so the pin IS this
# build: rust 1.92.0 in an image named by digest, wasm-pack fetched from its release and checked
# against a hash written here, dependencies locked, paths remapped, wasm-opt off. Any machine with
# Docker makes the same bytes, and .github/workflows/pact-identity.yml proves it on every push, on
# a runner that is not the machine the pin was written on.
#
# linux/arm64 because it runs natively on the machines this is developed on AND on a hosted CI
# runner. linux/amd64 would be the other choice; under emulation on an arm64 Mac rustc crashes.
#
# Needs docker, curl and node.
set -eu
cd "$(dirname "$0")/.."

IMAGE='rust:1.92.0-slim-bookworm@sha256:f1f73538ebe623fd3673a35aff3df358ae1084c64c55646516e5b17b321b6c9b'
PLATFORM='linux/arm64'
WP='wasm-pack-v0.15.0-aarch64-unknown-linux-musl'
WP_SHA='e17ef0806381c3a0acb9c9ddad643a49facaa5a2ecf657a421d4d8f3357a24b7'

MODE="${1:-verify}"
case "$MODE" in verify|--pin) ;; *) echo "usage: sh js/reproduce.sh [--pin]" >&2; exit 2 ;; esac

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
curl -fsSL -o "$WORK/wasm-pack.tar.gz" "https://github.com/rustwasm/wasm-pack/releases/download/v0.15.0/$WP.tar.gz"
GOT="$( (sha256sum "$WORK/wasm-pack.tar.gz" 2>/dev/null || shasum -a 256 "$WORK/wasm-pack.tar.gz") | cut -d' ' -f1)"
[ "$GOT" = "$WP_SHA" ] || { echo "reproduce: $WP.tar.gz is $GOT, not the $WP_SHA written here: refusing to run it" >&2; exit 1; }

# WHAT IS BUILT IS THE COMMIT, not this working tree: `git archive HEAD`, unpacked beside the
# build's other scratch. A pin is a statement about source somebody else can fetch, and a working
# tree is not that — it can hold an edit nobody committed, or lack one somebody did. It also puts
# the steps in the only order that cannot surprise: style is applied BEFORE the commit (the
# pre-commit hook formats staged Rust), the commit is made, and only then is it compiled and
# pinned. On 2026-09-20 a style fix made AFTER a pin moved a line, the line number was in the
# binary, and the pin stopped matching; a build that only ever reads commits cannot be ambushed by
# what has not been committed yet.
#
# So `--pin` refuses while a build input is uncommitted (js/inputs.mjs has the list), and a plain
# run says so and carries on, because comparing the COMMIT with the manifest is still the question.
# The STATUS matters, not just the output: `|| true` read every failure as "clean". 0 clean,
# 1 dirty, anything else means the question could not be answered — fatal when pinning.
DIRTY="$(node js/inputs.mjs --dirty)" && DIRTY_RC=0 || DIRTY_RC=$?
if [ "$DIRTY_RC" -gt 1 ]; then
  echo "reproduce: could not tell whether the build inputs are committed" >&2
  if [ "$MODE" = "--pin" ]; then
    echo "reproduce: refusing to pin without that answer" >&2
    exit 1
  fi
fi
if [ -n "$DIRTY" ]; then
  if [ "$MODE" = "--pin" ]; then
    { echo "reproduce: these build inputs are not committed, and a pin is of a commit:"; echo "$DIRTY"; echo "commit them (the pre-commit hook styles them), then pin."; } >&2
    exit 1
  fi
  { echo "reproduce: NOTE — building HEAD; these uncommitted changes are NOT in this build:"; echo "$DIRTY"; } >&2
fi
mkdir "$WORK/src"
git archive --format=tar HEAD | tar -x -C "$WORK/src"
echo "reproduce: building commit $(git rev-parse --short HEAD) (inputs $(node js/inputs.mjs | cut -c1-16)…)"

# The source goes in read-only and is copied, so the build cannot touch this checkout, and the
# path it builds under is the container's and not this machine's.
#
# The container runs as root and writes into a directory this script then cleans up. On Docker
# Desktop that is this user's file; on a Linux host it is root's, and the clean-up is refused — the
# first run on a hosted runner rebuilt the pinned bytes exactly and then failed for that. So what
# the container leaves behind is handed back to whoever ran this, whether or not the build worked.
docker run --rm --platform "$PLATFORM" -v "$WORK/src":/src:ro -v "$WORK":/work -e WP="$WP" -e OWNER="$(id -u):$(id -g)" "$IMAGE" sh -euc '
  trap "chown -R \"$OWNER\" /work" EXIT
  mkdir -p /build && cd /src
  cp -a . /build/
  tar -xzf /work/wasm-pack.tar.gz -C /usr/local/bin --strip-components=1 "$WP/wasm-pack"
  cd /build && sh js/build.sh
  cp -r js/pkg-web js/pkg-node /work/
  printf "{\"rustc\":\"%s\",\"wasm_pack\":\"%s\"}\n" "$(rustc --version)" "$(wasm-pack --version)" > /work/toolchain.json
'

if [ "$MODE" = "--pin" ]; then
  rm -rf js/pkg-web js/pkg-node
  cp -r "$WORK/pkg-web" "$WORK/pkg-node" js/
  node js/manifest.mjs "$WORK/toolchain.json" "$IMAGE" "$PLATFORM" "$WP_SHA"
  echo "pinned. Commit js/manifest.json, and vendor js/pkg-web into pact-cloud (gateway/vendor/pact-identity/VENDORED.md)."
  exit 0
fi

echo "rebuilt on $PLATFORM in $IMAGE:"
FAILED=0
for pkg in web node; do
  # ...against its OWN entry. Single-file mode used to compare whatever it was given with pkg-web's
  # recorded hash, which passed only because the two packages happen to be byte-identical today.
  node js/verify.mjs "$WORK/pkg-$pkg/pact_identity_wasm_bg.wasm" "pkg-$pkg/pact_identity_wasm_bg.wasm" || FAILED=1
done
exit "$FAILED"
