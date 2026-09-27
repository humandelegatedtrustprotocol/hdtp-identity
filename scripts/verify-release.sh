#!/bin/sh
# Check a published release against itself, against the tagged source, and against a fresh build.
#
#   make verify-release VERSION=X.Y.Z
#
#   1. downloads every asset of vX.Y.Z (gh release download) into a scratch directory;
#   2. every asset against SHA256SUMS, and against manifest.json's `assets` (sha256 and size), with
#      none missing from either and none extra;
#   3. manifest.json's version, tags and commit against the tags vX.Y.Z and go/vX.Y.Z (fetched from
#      origin if absent), and its pin fields against js/manifest.json AT that tag;
#   4. the Wasm tarball: exactly the pinned pkg-web/ files, each with the pinned sha256 and size; the
#      corpus tarball: exactly go/exportcorpus's cases.json and zips at the tag, byte for byte;
#   5. a fresh container build of the tagged commit (js/reproduce.sh in a worktree of the tag), which
#      compares its bytes with that same js/manifest.json — so published = pinned = rebuilt.
# GH and RELEASE_REPRODUCE can be overridden; js/release.test.mjs runs this against a stub gh.
set -eu
cd "$(dirname "$0")/.."
VERSION="${1:-}"
GH="${GH:-gh}"
REPRODUCE="${RELEASE_REPRODUCE:-sh js/reproduce.sh}"
fail() { echo "verify-release: $*" >&2; exit 1; }
echo "$VERSION" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' || fail "VERSION must be X.Y.Z: make verify-release VERSION=0.2.0"
TAG="v$VERSION"

WORK="$(mktemp -d)"
REPO="$(pwd)"
cleanup() { git -C "$REPO" worktree remove --force "$WORK/src" >/dev/null 2>&1 || true; rm -rf "$WORK"; }
trap cleanup EXIT
mkdir "$WORK/assets"
$GH release download "$TAG" --dir "$WORK/assets"

for t in "$TAG" "go/$TAG"; do
  git rev-parse -q --verify "refs/tags/$t" >/dev/null || git fetch -q origin "refs/tags/$t:refs/tags/$t" || fail "tag $t is neither here nor on origin"
done
git show "$TAG:js/manifest.json" > "$WORK/pin.json"
mkdir "$WORK/tagged"
git archive "$TAG" go/exportcorpus | tar -x -C "$WORK/tagged"
node scripts/verify-assets.mjs "$WORK/assets" "$WORK/pin.json" "$VERSION" "$(git rev-parse "$TAG^{commit}")" "$(git rev-parse "go/$TAG^{commit}")" "$WORK/tagged/go/exportcorpus"

echo "verify-release: a fresh container build of $TAG"
git worktree add -q --detach "$WORK/src" "$TAG"
( cd "$WORK/src" && sh -c "$REPRODUCE" ) || fail "the fresh build of $TAG does not reproduce its pin"
echo "verify-release: ok — v$VERSION as published is what its tag pins and what a fresh build makes"
