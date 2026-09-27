#!/bin/sh
# Publish a release cut by scripts/release.sh: the one step that leaves the machine.
#
#   make publish VERSION=X.Y.Z
#
# Checks dist/X.Y.Z against its SHA256SUMS, and the branch and both tags against the manifest's
# commit, then pushes the branch and both tags with a plain `git push` (through the pre-push hook,
# which runs gate.sh — never forced), and creates the GitHub release with every asset and the
# changelog section as its notes. GH (default gh) and RELEASE_BRANCH (default main) can be
# overridden; js/release.test.mjs runs this against a bare repository and a stub gh.
set -eu
cd "$(dirname "$0")/.."
VERSION="${1:-}"
BRANCH="${RELEASE_BRANCH:-main}"
GH="${GH:-gh}"
refuse() { echo "publish: $*" >&2; exit 1; }

echo "$VERSION" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' || refuse "VERSION must be X.Y.Z: make publish VERSION=0.2.0"
DIST="dist/$VERSION"
[ -f "$DIST/manifest.json" ] && [ -f "$DIST/SHA256SUMS" ] && [ -f "dist/$VERSION-notes.md" ] ||
  refuse "$DIST is not a cut release: make release VERSION=$VERSION first"
( cd "$DIST" && shasum -a 256 -c SHA256SUMS >/dev/null ) || refuse "$DIST does not match its SHA256SUMS"
want="$(node -p "require('./$DIST/manifest.json').commit")"
for t in "v$VERSION" "go/v$VERSION"; do
  got="$(git rev-parse -q --verify "refs/tags/$t^{commit}")" || refuse "tag $t does not exist"
  [ "$got" = "$want" ] || refuse "tag $t names $got, and the manifest was written for $want"
done
[ "$(git rev-parse -q --verify "refs/heads/$BRANCH")" = "$want" ] || refuse "$BRANCH is not at the release commit $want"

git push origin "refs/heads/$BRANCH:refs/heads/$BRANCH" "refs/tags/v$VERSION" "refs/tags/go/v$VERSION"
# shellcheck disable=SC2046 # one argument per asset; the names hold no spaces
$GH release create "v$VERSION" --verify-tag --title "pact-identity $VERSION" --notes-file "dist/$VERSION-notes.md" $(ls -d "$DIST"/*)
echo "publish: v$VERSION pushed and released. make verify-release VERSION=$VERSION checks what was published."
