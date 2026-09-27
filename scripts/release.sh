#!/bin/sh
# Cut a release, locally, up to the point where anything would leave the machine.
#
#   make release VERSION=X.Y.Z        (then `make publish VERSION=X.Y.Z` pushes and creates the release)
#
# In order, stopping at the first failure:
#   1. refuses: a VERSION that is not X.Y.Z; a branch other than $RELEASE_BRANCH (main); a dirty tree;
#      a VERSION not above the highest vX.Y.Z tag, or one already tagged; an empty `## Unreleased`
#      in CHANGELOG.md; a pact-protocol checkout that is dirty (its commit goes into the manifest);
#   2. runs the gate (gate.sh) on the tree as it is;
#   3. writes VERSION into every copy (scripts/version.mjs), dates the changelog section, checks the
#      lock file still resolves offline, and commits "Release X.Y.Z";
#   4. pins the Wasm of THAT commit (js/reproduce.sh --pin: the container build of `git archive HEAD`),
#      checks it (js/verify.mjs), and commits js/manifest.json;
#   5. tags that commit vX.Y.Z and go/vX.Y.Z (annotated; the Go module lives in go/);
#   6. packs dist/X.Y.Z/: pact-identity-wasm-web-X.Y.Z.tgz (the pinned pkg-web/), the `pact` CLI
#      for each target, manifest.json (scripts/release-manifest.mjs) and SHA256SUMS; the release
#      notes go to dist/X.Y.Z-notes.md.
# Nothing is pushed and nothing is published: that is scripts/publish.sh, a separate step, so all
# of the above can be looked at first. Every commit goes through this repository's hooks.
#
# The steps that run something heavy are commands, overridable from the environment, so that
# js/release.test.mjs can run this recipe against stubs: RELEASE_GATE, RELEASE_PIN,
# RELEASE_LOCKCHECK, RELEASE_CLI (called with <tag> <out-dir> <version> <targets...>),
# RELEASE_CLI_TARGETS, PROTOCOL_DIR, RELEASE_DATE. RELEASE_COMMIT_TRAILER, when set, is appended to
# both commit messages.
set -eu
cd "$(dirname "$0")/.."

VERSION="${1:-}"
BRANCH="${RELEASE_BRANCH:-main}"
GATE="${RELEASE_GATE:-sh gate.sh}"
PIN="${RELEASE_PIN:-sh js/reproduce.sh --pin}"
LOCKCHECK="${RELEASE_LOCKCHECK:-cargo metadata --locked --offline --format-version 1 >/dev/null}"
CLI="${RELEASE_CLI:-sh scripts/build-cli.sh}"
TARGETS="${RELEASE_CLI_TARGETS:-darwin-arm64 linux-amd64 linux-arm64}"
PROTOCOL="${PROTOCOL_DIR:-../pact-protocol}"
DATE="${RELEASE_DATE:-$(date -u +%Y-%m-%d)}"
TRAILER="${RELEASE_COMMIT_TRAILER:-}"

refuse() { echo "release: $*" >&2; exit 1; }

# 1. Refusals.
echo "$VERSION" | grep -Eq '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$' ||
  refuse "VERSION must be X.Y.Z (got '${VERSION}'): make release VERSION=0.2.0"
current="$(git symbolic-ref --quiet --short HEAD || echo '(detached)')"
[ "$current" = "$BRANCH" ] || refuse "on branch $current; a release is cut from $BRANCH"
[ -z "$(git status --porcelain)" ] || { git status --short >&2; refuse "the tree is not clean"; }
for t in "v$VERSION" "go/v$VERSION"; do
  if git rev-parse -q --verify "refs/tags/$t" >/dev/null; then refuse "tag $t already exists"; fi
done
last="$(git tag -l 'v[0-9]*.[0-9]*.[0-9]*' | node -e '
  const re = /^v(\d+)\.(\d+)\.(\d+)$/;
  const vs = require("fs").readFileSync(0, "utf8").split("\n").map((t) => re.exec(t)).filter(Boolean).map((m) => m.slice(1).map(Number));
  vs.sort((a, b) => a[0] - b[0] || a[1] - b[1] || a[2] - b[2]);
  if (vs.length) console.log(vs.at(-1).join("."));')"
if [ -n "$last" ]; then
  node -e '
    const [a, b] = process.argv.slice(1).map((v) => v.split(".").map(Number));
    process.exit((a[0] - b[0] || a[1] - b[1] || a[2] - b[2]) > 0 ? 0 : 1);' "$VERSION" "$last" ||
    refuse "$VERSION is not above the last release, v$last"
fi
node scripts/changelog.mjs --notes Unreleased >/dev/null 2>&1 ||
  refuse "CHANGELOG.md's '## Unreleased' section is empty or missing: say what $VERSION changes"
git -C "$PROTOCOL" rev-parse --git-dir >/dev/null 2>&1 ||
  refuse "$PROTOCOL is not a git checkout; the manifest records the protocol commit the gate ran against"
[ -z "$(git -C "$PROTOCOL" status --porcelain)" ] ||
  refuse "$PROTOCOL has uncommitted changes; the gate would run against a protocol no commit names"
PROTOCOL_COMMIT="$(git -C "$PROTOCOL" rev-parse HEAD)"
START="$(git rev-parse HEAD)"
echo "release: $VERSION from $BRANCH at $(git rev-parse --short HEAD) (last release: ${last:-none}); protocol at $(echo "$PROTOCOL_COMMIT" | cut -c1-12)"
echo "release: if a step below fails after a commit, nothing has left the machine: git reset --hard $START, fix, and run again"

# 2. The gate, on the tree as it is.
echo "release: gate"
sh -c "$GATE"

# 3. The version commit.
node scripts/version.mjs --set "$VERSION" >/dev/null
node scripts/version.mjs --check
node scripts/changelog.mjs --release "$VERSION" "$DATE"
sh -c "$LOCKCHECK" || refuse "the lock file does not resolve offline after the version change"
git add -u
git commit -q -m "Release $VERSION" -m "One version for the crates, the Go module and the Wasm package; CHANGELOG.md dated.${TRAILER:+

$TRAILER}"

# 4. The pin of that commit, and its record.
echo "release: pin"
sh -c "$PIN"
node js/verify.mjs
git add js/manifest.json
git commit -q -m "The pin of $VERSION" -m "js/reproduce.sh --pin of the release commit $(git rev-parse --short HEAD).${TRAILER:+

$TRAILER}"
COMMIT="$(git rev-parse HEAD)"

# 5. The tags.
git tag -a "v$VERSION" -m "pact-identity $VERSION" "$COMMIT"
git tag -a "go/v$VERSION" -m "pact-identity $VERSION (the Go module, github.com/pact-cloud/pact-identity/go)" "$COMMIT"

# 6. The assets.
DIST="dist/$VERSION"
rm -rf "$DIST" "dist/$VERSION-notes.md"
mkdir -p "$DIST"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
mkdir "$STAGE/pkg-web"
# Exactly the files the pin lists under pkg-web/, copied from the pinned bytes js/verify.mjs just checked.
WEB_FILES="$(node -e 'for (const k of Object.keys(require("./js/manifest.json").files)) if (k.startsWith("pkg-web/")) console.log(k)')"
[ -n "$WEB_FILES" ] || refuse "js/manifest.json lists no pkg-web/ files"
for f in $WEB_FILES; do cp "js/$f" "$STAGE/$f"; done
TGZ="pact-identity-wasm-web-$VERSION.tgz"
COPYFILE_DISABLE=1 tar -czf "$DIST/$TGZ" -C "$STAGE" pkg-web
listed="$(tar -tzf "$DIST/$TGZ" | grep -v '/$' | sed 's#^\./##' | sort)"
[ "$listed" = "$(echo "$WEB_FILES" | sort)" ] || { echo "$listed" >&2; refuse "$TGZ does not hold exactly the pinned pkg-web/ files"; }

echo "release: pact CLI for $TARGETS"
# shellcheck disable=SC2086 # the targets are words
sh -c "$CLI \"\$@\"" cli "v$VERSION" "$DIST" "$VERSION" $TARGETS
for t in $TARGETS; do [ -s "$DIST/pact-$VERSION-$t" ] || refuse "no CLI binary for $t"; done

node scripts/release-manifest.mjs "$DIST" "$VERSION" "$COMMIT" "$PROTOCOL_COMMIT"
node scripts/changelog.mjs --notes "$VERSION" > "dist/$VERSION-notes.md"
( cd "$DIST" && shasum -a 256 -c SHA256SUMS >/dev/null ) || refuse "SHA256SUMS does not verify what was just written"

echo
echo "release: $VERSION is cut, locally. Tags v$VERSION and go/v$VERSION name $(git rev-parse --short HEAD); assets in $DIST:"
ls -l "$DIST" | tail -n +2
echo "release: nothing has been pushed. make publish VERSION=$VERSION pushes $BRANCH and both tags, and creates the release."
