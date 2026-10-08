# scripts

The release of hdtp-identity, as scripts. `make release`, `make publish` and `make verify-release`
at the repository root (`Makefile`) are one-line wrappers around `release.sh`, `publish.sh` and
`verify-release.sh`; the recipes are scripts so that they fail the way a script fails (macOS make
3.81 ignores `.SHELLFLAGS`). They are run by the maintainer, from the maintainer's machine: this
repository has no CI and no CI credential, and nothing leaves the machine before `make publish`.
`CONTRIBUTING.md` and the root `README.md` ("Versions") describe a release from the outside; this file
lists what each script does and refuses.

## What it holds

| Script | What it does |
|---|---|
| `release.sh` | `make release VERSION=X.Y.Z`: cuts a release locally. Refuses first, then runs the gate (`gate.sh`), writes VERSION into every copy and commits "Release X.Y.Z", pins the Wasm of that commit (`js/reproduce.sh --pin`) and commits `js/manifest.json`, tags the commit `vX.Y.Z` and `go/vX.Y.Z` (annotated; the Go module lives in `go/`), and packs `dist/X.Y.Z/`: `hdtp-identity-wasm-web-X.Y.Z.tgz` (the pinned `pkg-web/`), `hdtp-identity-exportcorpus-X.Y.Z.tgz` (`go/exportcorpus`'s `cases.json` and zips), the `hdtp` CLI per target, `manifest.json` and `SHA256SUMS`; the release notes go to `dist/X.Y.Z-notes.md` |
| `publish.sh` | `make publish VERSION=X.Y.Z`: checks `dist/X.Y.Z` against its `SHA256SUMS` and the branch and both tags against the manifest's commit, then pushes the branch and both tags with a plain `git push` (through the pre-push hook, never forced) and creates the GitHub release with every asset and the changelog section as its notes |
| `verify-release.sh` | `make verify-release VERSION=X.Y.Z`: downloads a published release and checks every asset against `SHA256SUMS` and `manifest.json`, the manifest against the tags and the pin at the tag, the Wasm and corpus tarballs against the tag, and a fresh container build of the tagged commit (`js/reproduce.sh` in a worktree of the tag) against that same pin |
| `verify-assets.mjs` | the offline half of `verify-release.sh`: a directory of downloaded assets judged against `SHA256SUMS`, `manifest.json`, the tags' commits and the pin at the tag |
| `release-manifest.mjs` | writes the release's `manifest.json` (the tagged commit's `js/manifest.json` plus `version`, `commit`, `tags`, `protocol_commit` and the sha256 and size of every other asset) and `SHA256SUMS` into the assets directory |
| `build-cli.sh` | builds the `hdtp` CLI binaries of a release from a commit (`git archive` of the ref, never the tree): `darwin-arm64` natively, `linux-arm64` natively in the image `js/builder.json` names, `linux-amd64` cross-compiled in that arm64 container (rustc crashes under amd64 emulation on an arm64 Mac) |
| `changelog.mjs` | `--release X.Y.Z YYYY-MM-DD` moves `## Unreleased` under a dated version heading (refuses an empty Unreleased); `--notes X.Y.Z` prints a version's section |
| `version.mjs` | the one version and every place it is written: `Cargo.toml`, the four crates' entries in `Cargo.lock`, `js/package.json` and `go/api.go`. No argument prints it; `--check` exits 1 unless every copy agrees; `--set X.Y.Z` writes it |

## What it refuses, and how

`release.sh` and `publish.sh` refuse with `release: <why>` or `publish: <why>` on stderr and exit 1.
In `release.sh` the refusals of its first step (down to the hdtp-spec checkout below) come before anything is
committed or tagged; the later ones follow the commits and tags it has made. `release.sh` refuses: a
VERSION that is not X.Y.Z; a branch other than `main`; a dirty tree; a tag that already exists;
a VERSION not above the highest existing `vX.Y.Z` tag; an empty or missing `## Unreleased` in
`CHANGELOG.md`; an hdtp-spec checkout that is not a git checkout or has uncommitted changes (its
commit goes into the manifest); a lock file that does not resolve offline after the version change;
a tarball that does not hold exactly the pinned files; a missing CLI binary; `SHA256SUMS` that does
not verify. `publish.sh` refuses: a VERSION that is not X.Y.Z; a `dist/X.Y.Z` that is not a cut
release or does not match its `SHA256SUMS`; a tag missing or naming another commit than the
manifest's; the branch not at the release commit.

## Invariants

- A release is one version for the Rust crates, the Go module and the Wasm package, and both tags
  name the same commit; `version.mjs --check` is a gate step ("One version everywhere it is
  written").
- The Wasm in a release is the pinned container build of the tagged commit, and
  `verify-release.sh` rebuilds it and compares: published = pinned = rebuilt.
- The CLI binaries are built from a commit and are not bit-reproducible (`build-cli.sh`).
- A push is a plain `git push`, through the hooks; nothing here forces.
- The heavy steps of `release.sh` are commands overridable from the environment (`RELEASE_GATE`,
  `RELEASE_PIN`, `RELEASE_LOCKCHECK`, `RELEASE_CLI`, `RELEASE_CLI_TARGETS`, `PROTOCOL_DIR`,
  `RELEASE_DATE`; `RELEASE_COMMIT_TRAILER`), so the recipe can be run against stubs.

## Held by

`js/release.test.mjs` runs `release.sh`, `publish.sh` and `verify-release.sh` for real in a scratch
copy of the repository with a bare repository as origin, a stub gate, a stub pin that runs the real
`js/manifest.mjs`, a stub CLI build and a stub `gh`; it is in the gate's `js-tests` suite
(`node_tests js-tests js/*.test.mjs`). `version.mjs --check` is its own gate step.

## What it does not do

Nothing here runs on another machine or on a schedule, and nothing builds the Wasm on every push: the
container build runs only when `release.sh` pins and in `verify-release.sh`. `publish.sh` creates
the release with the maintainer's own `gh` (`GH`, default `gh`), from `RELEASE_BRANCH` (default `main`). `build-cli.sh` builds three targets only.
