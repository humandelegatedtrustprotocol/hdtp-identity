# Changelog

One version for everything in this repository: the Rust crates (`pact-identity`,
`pact-identity-wasm`, the `pact` CLI), the Go module `github.com/pact-cloud/pact-identity/go` and the
Wasm package. A release is tagged `vX.Y.Z` and `go/vX.Y.Z` on one commit (`make release`), and its
GitHub release carries the Wasm package, the CLI binaries, `manifest.json` and `SHA256SUMS`.
Versions follow semver; before 1.0.0 a minor version may change the contract (`CONTRACT.md`).

Entries go under `## Unreleased` as they land; `make release` dates them.

## Unreleased

The first release of pact-identity as a repository of its own (split from the umbrella
`pact-gateway` on 2026-09-27). What 0.1.0 was is unchanged in behaviour; what is new is how it is
named, depended on and released.

- The Go module is `github.com/pact-cloud/pact-identity/go` (it was
  `github.com/tech-sumit/pact-gateway/pact-identity`); the crates name this repository.
- Releases: `make release`, `make publish`, `make verify-release`; one version across the crates,
  the Go module (`ModuleVersion`) and the Wasm package, held equal by `scripts/version.mjs --check`.
- The library no longer reads or describes a hosting platform: the MUST holders that cited one are
  that platform's to keep, `js/musts.mjs` checks the node's names only, and test hosts are `.example`.
- The repository's own hooks (`githooks/`): rustfmt and clippy at commit, `gate.sh` at push.
- `js/check-no-1x.mjs`: no tracked file carries a PACT 1.x name; its marker list is held
  byte-identical to pact-protocol's.
