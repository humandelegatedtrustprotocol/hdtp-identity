# Changelog

One version for everything in this repository: the Rust crates (`hdtp-identity`,
`hdtp-identity-wasm`, `hdtp-limits`, the `hdtp` CLI), the Go module `github.com/humandelegatedtrustprotocol/hdtp-identity/go` and the
Wasm package. A release is tagged `vX.Y.Z` and `go/vX.Y.Z` on one commit (`make release`), and its
GitHub release carries the Wasm package, the CLI binaries, `manifest.json` and `SHA256SUMS`.
Versions follow semver; before 1.0.0 a minor version may change the contract (`CONTRACT.md`).

Entries go under `## Unreleased` as they land; `make release` dates them.

## Unreleased

- **HDTP 1.0.** The library implements HDTP 1.0.0, hdtp-spec's `docs/specification/1.0/`, and
  `version` answers spec `1.0.0` in both ports. The specification's text is read through
  hdtp-spec's `site/spec-source.mjs` (the index page and the pages it links); the Rust and Go tests
  and `hdtp vectors check` read the same pages, and `--spec` takes a version directory or one
  document carrying Appendix B.
- **Every name is HDTP's.** The crates are `hdtp-identity`, `hdtp-identity-wasm`, `hdtp-limits` and
  `hdtp` (the CLI); the Go module is `github.com/humandelegatedtrustprotocol/hdtp-identity/go`,
  package `hdtpidentity`; the release assets are `hdtp-<version>-<os>`,
  `hdtp-identity-wasm-web-<version>.tgz` and `hdtp-identity-exportcorpus-<version>.tgz`; the
  environment variables are `HDTP_*`.
- **The wire labels and every version restart at 1.** HPKE `info` `HDTP-SEAL-v1`; suites
  `HDTP-SEAL-P256` and `HDTP-SEAL-X25519`; the challenges `HDTP root proof v1` and
  `HDTP card-attach proof v1`; the derivation `info` strings `hdtp/root/1`, `hdtp/store-key/1`,
  `hdtp/store-id/1` over the PRF input `SHA-256("hdtp/vault/1")`; media types
  `application/hdtp-call+json` and `application/hdtp-result+json`; the card's `X-HDTP-VERSION:1`,
  `X-HDTP-CERT` and `X-HDTP-SEAL`; an envelope header's `v` is 1; an export's `hdtp_export` is 1;
  the vault is `hdtp-vault/1` and its plaintext's `v` is 1. Anything else is refused as before, and
  nothing converts. The Go constant for the info string is `Info` (Rust `envelope::INFO`). One
  refusal a caller reads changed its article with the name: `not an hdtp-vault/1 document`.
- **The vectors and the corpus are new bytes**: Appendix B from the seeds `hdtp-1.0-vectors/{label}`,
  the export corpus from `hdtp-identity/exportcorpus/{label}`, and the live battery's version
  scenario is `unknown-v2`.
- **The name guard replaces the guard of retired behaviours' names.** `js/check-names.mjs` and `js/hdtp-names.txt`, byte for
  byte hdtp-spec's `scripts/` copies, fail the gate on the name the list forbids in any tracked
  path or text, and on the names of the behaviours HDTP does not have; `js/check-no-1x.mjs` and its list are gone.
