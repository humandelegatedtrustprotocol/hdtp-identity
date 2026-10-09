# Changelog

One version for everything in this repository: the Rust crates (`hdtp-identity`,
`hdtp-identity-wasm`, `hdtp-limits`, the `hdtp` CLI), the Go module `github.com/humandelegatedtrustprotocol/hdtp-identity/go` and the
Wasm package. A release is tagged `vX.Y.Z` and `go/vX.Y.Z` on one commit (`make release`), and its
GitHub release carries the Wasm package, the CLI binaries, `manifest.json` and `SHA256SUMS`.
Versions follow semver; before 1.0.0 a minor version may change the contract (`CONTRACT.md`).

Entries go under `## Unreleased` as they land; `make release` dates them.

## Unreleased

- **An export carries a former contact's conversation (SEP-0004).** A removed thread is a row of
  `threads.csv` whose `contact` is not a root of `contacts.csv`. It carries the names the contact is
  known by in two new columns, `contact_name` and `contact_display_name`, which are empty on every
  other thread. `threads.csv` takes the longer header only when a removed thread exists, so a file
  without one is the file this library wrote before, and the manifest does not change. A removed
  thread's root is a fingerprint and not the owner's. Its names are at most 200 characters (the
  display name cut, as a contact's is) and the same on every removed thread of that root.
  `export_read` answers the two names on a removed thread and on no other; `export_write` takes
  them on a removed thread and refuses them on any other. A message's `contact` may be a removed
  thread's: its refusal now reads `names no contact in contacts.csv and no removed thread` for every
  file, where it read `names no contact in contacts.csv`. A threads.csv header that is neither of the
  two is refused naming both. The corpus gains `valid-export-with-removed-thread.zip`,
  `valid-export-with-a-nameless-removed-thread.zip` and fourteen refusals (60 cases);
  `valid-export.zip` and `valid-book.zip` are byte for byte what they were. The reader keeps a removed
  thread's names by the row (Go) or as digests (Rust), never as copies: a file whose every thread is
  removed with a root of its own allocates 7.5–7.7× its threads.csv in the Go port and peaks at
  3.8–3.9× in the core (11.3–11.6× and 6.1× before), and the largest such file grows a Wasm instance
  by 84.0 MB; the memory tests hold both at N and 4N rows.
- **A fingerprint has one spelling.** `sha256:` and 43 base64url characters whose last is one of
  `AEIMQUYcgkosw048`: the two spare bits are zero (RFC 4648 §3.5). Any other last character spells the
  same 32 bytes again, a second name for one root: a live contact's root so spelled would have read as
  a removed thread, the owner's as a removed thread that is not the owner, and two contacts.csv rows
  as two roots. Both ports refuse it everywhere a fingerprint is read (SEP-0004, SPEC §2); the corpus
  holds the three aliases.
- **The seed's six stale-sender scenarios run on both ports.** `js/intrude.mjs` carries the
  scenarios hdtp-spec's `vectors/intrude.mjs` gained for the stolen leaf key in the small form of
  §13.2 and for the sender a renewal has not reached (§2): the superseded key the host still holds
  opens what a contact seals to it, until the leaf's `notAfter`, and so does whoever holds that
  key; once the renewal reaches the contact, what it seals next is closed to it, and a replay of
  the superseded chain does not roll the pin back. Verdicts agree with the seed on both ports.
- **The repository is written for a public reader.** `NOTICE`, `SECURITY.md`, `CONTRIBUTING.md`,
  `GOVERNANCE.md`, `MAINTAINERS.md`, `CODE_OF_CONDUCT.md`, `CITATION.cff` and `.github/` (two issue
  forms, the pull-request template, `CODEOWNERS`; no workflow), modelled on hdtp-spec's; the README
  in the public form (`go get …/go@v0.7.3`, Cargo by git tag, the Wasm from the release asset), with
  every number read from the tree (seven version copies, the pinned `.wasm` at 863,199 bytes, Node 22,
  the pin's `linux/arm64` builder); `gate.sh`, the hooks, `js/reproduce.sh` and the `Makefile` no
  longer call hdtp-spec private, and `make verify-release` no longer rewrites the remote to SSH;
  the limits vectors' batondeck citations carry their measured dates, as a private repository's.

## 0.7.3 — 2026-10-07

- **SPEC §9 9.#4 follows SEP-0003.** `js/musts.json` holds the amended rule (hash `f835c346eb45`):
  a left address is kept for 24 hours for the account that held it, which may be one the person
  shares at the host. The `hdtp` wallet's move notice says so.

## 0.7.2 — 2026-10-07

- **`hdtp id issue` counts the days the leaf has.** A leaf ended with its root printed the days
  asked beside the shorter span; the consent line now reads `(31 days; 365 asked)`.
- **`hdtp id issue` says each thing once, on the consent screen where the person decides**: that
  the leaf ends with its root, that the host is new, that the identity moves. The core's warnings of
  the same facts are no longer printed again after the signature.
- **PROOFS.md says which elsewhere rows name an artefact and which a role.** Of the 30 MUSTs held
  outside this repository, 16 name the artefact that holds them and 14 the implementation role, by
  declaration, as hdtp-spec's §12 (The record) now allows; the header had said every one named an
  artefact.
- **SPEC §4 4.#1 names the tests that hold it**: hdtp-gateway's `TestP1ExitTwoNodesPairAndMessage`
  (the landing's chain validates and its leaf is the card's certificate) and `TestVerifyOfferRefusals`
  (the redeemer refuses a chain that is not the card's), in place of `TestLandingNoOracle404`, which
  holds the not-found sentence and no MUST. Its gap is named: no test fails when the node's redeemer
  ignores the chain's validation, since its other checks refuse every case.

## 0.7.1 — 2026-10-06

- **SPEC §9 9.#4 follows SEP-0002.** `js/musts.json` holds the amended rule (hash `9c1f6a96da61`):
  an address left, deleted or moved, is kept for the person for 24 hours, then freed.
- **The `hdtp` wallet's move notice states that rule** in the web wallet's words; it no longer says
  the address stays reserved until the old leaf expires.

- **The gate holds hdtp-spec's JSON Schema to this contract.** `gate.sh`, and so the pre-push hook
  and `make release`, runs hdtp-spec's `schema/gen.mjs --check` with `HDTP_IDENTITY_DIR` set to this
  tree: the spec's committed `schema/*/schema.json` must be what this `contract/contract.json`
  generates. 0.7.0 shipped a contract change that schema did not carry, found only when the
  whitepaper's publish ran the spec's own `schema:check`. On a difference the gate fails and names
  the fix: regenerate the schema in hdtp-spec first, as a spec PR.

## 0.7.0 — 2026-10-05

- **A card whose folding a paste damaged reads (hdtp-spec SEP-0001, draft §3 *Reading a card*).**
  `card_decode` (Go: `DecodeCard`), in both ports and the seed: after RFC 6350 unfolding,
  `X-HDTP-CERT` takes every following line that does not start a property
  (`[group.]NAME[;params]:`), blank lines included, and loses every space, tab, CR and LF before it
  is read. A card pasted through a chat — continuations without their leading space, blank lines
  between them — was refused `certificate does not parse` (seen on staging, 2026-10-05). A line that
  starts a property is never taken into the certificate. A certificate with a space or a tab inside
  it now reads (it was `not base64url`); a vertical tab, a no-break space and every other character
  outside base64url are refused as before. A cut certificate is still refused by the DER parse; a
  changed character either fails to parse or reads as a certificate its root did not sign, which
  reading cannot find (a card carries no root) — the position of a card altered in transit, as before
  (`tests/card_paste.rs`, `go/card_paste_test.go`, `js/cases/cards.mjs`).

## 0.6.0 — 2026-10-04

- **A root may carry an end date (SPEC 1.0.0 as amended 2026-10-04, §14.1, §14.2, §2.2).** Every
  root still has none by default (`99991231235959Z`) and is never rotated; `build_root` and
  `root_tbs` take an optional `not_after` (Go: `RootOpts.NotAfter`, `RootTBS`'s `notAfter`), refuse
  one before `not_before`, and the profile admits any root `notAfter` from its `notBefore` on.
  `validate_chain`'s rule 4 refuses `root has expired` (first) and `leaf outlives the root` (last),
  by one predicate in each port (`x509::root_expired`, `RootExpired`), inclusive as RFC 5280 reads
  validity. Appendix B's five new chain cases are read with their reasons.
- **Every wallet refuses an expired root before it signs, as `root_expired`**, a new code in the
  library's vocabulary, never on the wire: `issue_from_csr`, `issue_tbs_from_csr` (before a `tbs`
  exists), `wallet_issue` (before its proof of possession), and the CLI's `id issue` (before the
  leaf is shown, the passphrase asked again or a card touched). A leaf that would outlive its root
  ends with it, and `warnings` says so (the two issuers gained `warnings`).
- **`issue_from_csr` and `issue_tbs_from_csr` take `root_cert`** in place of `root_cn` and
  `root_spki` (Go: `IssueOpts.Root` in place of `RootCN` and `RootPub`): the name, key and end date
  are read from the root's certificate, which must be a root of the profile and self-signed;
  `root_pkcs8` must be its key. `build_leaf` and `leaf_tbs` stay raw builders for tests and vectors,
  and judge no date against a root.
- **`hdtp id create --ends <RFC 3339>`**, with `--piv` too: the identity's end date, refused before
  anything is asked when it is not in the future.
- **Cards fold at 75 octets** (RFC 6350 §3.2, as CONTRACT §4 says), never splitting a UTF-8
  sequence, in both ports and the seed; they counted UTF-16 code units, so a name beyond ASCII
  folded where no octet-counting reader would.

## 0.5.0 — 2026-10-03

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
