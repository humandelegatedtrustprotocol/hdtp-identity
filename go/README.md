# go: the Go port of hdtp-identity

An independent implementation of the identity core in Go: the same contract as `crates/hdtp-identity`
(`contract/contract.json`, rendered as `CONTRACT.md`), written rule for rule and word for word, and
tied to the Rust core by the same vectors and a cross-port parity run. The module is
`github.com/humandelegatedtrustprotocol/hdtp-identity/go` (package `hdtpidentity`, `go 1.25`);
HDTP Gateway, the self-hosted node, imports it. Its tags are `go/vX.Y.Z`, each naming the same commit
as `vX.Y.Z`, and the version is the repository's one version (`ModuleVersion` in `api.go`, held equal
to the crates' by `scripts/version.mjs --check`). The root `README.md` says how to `go get` it and
`CONTRIBUTING.md` how the ports are held together; this file does not repeat either.

Dependencies (`go.mod`): `golang.org/x/crypto` (Argon2id and ChaCha20-Poly1305) and
`filippo.io/edwards25519` (indirect, used for the small-order check of `strict.go`); the rest is the
standard library.

## What it holds

| Package | What |
|---|---|
| `hdtpidentity` (this directory) | the library |
| [`cmd/hdtp-identity-go`](cmd/hdtp-identity-go) | the stdin adapter the JavaScript harness drives the port through |
| [`exportcorpus`](exportcorpus) | the fixture corpus of the export (SPEC section 9.2), embedded; `exportcorpus/gen` writes it |

The library's one boundary is `Call(name string, args json.RawMessage) json.RawMessage`: a function
name and a JSON object in, one JSON object out, never a panic, with the names and shapes of
`CONTRACT.md`. Arguments are read once and held to the members the function declares
(`api_args.go`); the bodies are in `api_<section>.go`, one file per contract section (build, keys,
certificates, csr, cards, envelopes, vault, ledger, signing, export, limits), dispatched by the
`functions` map in `api.go`. Beneath `Call`, the typed API is exported for a Go host, which is how
the node uses it. `go doc ./...` lists it; by concern:

- Keys and signatures: `GenerateKey`, `KeyFromSeed`, `ParsePKCS8`, `ParseSPKI`, `PrivateKey`,
  `PublicKey`, `Fingerprint`, `KeyID`, `SignDetached`, `VerifyDetached`, `DeriveSeed`, `PrfSalt`
  (`keys.go`, `hpke.go`).
- Certificates and chains: `BuildRoot`, `BuildLeaf`, `RootTBS`, `LeafTBS`, `Assemble`, `Parse`,
  `ValidateChain`, `CompareLeaves`, `ProfileError`, `IsNormalHTTPS`, `AddressGuard`, `IPIsPrivate`
  (`x509.go`, `der.go`, `address.go`, `strict.go`).
- Requests and issuance: `CSRNew`, `CSRCheck`, `IssueFromCSR`, `IssueTBSFromCSR`,
  `SigningRequestCheck` (`csr.go`, `signing.go`).
- Cards and refresh: `EncodeCard`, `DecodeCard`, `RefreshCheck` (`card.go`, `refresh.go`).
- Envelopes: `SuiteForKey`, `Seal`, `Open`, `SealRequest`, `SealResult`, `OpenResult`,
  `FollowRenewed`, `Decide`, `DecideChain`, with `Envelope`, `NodeState`, `Pin` and `Decision`
  (`envelope.go`, `hpke.go`).
- Vault and wallet: `VaultSeal`, `VaultOpenDoc`, `CheckFile`, `CheckRecord`, `WalletIssue`,
  `LedgerCheck`, `ReadLedger` (`vault.go`, `ledger.go`).
- The export: `ReadExportZip` and `WriteExportZip` over `archive/zip`, plus the contract's
  `export_*` functions (`export.go`, `export_csv.go`, `export_zip.go`).
- Call budgets: `LimitsDecide`, `LimitsRules`, `LimitsCharge`, `LimitsStore`, `LimitsMemoryStore`
  (`limits.go`).
- Constants held to the contract: `ModuleVersion`, `SpecVersion`, `VaultFormat`, `DefaultKDF`,
  `MaxLifetimeSeconds`, `SigningMaxAhead`, `LimitsIdleMS`, the `Export...Max` bounds.

## What it refuses, and how

Failures are `{"error", "why"}` with a code from the contract's `ErrorCode`: `bad_request`, `parse`,
`unsupported`, `envelope_invalid`, `vault`, `root_expired`, `key`, `internal`; each function declares
which it can fail with, and `js/parity.mjs` fails a port that answers with another or words a
refusal differently from the Rust core. A member a function does not declare is refused by name
before any member is read. Bytes a caller hands the boundary are read forgiving the padding and the
standard alphabet and nothing else (`b64.go`, held by `js/b64url-arguments.json`). `decide` and
`decide_chain` answer `envelope_invalid`, `chain_required`, `certificate_renewed` and
`pending_approval` as successes.

## Invariants

- `Call` never panics across the boundary; `unit_test.go`'s `TestCallNeverPanics` sends it the same
  hostile object (`js/cases/hostile.json`) that `crates/hdtp-identity/tests/boundary.rs` sends the core.
- CSV is read and written by `export_csv.go`, strictly, and not by `encoding/csv`, which skips a
  blank line and rewrites a quoted CRLF to LF; a reader that repairs what it reads is not the rule
  both ports hold.
- Every instant is read by one grammar (`instant_test.go`); an Ed25519 key or signature point of
  small order is not a key (`strict.go`); an envelope's lifetime is bounded.
- Constants are written in both ports and held to the single copy in `contract/contract.json` by
  `constants_test.go` and `export_limits_test.go`.

## Held by

Gate steps (`gate.sh`): "Go port: vet, tests, adapter" (`go vet ./...`, `go test ./...`,
`make build`); "The corpus the CLI writes for a fresh owner reads in the Go port as its cases.json
says" (`TestReadExportZipAnswersTheCorpusWrittenForAnotherOwner`); `node js/check.mjs --port go`
(Appendix B through the adapter); `node js/intrude.mjs --port go` (the intrusion scenarios against
the seed's verdicts); `node js/parity.mjs` (both ports, same arguments, same answers, validated
against the contract); `js/limits.test.mjs` and `js/doors.test.mjs`.

Test files here: `vectors_test.go` (Appendix B), `unit_test.go`, `review_test.go` (the cryptography
review of 2026-09-14 and P-21 of 2026-09-23), `card_paste_test.go`, `b64_test.go`,
`api_args_test.go`, `instant_test.go`, `constants_test.go`, `ledger_test.go`, `signing_test.go`,
`limits_test.go`, `export_test.go`, `export_zip_test.go`, `export_corpus_test.go`,
`export_limits_test.go`, `export_memory_test.go`, `export_growth_test.go`, `helpers_test.go`
(helpers only).

## What it does not do

It resolves no name: `AddressGuard` checks a name as written, and the host applies `IPIsPrivate` to
what it resolves. The `ReadExportZip` and `WriteExportZip` conveniences are not contract functions:
parity does not reach them, and this port's tests hold them to the corpus instead. It keeps no
state: pins, node state and the ledger are the host's and are handed in. `limits.go`'s header says the
node decides its budgets in its sidecar with the Rust crate itself, and that nothing outside this
module calls the Go budgets.
