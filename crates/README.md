# crates

The Cargo workspace of hdtp-identity (`Cargo.toml` at the repository root): four crates, one version
(`version.workspace`). `hdtp-limits` is a dependency of `hdtp-identity`, `hdtp-identity-wasm` and
`hdtp` are two front ends over `hdtp-identity`, and nothing here is published to crates.io. The root
`README.md` says how a host takes the library; `CONTRIBUTING.md` and `gate.sh` say how it is built
and gated.

This file describes the three crates that are inputs of the pinned Wasm: `hdtp-identity`,
`hdtp-identity-wasm` and `hdtp-limits`. They have no `README.md` of their own, on purpose.
`js/inputs.mjs` lists those three directories as whole directories, and `node js/verify.mjs`
compares the SHA-256 of `git ls-tree -r HEAD` over them with the one `js/manifest.json` records. A
file added under any of them, a README included, changes that listing (55 entries become 56, and
the hash changes), makes the pin stale, and demands a container re-pin (`sh js/reproduce.sh --pin`)
for a file the compiler never reads. This file sits in `crates/` itself, which is not on the list.
The fourth crate, `crates/hdtp`, is not an input and has its own [README](hdtp/README.md).

| Crate | What it is | Who uses it |
|---|---|---|
| `hdtp-identity` | the core: certificates, envelopes, cards, requests, the vault, the export, the receiving rules | the Wasm crate and the CLI link it; the Go port is its independent twin |
| `hdtp-identity-wasm` | the `wasm-bindgen` boundary over the core | built into `js/pkg-web` and `js/pkg-node`, which BatonDeck vendors from the release asset |
| `hdtp-limits` | SPEC section 12's call budgets, as token buckets | linked into the core, which answers it as three contract functions |

## hdtp-identity

The identity core of HDTP (`crate-type = ["rlib"]`). `src/lib.rs`: the certificate profile and chain
validation of SPEC section 14, the sealed envelopes of section 13 in both forms, the card codec of
section 3, PKCS #10 requests and issuance per section 9, the receiving rules as one pure decision,
and the vault. Stateless: the host applies what it returns. `hdtp-spec/vectors/lib` is the
specification of every byte.

### What it holds

The public surface is `hdtp_identity::call(name, args_json) -> json` (`src/api.rs`) and the modules
beneath it. The contract (`contract/contract.json`) declares 55 functions in 11 sections; ten of
the sections have a body in `src/api/<section>.rs`, and `build`'s only function, `version`, is an arm
of the dispatcher in `src/api.rs`.

| Module | What it holds |
|---|---|
| `der` | the DER the profile needs: an encoder, and a strict walker (definite and minimal lengths only, nothing past the end) |
| `keys` | Ed25519 and P-256 in PKCS #8 and SubjectPublicKeyInfo, fingerprints, the conversions of section 13.1 to X25519 |
| `canonical` | RFC 8785 for the objects HDTP canonicalises |
| `hpke` | HPKE Base mode (RFC 9180) for the two suites, `HDTP-SEAL-P256` and `HDTP-SEAL-X25519` |
| `x509` | the section 14.1 profile as bytes, the exact-profile check, section 14.2 chain validation, the section 14.3 comparison |
| `address` | the address guard of sections 3 and 14.2; resolution is the host's, `ip_is_private` judges what it resolves |
| `csr` | PKCS #10 with an exact profile, the wallet's checks, issuance (section 9) |
| `signing` | a signing request a host POSTs to a web wallet, and everything a wallet can decide about it before a person sees it (section 9.1) |
| `card` | the section 3 card: a vCard 4.0 with the leaf in it, folded per RFC 6350, read back with the intake rules |
| `refresh` | what a peer's answer to `get_card` proves about one pinned contact and what the pin becomes (sections 3 and 14.3) |
| `envelope` | sealing in both forms, the caller's side of a result, `certificate_renewed`, and `decide`, the receiving side as one pure function over state the host supplies (`envelope/decide.rs`, `envelope/state.rs`) |
| `vault` | the vault and the record: Argon2id and AES-256-GCM with the document's header as AAD |
| `ledger` | the wallet's ledger rules: what signing a leaf for an endpoint would mean, read off the ledger |
| `export` | the export and the book (section 9.2): the rules of validation that can be decided on what a host read from the zip |
| `time` | UTC instants as Unix seconds; RFC 3339 at the boundary |
| `util` | `Error`, `Result`, encodings, randomness |

The 55 functions by contract section, from `contract/contract.json` (`CONTRACT.md` has the
arguments and answers): build (`version`); keys; certificates; csr; signing; cards; envelopes;
vault (including `wallet_issue`); ledger; export; limits. Rust tests that hold the core are in
`tests/` (`boundary.rs`, `card_paste.rs`, `constants.rs`, `findings.rs`, `limits.rs`, `memory.rs`,
`review.rs`, `vectors.rs`) and in the modules.

### What it refuses, and how

Every failure is `{"error", "why"}` and the code is one of the contract's `ErrorCode`: `bad_request`
(an argument is missing or unusable), `parse` (bytes that will not read), `unsupported` (an
algorithm or a function this library does not have), `envelope_invalid`, `vault`, `root_expired`
(a wallet asked to sign under a root past its `notAfter`), `key` and `internal` (declared so a
caller's switch has a name for them; `internal` is what a caught panic becomes). Each function
declares the codes it can fail with; `js/parity.mjs` fails a port that answers with another.
`decide` and `decide_chain` also answer, as successes, with `code` `envelope_invalid`,
`chain_required`, `certificate_renewed` or `pending_approval`.

### Invariants

- A member a function does not declare is refused by name before any member is read
  (`CONTRACT.md` section 0); `tests/boundary.rs` asks every function with nothing, with `{}`, with a
  list and with the hostile object of `js/cases/hostile.json`.
- Off wasm32, `call` turns a panic into `{"error":"internal"}` (`catch_unwind` in `src/api.rs`).
  That code is compiled out on wasm32, where the release profile is `panic = "abort"`
  (`Cargo.toml`); the Wasm's protection is that `tests/boundary.rs` finds no input that reaches
  `internal`, not a catch.
- The vault's key and plaintext are held in `Zeroizing` buffers in `src/vault.rs`, and a private
  key read from an argument in `src/api.rs`.
- DER is read strictly (`src/der.rs`); the protocol's windows and the export's bounds exist as
  constants in the core and as one copy in the contract, and `tests/constants.rs` and
  `tests/limits.rs` hold them to it.
- The Wasm that ships is the pinned container build; a native build gives different bytes
  (`js/reproduce.sh`, `js/verify.mjs`).

### Held by

`gate.sh` steps "Rust core, CLI and Wasm crate: style, clippy, tests" (`cargo fmt --check`, clippy
with `-D warnings`, `cargo test --workspace`), "Every Rust dependency's licence" (`cargo deny`),
then through the Wasm: `js/check.mjs`, `js/intrude.mjs`, `js/parity.mjs`, `js/musts.mjs`. `PROOFS.md`
lists every MUST of the specification with what holds it.

### What it does not do

It does no I/O and holds no state: a host supplies the pins, the node state, the ledger and the
clock (`now` is an argument), and applies the effects `decide` returns. It never opens a zip
(`src/export/mod.rs`): a host reads the container, counts the bytes it actually decompresses and
hashes the media; the core decides what it was handed. It resolves no name: DNS is the host's.
Keys in Wasm memory are readable by any script in the same context, so a root is opened into the
core for one issuance and not kept (root `README.md`, "Keys in Wasm memory").

## hdtp-identity-wasm

The `wasm-bindgen` boundary (`crate-type = ["cdylib", "rlib"]`, `src/lib.rs`): bytes in, JSON out.

What it holds: `call(name, args) -> String`, which is `hdtp_identity::call`, and `version() -> String`,
which is `call("version", "{}")`. Its one test, `calls_through_the_boundary`, runs in headless
Chrome (`wasm-pack test --headless --chrome crates/hdtp-identity-wasm`) and is not part of the gate.
It declares no errors of its own; every answer is the core's. The loaders that consume the built
package are `js/index.mjs` (Node and browser) and `js/worker.mjs` (Cloudflare Workers); `js/build.sh`
builds it into `js/pkg-web` and `js/pkg-node`, and `js/reproduce.sh` builds the pinned bytes.

## hdtp-limits

SPEC section 12's per-caller call budgets, decided in one place (`crate-type = ["rlib"]`, no
dependencies). Everything is a pure function of its arguments: the counters live in a `StateStore`
the host implements, the clock is the `now` the host passes (milliseconds), and the numbers are a
`Rules` document the host keeps in its configuration. The crate carries no default rule set. The
core links it (`src/api/limits.rs`) and answers it as `limits_rules_check`, `limits_decide` and
`limits_buckets`; the Go port is `go/limits.go`.

### What it holds

| Item | What it is |
|---|---|
| `Rules`, `RULE_MEMBERS` | nine required numbers: `contact_calls_per_second`, `contact_burst`, `identity_capacity_per_second`, `guest_calls_per_hour`, `guest_source_calls_per_hour`, `stranger_calls_out_per_hour`, `integration_calls_per_hour`, `guest_total_calls_per_hour`, `pending_in_cap` |
| `Rules::check` | whether a rule set can be enforced as written |
| `Charge` | what a call is charged to: `ContactIn`, `GuestIn`, `GuestTotal`, `ContactOut`, `StrangerOut`, `Integration`, `PendingIn` |
| `Charge::buckets` | the buckets a charge reads, in order, with their keys, rates and bursts |
| `decide` | charges one call to every bucket of a charge or to none, and answers `Decision::Allow` or `Decision::Refuse { retry_after, which }` |
| `StateStore`, `Level`, `MemoryStore` | where the counters live; the in-memory store is the contract function's state and the tests' |
| `IDLE_MS` | 3,600,000: a row untouched this long is full whatever it budgets, so a host may delete it |

### What it refuses, and how

`Rules::check` refuses, with a one-line reason, a number that is not finite, `contact_calls_per_second`
at or below 0, any other member below 1, a `pending_in_cap` that is not whole, and a contact bucket
that takes longer than `IDLE_MS` to refill from empty. `decide` refuses a call by returning
`Refuse` with the key of the bucket that needs longest (`retry_after` is whole seconds, at least 1;
`None` for the pending-request cap, which no wait refills). Through the core, malformed arguments
are `bad_request`.

### Invariants

- A refusal spends nothing: a call is charged to all its buckets or none (`decide`).
- `tests/vectors.rs` replays every step of `js/cases/limits-vectors.json`, a fixed record of the
  cloud's earlier limiter, bit for bit; `src/tests.rs` holds the decision's properties over
  generated sequences. The Wasm and the Go port are held to the same file by `js/limits.test.mjs`
  and `go/limits_test.go`.

### Held by

`cargo test --workspace` in `gate.sh`; `js/limits.test.mjs` in the `js-tests` suite; `js/parity.mjs`
through the cases of `js/cases/limits.mjs`.

### What it does not do

No I/O, no clock, no default rules, no storage: a compiled default would be a second source of
truth, and a host that wants one logs it when it uses it. Layer 1 (per address and per path) is the
host's edge, not this crate's.
