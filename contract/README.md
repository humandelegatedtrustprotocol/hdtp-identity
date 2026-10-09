# contract

The boundary every port of hdtp-identity presents, as data. `contract.json` declares each function
as `call(name, args) -> answer`: its arguments, its answer, and the error codes it can fail with.
The Rust core (natively, as the Wasm and in the CLI) and the Go port are both held to it, and so is
hdtp-spec's committed JSON Schema. Consumers: `js/parity.mjs` and the gate (which validate every
answer of both ports against it), `CONTRACT.md` at the repository root (rendered from it), the
`schema/gen.mjs` of the sibling `hdtp-spec` (which generates the published schema from it), and the
tests that hold constants to it (`crates/hdtp-identity/tests/constants.rs`,
`crates/hdtp-identity/tests/limits.rs`, `go/constants_test.go`, `go/export_limits_test.go`).

## What it holds

| File | What |
|---|---|
| `contract.json` | the source: JSON Schema 2020-12 (`$id` `urn:hdtp:identity:contract`, `spec` 1.0.0). Members: `sections` (11: build, keys, certificates, csr, signing, cards, envelopes, vault, ledger, export, limits), `failure` (the one failure shape), `$defs` (59 domain types) and `methods` (55 functions, each with `section`, `params`, `result`, `errors`, `notes`) |
| `CONTRACT.template.md` | the hand-written prose of `CONTRACT.md`: conventions (section 0), the order of the receiving rules (5.1), the vault format (6), the gates (7); it holds `{{table:<section>}}`, `{{types}}`, `{{spec}}`, `{{count}}` and `{{error_codes}}` placeholders |
| `render.mjs` | generates `../CONTRACT.md` from the two files above: one table per section, one row per function, the appendix of domain types; every section the contract declares must be rendered somewhere and no placeholder may be left |
| `contract.mjs` | `loadContract()` and `judge(contract, fn, args, answer)`: judges one answer by the contract |
| `schema.mjs` | the validator: exactly the JSON Schema keywords `contract.json` uses, no others; `compile` refuses any keyword it does not implement and any `$ref` that points nowhere |
| `schema.test.mjs` | holds every keyword to a value that must fail it and one that must pass, and holds `compile`'s refusals |

`CONTRACT.md` is generated: `node contract/render.mjs` writes it, `node contract/render.mjs --check`
fails if what is committed is not what the template and the contract render. Never edit it by hand;
edit the template or `contract.json` and render. `judge` recognises a failure by its shape (a string
`error` beside a `why`), not by `error` alone, because `profile_error` answers `{"error": null | "<words>"}`
as a result. Its rules: a non-failure answer validates against `result`, members it does not
describe included; a failure is `{error, why}` with a code the function declares; an accepted call's
arguments validate against `params`, one direction only, with `null` members dropped first because
the contract reads `null` as absent.

## What it refuses, and how

`$defs.ErrorCode` is the one list of failure codes: `bad_request`, `parse`, `unsupported`,
`envelope_invalid`, `vault`, `root_expired`, `key`, `internal`. `key` and `internal` are declared so
a caller's switch has a name for them; no known input reaches either. A failure is
`{"error": <code>, "why": <one line in the library's own words>}` and nothing else. The codes per
function, read from `methods.*.errors`:

| Can fail with | Functions |
|---|---|
| `bad_request` only | `version`, `prf_salt`, `is_normal_https`, `address_guard`, `ip_is_private`, `export_read_messages`, `export_read_end`, `export_write_messages`, `export_manifest`, `export_merge`, `limits_rules_check`, `limits_decide`, `limits_buckets` |
| `bad_request`, `unsupported` | `generate_key` |
| `bad_request`, `parse` | `derive_seed`, `assemble_root`, `assemble_leaf`, `validate_chain`, `csr_check`, `card_encode`, `card_decode`, `follow_renewed`, `ledger_check`, `signing_request_check`, `export_read`, `export_write`, `book_rows`, `media_holds_private_key` |
| `bad_request`, `parse`, `unsupported` | `key_from_seed`, `public_key`, `key_info`, `sign`, `verify`, `build_root`, `root_tbs`, `build_leaf`, `leaf_tbs`, `parse_certificate`, `profile_error`, `compare_leaves`, `csr_new`, `refresh_check`, `suite_for`, `decide`, `decide_chain` |
| `bad_request`, `parse`, `unsupported`, `root_expired` | `issue_from_csr`, `issue_tbs_from_csr`, `wallet_issue` |
| `bad_request`, `envelope_invalid`, `parse`, `unsupported` | `hpke_seal`, `hpke_open`, `seal_request`, `seal_result`, `open_result` |
| `bad_request`, `parse`, `vault` | `vault_seal` |
| `bad_request`, `vault` | `vault_open` |

Refusals that are answers, not failures: `decide` answers `envelope_invalid`, `chain_required`,
`certificate_renewed` or `pending_approval` as the `code` of a successful answer, and
`validate_chain` answers a refusal as `{ok: false, rule, reason}` with `rule` 1 to 5.

## Invariants

- One source: the tables of `CONTRACT.md` cannot say anything `contract.json` does not, because
  they are rendered from it (`render.mjs --check` in the gate).
- A validator that ignores a keyword is worse than none, so `schema.mjs` refuses what it does not
  implement (`schema.test.mjs`).
- The committed JSON Schema in the sibling hdtp-spec is what this file generates, checked by
  `gate.sh` ("hdtp-spec's committed JSON Schema is what THIS contract generates"). After a contract
  change the schema is regenerated in hdtp-spec first, from this tree's contract, and the gate is
  run again with hdtp-spec at that change.
- Constants the ports each write down (`Windows`, `Kdf`, `KdfDefault`, `VaultSaltMin`,
  `ExportLimits`, `LimitsIdle`) exist as one copy here and are held to it by a test in each port.

## Held by

Gate steps: "The contract's own validator, and CONTRACT.md rendered from the contract file"
(`node --test contract/schema.test.mjs` as suite `contract-tests`, then `node contract/render.mjs
--check`); "hdtp-spec's committed JSON Schema is what THIS contract generates"; "The two ports
answer a caller alike, and both answer as contract/contract.json says" (`js/parity.mjs`, which
also fails when a function on either dispatcher has no case, or a declared error code is never
produced by both ports in a case they answered alike). `PROOFS.md` (the generated record) states
the counts of the day: 55 functions, 2895 cross-port parity cases over 54 guarded functions.

## What it does not do

It says what a function takes and answers, not what the specification means by it: the normative
sentences are hdtp-spec's, and `PROOFS.md` lists which test or scenario holds each. It declares no
state, no transport and no clock; a host supplies those. Free-text `why` strings are held equal
between the two ports by parity, but the contract types them only as strings.
