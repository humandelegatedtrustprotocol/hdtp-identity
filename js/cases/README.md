# cases

The cross-port parity cases that `js/parity.mjs` runs: the same arguments sent to the Rust core (as
the Wasm) and to the Go port, with the answers compared whole and each validated against
`contract/contract.json`. It is a directory of `js/`, not a module of its own (no `package.json`);
`index.mjs` collects the files and `js/cases.test.mjs` holds the collection.

## What it holds

- One file per section of the contract, named for it: `build.mjs`, `keys.mjs`, `certificates.mjs`,
  `csr.mjs`, `signing.mjs`, `cards.mjs`, `envelopes.mjs`, `vault.mjs`, `ledger.mjs`, `export.mjs`,
  `limits.mjs`; plus `dispatcher.mjs` (a name nobody defines, and arguments that are not an object),
  which is not a contract section. `export.mjs` calls `export-instants.mjs` and `export-reader.mjs`.
- `generated.mjs`: the cases nobody writes by hand, made from the contract for every function it
  declares (`{}`, the hostile object, each required member absent and `null`, each optional member
  of the wrong type, a member the contract does not declare).
- `fixtures.mjs`: what the cases are handed (certificates, keys, cards, envelopes), built from
  `js/cast.mjs` by the seed library, not by the port under test.
- Data: `hostile.json` (the object `go/unit_test.go`'s `TestCallNeverPanics` and the core's
  `tests/boundary.rs` also send), `limits-vectors.json` (a fixed record of the earlier cloud limiter,
  replayed by `crates/hdtp-limits/tests/vectors.rs`, `js/limits.test.mjs` and `go/limits_test.go`).

A case is `add(id, fn, args, how)`; its id is unique across all files and its `fn` must belong to its
file's section, so the files are the contract's sections. `expect(id, want)` holds a case to what the
specification says.

## What it refuses, and how

`collect` returns a list of problems rather than a quiet no-op: an `expect` naming an id no case has,
a duplicate id, a case calling a function outside its file's section. `parity.mjs` then fails, as it
also fails when a function on either dispatcher has no case, so the contract cannot grow past its
guard. The refusals the cases provoke are the contract's error codes.

## Held by

`js/cases.test.mjs`, and `js/parity.mjs` in the gate step "The two ports answer a caller alike, and
both answer as contract/contract.json says".

## What it does not do

It excuses no failure: there is no list of known disagreements. It does not build its fixtures with
the port under test, except the four kinds named in `fixtures.mjs`.
