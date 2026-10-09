# js

The JavaScript side of hdtp-identity: the loaders that a Node, browser or Worker host uses to call
the Wasm core, the pin that says which Wasm bytes are the real ones, and the harness that holds the
Rust core (as the Wasm) and the Go port to the contract and to the specification's vectors. Nothing
here is published to npm (`package.json` is `private`, name `@hdtp/identity`, Node 22 or later,
no dependencies). BatonDeck vendors the Wasm from a release asset, not from this directory; the node
imports the Go module. The harness reads the sibling `hdtp-spec` by relative path (the specification's
text, its seed under `vectors/lib`); `CONTRIBUTING.md` and the root `README.md` describe the gate
and the pin from the outside.

`js/pkg-web/` and `js/pkg-node/` are the built packages (the `.wasm`, its wasm-bindgen glue and
types, `package.json`). They are git-ignored build output, present after `sh js/reproduce.sh` or
`sh js/build.sh`, and `gate.sh` stops with the command that makes them when they are absent. They
are not documented here because they hold no source of their own.

## What it holds

Loaders:

| File | Purpose |
|---|---|
| `index.mjs` | `load()` resolves to `{ call(name, args), version() }`, the Node package under Node and the web package elsewhere; every answer is a parsed object, `{ error, why }` on failure |
| `worker.mjs` | Cloudflare Workers: the web package initialised synchronously over a `CompiledWasm` module. Not verified under workerd from this repository |

The build and the pin:

| File | Purpose |
|---|---|
| `build.sh` | how the Wasm is built (`wasm-pack`, into `pkg-web` and `pkg-node`), wherever it is built; a direct run gives this machine's bytes, which `verify.mjs` refuses |
| `reproduce.sh` | the canonical build of HEAD in a container named by digest; no argument compares the bytes with `manifest.json`, `--pin` installs them as `pkg-web` and `pkg-node` and writes `manifest.json` |
| `builder.json` | the build image by digest, the platform and the wasm-pack release with its hash |
| `inputs.mjs` | the list of paths the Wasm is built from, and `inputsAtHead()`, their identity at HEAD (`--dirty` lists uncommitted ones) |
| `manifest.mjs` | writes `manifest.json`: crate version, toolchain, builder, the inputs' identity and the SHA-256 and size of every package file; run by `reproduce.sh --pin` and by nothing else |
| `verify.mjs` | first, is the pin OF this commit (HEAD's inputs against the manifest's); then the SHA-256 of every file in `pkg-web` and `pkg-node`; `<file> [entry]` checks one vendored file; `--inputs` asks the first question alone |

The proofs (each exits non-zero on a failure):

| File | Purpose |
|---|---|
| `check.mjs` | Appendix B through a port (`--port wasm`, the default, or `--port go`), reading the vectors from the specification itself |
| `intrude.mjs` | the seed's intrusion suite aimed at a port (`--port wasm`, `go`, or `live`): Mallory is built on the seed library, the defender is the port; each verdict is compared with the seed's own |
| `live.mjs` | the black-box half, aimed at a live endpoint (`--endpoint`, `--card`, `--insecure`); `live-scenarios.json` is its data, which the `hdtp` CLI also compiles in |
| `parity.mjs` | both ports, the same arguments, the same answers, every answer validated against `contract/contract.json`; `--only`, `--verbose`, `--manifest <file>` |
| `musts.mjs` | every MUST in the specification and what holds it, from `musts.json`; fails on MISSING, DRIFTED or DANGLING entries and prints ONE PORT and GAP entries |
| `record.mjs` | regenerates `../PROOFS.md` from `musts.json` and the parity manifest; `--check` fails if it is stale |
| `seed.mjs` | runs the seed's intrusion suite once per gate run and reads Appendix B's vector blocks |

Support and test tooling: `port.mjs` and `go-adapter.mjs` (a port is `{ kind, call }`: the Wasm
in-process, or the Go adapter kept open for the suite behind a worker thread), `cast.mjs` (the
people, keys, addresses and clock every suite shares, built by the seed library, never by the port
under test), `defender.mjs` (the seed's shapes backed by a port), `surface.mjs` (the dispatchers'
function names read out of the Rust and Go sources), `results.mjs` and `test-reporter.mjs` (one
result file per suite), `wasm-memory.mjs`, `zip.mjs`, and the data files `appendix-b-reader.json`,
`b64url-arguments.json`, `boundary-text.json`, `key-material.json`. `cases/` holds the parity cases.
`prf-check.mjs`, `prf-check.js` and `prf-check.html` build and serve a page that measures whether a
passkey's PRF output is the same on a second device; it stores and sends nothing.

The `*.test.mjs` files are `node --test` suites: `cases`, `doors`, `export-limits`,
`export-memory`, `limits`, `live`, `port`, `release`, `results`, `seed`, `surface`.

## What it refuses, and how

Every script prints what failed and exits 1: `verify.mjs` on a pin that is not of this commit, on a
builder that moved, or on a file whose SHA-256 differs from the manifest; `parity.mjs` on any
disagreement between the ports, on an answer off the contract, and when the contract's surface grows
without a case; `musts.mjs` on a MUST nothing names; `record.mjs --check` on a stale `PROOFS.md`;
`reproduce.sh --pin` while a build input is uncommitted (`inputs.mjs --dirty` exits 1 for dirty and
2 for "could not tell", which `reproduce.sh` treats as fatal). `intrude.mjs --port go` exits 2 with
"the Go port is not built" when `go/bin/hdtp-identity-go` is missing; `check.mjs --port go` also
reports it. The error codes the ports answer with are the contract's, listed in
[`../contract/README.md`](../contract/README.md).

## Invariants

- The Wasm that ships is the pinned container build; a native build gives different bytes
  (`reproduce.sh`, `verify.mjs`). The pin is of a COMMIT: `reproduce.sh` builds `git archive HEAD`.
  `manifest.json` records the SHA-256 of the inputs' `git ls-tree` listing (55 files at this
  commit), and `verify.mjs` compares it with HEAD's in a second.
- Style, then commit, then compile: after a change to a build input, commit, `sh js/reproduce.sh
  --pin`, commit the manifest.
- Fixtures are built by the seed library, never by the port under test (`cast.mjs`,
  `fixtures.mjs`), except four kinds the seed cannot build, each named where it is made.
- `parity.mjs` has no list of excused failures.
- The shipped package is two copies of one Wasm: `pkg-web` and `pkg-node` hold the same
  `hdtp_identity_wasm_bg.wasm`, 872,293 bytes in `manifest.json`.

## Held by

`gate.sh` runs, in order: `verify.mjs`; `check.mjs` and `check.mjs --port go`; `intrude.mjs` and
`intrude.mjs --port go`; `parity.mjs --manifest`; `node --test js/*.test.mjs` as the `js-tests`
suite; `musts.mjs`; `record.mjs --check`;
`seed.mjs`; and `results.mjs --summary`. The numbers of the current tree are in `../PROOFS.md`
(generated; `record.mjs --check` keeps them current): 101 normative sentences, 2895 cross-port
parity cases over 54 guarded functions, 55 contract functions, spec 1.0.0; `check.mjs` printed
148/148 checks passed and `intrude.mjs` 157 scenarios (151 blocked, 6 residual by decision,
0 reproduce) on the run that wrote this file. Those last two counts come from the sibling
`hdtp-spec` at the time and are not held anywhere in this repository.

## What it does not do

It does not build the Wasm in the gate; the container build runs at `reproduce.sh --pin` and in
`make verify-release`. It does not run on another machine on every push, and has no CI. `worker.mjs`
has not been executed under workerd from this repository. It aims no code at any endpoint except
under `live.mjs` / `intrude.mjs --port live`, which post to the endpoint named and leave the
attacker pending on it. `index.mjs` hands `args` to the core as given and does not repair it (`null`,
a list or a scalar is the core's to refuse); until 2026-09-29 a `null` was made `{}` here.
`prf-check` is a measurement for a person to read, not part of the gate.
