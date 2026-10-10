# Contributing

This repository holds the HDTP identity core: the Rust crates under `crates/` (the core, its
wasm-bindgen boundary, the call budgets and the `hdtp` command line), the Go port under `go/`, the
contract both present (`contract/`, rendered as `CONTRACT.md`), the pinned WebAssembly build
(`js/manifest.json`, `js/reproduce.sh`) and the JavaScript harness that proves both ports against
hdtp-spec's vectors and intrusion scenarios (`js/`). Changes come as pull requests and are reviewed
by the maintainers (`MAINTAINERS.md`). How decisions are made is `GOVERNANCE.md`.

## Where to start

- **A defect** — a port that answers differently from the other, from `CONTRACT.md` or from the
  specification; a vector or a scenario that fails; a build that does not reproduce its pin: open
  an issue ("Defect"), naming the port, the version and the function.
- **A question or an idea:** open an issue ("Question or idea").
- **A change to what an implementation must do** is the protocol's, not this library's: it starts
  as an enhancement proposal in hdtp-spec (`seps/README.md` there), and code here follows the text.
- **A change to the contract** — a function, an argument, a member of an answer, an error code:
  `contract/contract.json` first, then both ports, in one pull request.
- **A security weakness:** never an issue. `SECURITY.md` says how to report it privately.

## Ground rules

- One operation, one implementation. A function exists in the Rust core and in the Go port with
  one input schema, one answer shape and one refusal vocabulary; `js/parity.mjs` holds the two
  ports to each other and to `contract/contract.json` on every gate run, and a function added to
  one port is added to the other in the same change.
- `CONTRACT.md` and `PROOFS.md` are generated (`node contract/render.mjs`, `node js/record.mjs`),
  and the gate fails when either differs from what its generator writes. The sources are
  `contract/contract.json`, `contract/CONTRACT.template.md` and `js/musts.json`.
- Every MUST sentence of the specification is hashed in `js/musts.json`, each entry naming the test
  or scenario that holds it. A sentence that changed, a MUST no entry covers, or an entry that
  names a test or scenario that does not exist fails `node js/musts.mjs`; say in the pull request
  which entries you touched.
- Style is applied before the commit, never after. The pre-commit hook runs rustfmt over the staged
  Rust and re-stages it, then clippy with warnings as errors; a lint is fixed, not suppressed.
- The Wasm that ships is built from a commit, not a working tree. A change to a build input —
  `crates/hdtp-identity`, `crates/hdtp-identity-wasm`, `crates/hdtp-limits`, `Cargo.toml`,
  `Cargo.lock`, `rust-toolchain.toml`, `.cargo/config.toml`, `js/build.sh`, `js/builder.json`; the
  list is `js/inputs.mjs` — is committed first, then pinned (`sh js/reproduce.sh --pin`, the
  container build of that commit), then `js/manifest.json` is committed. The post-commit hook says
  when a commit has left the pin behind, and the gate refuses a stale pin.
- No dead code, and no code for a behaviour HDTP does not have.
- A sentence about behaviour is written after measuring it: a count, a size or a version quoted in
  prose is read from the code or the file it describes, never from memory.

## Getting set up

The toolchain the gate runs:

- Rust 1.92.0 with the `wasm32-unknown-unknown` target (`rust-toolchain.toml`; rustup installs
  both), and cargo-deny 0.20.2 (`cargo install cargo-deny --version 0.20.2 --locked`; the gate
  refuses any other version);
- Go 1.25 or later (`go/go.mod`);
- Node 22 or later (`js/package.json`); the harness has no npm dependencies;
- Docker and curl, for the canonical Wasm build (`js/reproduce.sh`); wasm-pack 0.15.0 for a native
  one (`sh js/build.sh`);
- for the `hdtp` CLI's default `piv` feature, PC/SC: on Linux `apt install libpcsclite-dev` to
  build and `libpcsclite1` to run, or `cargo build -p hdtp --no-default-features` without the
  smartcard door.

Beside this checkout, the specification: `../hdtp-spec` at its `main`. The tests read it.

| Port | What reads the sibling | Without it |
|---|---|---|
| Rust (`cargo test`) | `crates/hdtp-identity/tests/vectors.rs`: `../hdtp-spec/vectors/hdtp-1.0-vectors.json` and the newest released version under `../hdtp-spec/docs/specification/`, or the paths `HDTP_VECTORS` and `HDTP_SPEC` name; `crates/hdtp/tests/cli.rs`: the same two paths | the core's vector tests fail; the CLI's skip |
| Go (`go test ./...`) | `go/vectors_test.go`: the same two paths relative to `go/`, or `HDTP_VECTORS` and `HDTP_SPEC` | the tests that read them skip |
| JavaScript (`js/check.mjs`, `js/intrude.mjs`, `js/parity.mjs`, `js/musts.mjs`, `js/*.test.mjs`, `js/cases/*.mjs`) | hdtp-spec's seed library (`vectors/lib/*.mjs`) and spec reader (`site/spec-source.mjs`), imported by relative path | they do not load |

The gate also needs the pinned Wasm packages in `js/pkg-web` and `js/pkg-node`, which are not
tracked. `sh js/reproduce.sh --pin` builds the checked-out commit in the container and installs
them, rewriting `js/manifest.json` from the bytes it made; `git diff js/manifest.json` is then empty
when your build reproduced the pin. A native `sh js/build.sh` makes packages too, but this
machine's, which `node js/verify.mjs` refuses, correctly. The Go adapter the harness drives is
`make build` in `go/` (`go/bin/hdtp-identity-go`); `gate.sh` builds it.

```
cargo test --workspace --locked           # the core, the budgets, the CLI; Appendix B rebuilt byte for byte
( cd go && go test ./... && make build )  # the Go port, and the adapter the harness drives
node js/check.mjs [--port go]             # Appendix B through a port
node js/intrude.mjs [--port go]           # hdtp-spec's intrusion scenarios against a port, verdict by verdict
node js/parity.mjs                        # both ports, the same arguments, the same answers
node js/musts.mjs                         # every MUST of the specification names what holds it
node contract/render.mjs                  # CONTRACT.md from contract/contract.json (after a contract change)
node js/record.mjs                        # PROOFS.md (after a change to js/musts.json or the parity cases)
sh gate.sh                                # everything, in the order the pre-push hook runs it
```

## Gates and where they run

Every gate runs locally. Nothing runs on GitHub: there is no CI and no CI credential, and there
will be none. This repository's hooks are its own, in `githooks/`, installed by
`git config core.hooksPath githooks`:

| Hook | Runs |
|---|---|
| `pre-commit` | rustfmt over each staged `.rs` file, re-staged; `cargo clippy --workspace --all-targets --locked -- -D warnings` |
| `commit-msg` | refuses a message that carries a path under `/Users` or `/home`: a message is published with its commit, and the gate holds the tracked files to the same rule but cannot see a message. Say "the worktree" or "the sibling checkout" instead |
| `post-commit` | `node js/verify.mjs --inputs`: says when the commit moved a build input and the pin is behind |
| `pre-push` | `sh gate.sh` |

`sh gate.sh`, in order: rustfmt, clippy and the tests of every crate; cargo-deny over licences and
sources; the one version in every place it is written; the Go port's vet, tests and adapter; the
export corpus the CLI writes read back by the Go port; the pin — HEAD's build inputs are the ones
the pin was built from, and the bytes in `js/pkg-*` are the pinned ones; Appendix B through the
Wasm and through the Go port; the intrusion scenarios through both; the contract's validator and
`CONTRACT.md`; hdtp-spec's committed JSON Schema against this contract; the parity of the two
ports; the harness's own tests; the article before the name, which takes "an"; no generation
suffix in a name; no path from the machine that wrote it in any tracked text; the MUST registry and `PROOFS.md`; the seed proving the specification; and one line per suite. It needs `../hdtp-spec` and the pinned packages above.

Outside contributors who cannot run the whole gate say in the pull request which steps they ran.

## Sending a change

- One logical change per commit. The message says what changed and why; if it fixes a defect, say
  how the defect was shown.
- A change carries its `CHANGELOG.md` line under `## Unreleased` in the same commit; a change to a
  build input carries its pin (`js/manifest.json`) in the commit after it.
- Inbound is outbound. A contribution is accepted only under the terms the repository gives out:
  the Apache License 2.0 (`LICENSE`, with `NOTICE`).
- Every commit carries a sign-off: a `Signed-off-by: Your Name <you@example.com>` line, which
  `git commit -s` adds. It certifies the Developer Certificate of Origin 1.1
  (<https://developercertificate.org/>): that you wrote the contribution or otherwise have the
  right to submit it under the terms above. A pull request with a commit that has no sign-off is
  not merged.
- Conduct is `CODE_OF_CONDUCT.md`, the Contributor Covenant 2.1.
