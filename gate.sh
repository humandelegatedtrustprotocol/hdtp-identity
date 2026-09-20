#!/bin/sh
# The cross-language gate of pact-identity, as one command: the Rust core, the Go port and the
# pinned Wasm build must all answer Appendix B's vectors and the seed's intrusion scenarios exactly
# as the seed does. This is the list; README.md points here, and so does the pre-push hook.
#
#   sh gate.sh
#
# IT RUNS HERE AND NOT IN CI, by the owner's decision (2026-09-20): the list reads the private
# sibling `pact-protocol` — SPEC.md, the seed in `vectors/lib` — and no CI credential for it will
# be created. For five days a CI job held this list and failed at its first step on every run it
# ever had; a gate nothing can run is a comment. The umbrella's pre-push hook runs this whenever a
# push touches `pact-identity/` or moves the `pact-protocol` pointer.
#
# It does NOT rebuild the Wasm. The build that ships is the pinned one (`js/reproduce.sh --pin`, a
# container named by digest); a native `js/build.sh` writes this machine's bytes over it and
# `js/verify.mjs` then refuses them, correctly. The pin's reproducibility is proven off this
# machine, by the `reproduce` job of .github/workflows/pact-identity.yml, which needs no secret.
set -eu
cd "$(dirname "$0")"

[ -f ../pact-protocol/SPEC.md ] && [ -f ../pact-protocol/vectors/lib/x509.mjs ] || {
  echo "gate: ../pact-protocol is not checked out beside this directory (SPEC.md and vectors/lib are read from it)" >&2
  exit 2
}

step() { printf '\n── %s\n' "$1"; }

step "Rust core, CLI and Wasm crate: style, clippy, tests"
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked

step "Go port: vet, tests, adapter"
( cd go && go vet ./... && go test ./... && make build )

step "The pin is of THIS commit, and the Wasm build in this tree is the pinned one"
node js/verify.mjs

step "Appendix B through the bindings, and through the Go port"
node js/check.mjs
node js/check.mjs --port go

step "The intrusion scenarios, both ports, against the seed's verdicts"
node js/intrude.mjs
node js/intrude.mjs --port go

step "The two ports answer a caller alike"
node js/parity.mjs
node --test --test-timeout=60000 js/live.test.mjs

step "Every MUST in the specification names something that holds it, and the record is current"
node js/musts.mjs
node js/record.mjs --check

step "The seed itself still proves the spec"
( cd ../pact-protocol && node vectors/check.mjs && node vectors/intrude.mjs )

printf '\ngate: ok\n'
