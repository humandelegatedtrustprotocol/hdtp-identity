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
# ever had; a gate nothing can run is a comment. This repository's pre-push hook
# (githooks/pre-push) runs it on every push, and `make release` runs it before a version is cut.
#
# It does NOT rebuild the Wasm. The build that ships is the pinned one (`js/reproduce.sh --pin`, a
# container named by digest); a native `js/build.sh` writes this machine's bytes over it and
# `js/verify.mjs` then refuses them, correctly. The container build is run again, and compared with
# what was published, by `make verify-release VERSION=x.y.z`.
set -eu
cd "$(dirname "$0")"

[ -f ../pact-protocol/SPEC.md ] && [ -f ../pact-protocol/vectors/lib/x509.mjs ] || {
  echo "gate: ../pact-protocol is not checked out beside this directory (SPEC.md and vectors/lib are read from it)" >&2
  exit 2
}

step() { printf '\n── %s\n' "$1"; }

# The gate does not BUILD the Wasm (see the header), and `js/pkg-*` is gitignored — so on a fresh
# clone, a new worktree or a second machine, `node js/verify.mjs` below used to die with an ENOENT
# traceback naming a file, and never naming the command that makes it.
[ -f js/pkg-web/pact_identity_wasm_bg.wasm ] && [ -f js/pkg-node/pact_identity_wasm_bg.wasm ] || {
  echo "gate: js/pkg-web and js/pkg-node are not built, and this gate does not build them." >&2
  echo "      Run 'sh js/reproduce.sh' for the pinned container build (what the pin is OF), or" >&2
  echo "      'sh js/build.sh' for a local one — after which js/verify.mjs will refuse the bytes," >&2
  echo "      correctly, because a local build is this machine's and the pin is the container's." >&2
  exit 2
}

step "Rust core, CLI and Wasm crate: style, clippy, tests"
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked

step "Every Rust dependency's licence is one deny.toml allows"
command -v cargo-deny >/dev/null 2>&1 || {
  echo "gate: cargo-deny is not installed, and this step needs it: cargo install cargo-deny --locked" >&2
  exit 2
}
cargo deny --locked check licenses

step "One version everywhere it is written"
node scripts/version.mjs --check

step "Go port: vet, tests, adapter"
( cd go && go vet ./... && go test ./... && make build )

step "The pin is of THIS commit, and the Wasm build in this tree is the pinned one"
node js/verify.mjs

# Every JS suite below writes one result file (js/results.mjs: id, verdict, reason, ms per case) into
# target/gate-results, wiped here so nothing in it predates this run; the last step prints a line per
# suite and fails if a suite wrote none. The seed's intrusion run is kept there too (js/seed.mjs), so
# the four suites that read it run it once.
PACT_RESULTS="$(pwd)/target/gate-results"
PACT_RUN="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
export PACT_RESULTS PACT_RUN
rm -rf "$PACT_RESULTS"
mkdir -p "$PACT_RESULTS"
node_tests() { # <suite> <files…>: node --test, with the spec reporter here and a result file there
  suite="$1"; shift
  PACT_SUITE="$suite" node --test --test-timeout=60000 \
    --test-reporter=spec --test-reporter-destination=stdout \
    --test-reporter=./js/test-reporter.mjs --test-reporter-destination="$PACT_RESULTS/$suite.json" "$@"
}

step "Appendix B through the bindings, and through the Go port"
node js/check.mjs
node js/check.mjs --port go

step "The intrusion scenarios, both ports, against the seed's verdicts"
node js/intrude.mjs
node js/intrude.mjs --port go

step "The contract's own validator, and CONTRACT.md rendered from the contract file"
node_tests contract-tests contract/schema.test.mjs
node contract/render.mjs --check

step "The two ports answer a caller alike, and both answer as contract/contract.json says"
node js/parity.mjs --manifest "$PACT_RESULTS/parity-manifest.json"

step "The harness's own tests: the live battery against the seed's node, the Go adapter, the readers"
node_tests js-tests js/*.test.mjs

step "No tracked file carries a name PACT 1.x had, and the list of names is the protocol's"
node js/check-no-1x.mjs --selftest
node js/check-no-1x.mjs

step "Every MUST in the specification names something that holds it, and the record is current"
node js/musts.mjs
node js/record.mjs --check --manifest "$PACT_RESULTS/parity-manifest.json"

step "The seed itself still proves the spec"
( cd ../pact-protocol && node vectors/check.mjs )
node js/seed.mjs

step "One line per suite, from its result file"
node js/results.mjs --summary check-wasm check-go intrude-wasm intrude-go contract-tests parity js-tests musts

printf '\ngate: ok\n'
