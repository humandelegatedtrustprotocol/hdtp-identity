#!/bin/sh
# The cross-language gate of hdtp-identity, as one command: the Rust core, the Go port and the
# pinned Wasm build must all answer Appendix B's vectors and the seed's intrusion scenarios exactly
# as the seed does. This is the list; README.md points here, and so does the pre-push hook.
#
#   sh gate.sh
#
# IT RUNS HERE AND NOT IN CI, by the owner's decision (2026-09-20): the list reads the private
# sibling `hdtp-spec` — the specification's text, the seed in `vectors/lib` — and no CI credential for it will
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

[ -f ../hdtp-spec/site/spec-source.mjs ] && [ -d ../hdtp-spec/docs/specification ] && [ -f ../hdtp-spec/vectors/lib/x509.mjs ] || {
  echo "gate: ../hdtp-spec is not checked out beside this directory (docs/specification and vectors/lib are read from it)" >&2
  exit 2
}

step() { printf '\n── %s\n' "$1"; }

# The gate does not BUILD the Wasm (see the header), and `js/pkg-*` is gitignored — so on a fresh
# clone, a new worktree or a second machine, `node js/verify.mjs` below used to die with an ENOENT
# traceback naming a file, and never naming the command that makes it.
[ -f js/pkg-web/hdtp_identity_wasm_bg.wasm ] && [ -f js/pkg-node/hdtp_identity_wasm_bg.wasm ] || {
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

step "Every Rust dependency's licence is one deny.toml allows, and its source is crates.io"
# One version of cargo-deny, so a check's meaning does not move with whatever a machine installed.
DENY_VERSION=0.20.2
case "$(cargo deny --version 2>/dev/null)" in
  "cargo-deny $DENY_VERSION") ;;
  *)
    echo "gate: this step runs cargo-deny $DENY_VERSION: cargo install cargo-deny --version $DENY_VERSION --locked" >&2
    exit 2
    ;;
esac
cargo deny --locked check licenses sources

step "One version everywhere it is written"
node scripts/version.mjs --check

step "Go port: vet, tests, adapter"
( cd go && go vet ./... && go test ./... && make build )

step "The corpus the CLI writes for a fresh owner reads in the Go port as its cases.json says"
# `hdtp vectors corpus` re-issues go/exportcorpus for another owner root. This is the one port that
# did not write it. A random root each run, so the check is of the verb and not of one output.
REISSUED="$(mktemp -d)"
trap 'rm -rf "$REISSUED"' EXIT
OWNER="sha256:$(node -e "process.stdout.write(require('node:crypto').randomBytes(32).toString('base64url'))")"
cargo run -q --locked -p hdtp -- vectors corpus --owner "$OWNER" --out "$REISSUED/corpus"
( cd go && HDTP_REISSUED_CORPUS="$REISSUED/corpus" go test -count=1 -v -run '^TestReadExportZipAnswersTheCorpusWrittenForAnotherOwner$' . ) >"$REISSUED/go.txt" 2>&1 || {
  cat "$REISSUED/go.txt"
  exit 1
}
# Skipped is not passed: the test runs here or nowhere.
grep -q -- '--- PASS: TestReadExportZipAnswersTheCorpusWrittenForAnotherOwner' "$REISSUED/go.txt" || {
  cat "$REISSUED/go.txt"
  echo "gate: the Go port did not read the corpus written for $OWNER" >&2
  exit 1
}
echo "the corpus written for $OWNER: every case in the Go port as cases.json says"

step "The pin is of THIS commit, and the Wasm build in this tree is the pinned one"
node js/verify.mjs

# Every JS suite below writes one result file (js/results.mjs: id, verdict, reason, ms per case) into
# target/gate-results, wiped here so nothing in it predates this run; the last step prints a line per
# suite and fails if a suite wrote none. The seed's intrusion run is kept there too (js/seed.mjs), so
# the four suites that read it run it once.
HDTP_RESULTS="$(pwd)/target/gate-results"
HDTP_RUN="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
export HDTP_RESULTS HDTP_RUN
rm -rf "$HDTP_RESULTS"
mkdir -p "$HDTP_RESULTS"
node_tests() { # <suite> <files…>: node --test, with the spec reporter here and a result file there
  suite="$1"; shift
  HDTP_SUITE="$suite" node --test --test-timeout=60000 \
    --test-reporter=spec --test-reporter-destination=stdout \
    --test-reporter=./js/test-reporter.mjs --test-reporter-destination="$HDTP_RESULTS/$suite.json" "$@"
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
node js/parity.mjs --manifest "$HDTP_RESULTS/parity-manifest.json"

step "The harness's own tests: the live battery against the seed's node, the Go adapter, the readers"
node_tests js-tests js/*.test.mjs

step "No tracked path or text carries a name hdtp-names.txt forbids, and the list and guard are hdtp-spec's"
node js/check-names.mjs --selftest
node js/check-names.mjs

step "The name takes \"an\": no tracked text writes \"a\" before it"
# A rename leaves the old article behind ("a" before a name that now begins with a vowel sound), in
# prose, in comments and in the refusal strings a caller reads. Bare, or behind a mark or the X- prefix.
if git grep -n -I -E '(^|[^[:alnum:]_])[Aa] [`*_"(]*(X-)?(HDTP|hdtp)' -- . >&2; then
  echo "gate: the lines above write \"a\" before the name; it takes \"an\"" >&2
  exit 1
fi

step "No identifier and no file name carries a generation suffix"
# HDTP has one generation. A test or a function named for another one's number says otherwise while
# it opens envelopes of this one, and the name guard cannot see it. Refused, in any tracked text and
# any path: a V and a number inside a camel-case name, and a v and a number joined to a snake-case
# name by an underscore on either side. A VALUE a test feeds in is not a name and is not matched: a
# scenario id or a label spelled with a hyphen, a quoted string. Two standard names are let through
# by name, because they are not generations: IPv4 and IPv6 in the address guard's two functions, and
# the curve's own name in its OID constant.
GENERATION='([a-z0-9]V[0-9]+([A-Z_]|[^A-Za-z0-9]|$)|_v[0-9]+(_|[^A-Za-z0-9]|$)|(^|[^A-Za-z0-9_-])v[0-9]+_)'
NOT_A_GENERATION='v[46]_private|PRIME256V1'
if { git grep -n -I -E "$GENERATION" -- . ; git ls-files | grep -E "$GENERATION"; } | sed -E "s/($NOT_A_GENERATION)//g" | grep -E "$GENERATION" >&2; then
  echo "gate: the lines above carry a generation's number in a name" >&2
  exit 1
fi

step "Every MUST in the specification names something that holds it, and the record is current"
node js/musts.mjs
node js/record.mjs --check --manifest "$HDTP_RESULTS/parity-manifest.json"

step "The seed itself still proves the spec"
( cd ../hdtp-spec && node vectors/check.mjs )
node js/seed.mjs

step "One line per suite, from its result file"
node js/results.mjs --summary check-wasm check-go intrude-wasm intrude-go contract-tests parity js-tests musts

printf '\ngate: ok\n'
