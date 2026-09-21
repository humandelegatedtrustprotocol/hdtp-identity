# The contract in one place

A proposal, written 2026-09-20; its numbers were measured again on 2026-09-21, against PACT 2.1.2.

**Status, 2026-09-21: Phases 1 and 2 are built.** `contract/contract.json` is the file, 39 methods
over 34 domain types; `CONTRACT.md` is rendered from it and `contract/render.mjs --check` fails when
it is stale; `js/parity.mjs` takes its surface from the contract as well as from both dispatchers,
and validates every answer of both ports against the `result` schema, with a failure held to the
codes its method declares. Two deviations from what is proposed below, each deliberate:

- **The validator is not a stock one.** `js/` has no dependencies and nothing to install them with,
  and one package to check forty schemas is not the reason to start. `contract/schema.mjs` is a
  validator for exactly the keywords the contract uses; what makes that safe rather than merely
  smaller is that `compile` REFUSES a keyword it does not implement, so a schema cannot state a
  constraint nothing holds, and `contract/schema.test.mjs` holds each keyword to a value that must
  fail it.
- **The params direction is one-way.** An accepted call is validated against its `params` schema;
  nothing asserts that every call the schema admits is accepted, because the cases that would show
  it are refusals by design.

It found two places where both ports accept a value the contract does not describe:
`profile_error`'s `kind` (anything but `"root"` is read as a leaf) and `card_encode`'s `seal` (a
non-empty value is written into the card as given). Both are the Rust core, so narrowing them costs
a re-pin, and they are recorded as Phase 4's first candidates rather than widened silently.

Phases 3, 4 and 5 are not built.

The ask: bring the contract into one place, the way OpenAPI or protocol buffers do, so native code
can be built on top of it.

## There are two contracts, and they have different audiences

| | **A — the wire protocol** | **B — the library boundary** |
|---|---|---|
| Who needs it | somebody writing a native PACT implementation in a language we do not ship | us, plus anybody embedding `pact-identity` |
| What it fixes | the certificate profile (§14.1), the six chain rules (§14.2), the envelope and its header (§13), the card (§3), the error codes (§12) | 39 functions, each `(name, argsJSON) → resultJSON` |
| Where it lives now | `pact-protocol/SPEC.md` (2.1.2, 47 MUSTs) + Appendix B vectors + `PROOFS.md` | `pact-identity/CONTRACT.md` tables + two dispatchers + `js/parity.mjs`'s hand-written cases |
| Machine-readable today | the Appendix B vectors, and nothing else — every SHAPE is prose | nothing |

"So native code can be built on top of it" is contract **A**'s audience. But A's hard part is already
proven: Appendix B's vectors are machine-readable and both ports reproduce them (114/114), 124
intrusion scenarios agree across ports, and `PROOFS.md` maps all 47 MUSTs to a holder. What A lacks
is a way to read the SHAPES without reading prose.

Contract **B** is the one that is genuinely unguarded, and it is where the drift has actually
happened (below).

**Recommendation: build one type registry and take two views of it.** The 39 functions' params and
results are assembled from roughly a dozen domain types — `Alg`, `Spki`, `Pkcs8`, `Fingerprint`,
`CertDer`, `Chain`, `Envelope`, `Header`, `Card`, `Vault`, `Pin`, `Decision` — and those domain types
ARE the wire contract's types. Define them once. View one is the boundary (B); view two is a schema
bundle published beside SPEC.md for external implementers (A). Neither view is hand-maintained.

(39 is the names both dispatchers answer to. `js/parity.mjs` guards 38 of them: `version` describes
the build rather than a rule, so its answer cannot agree between ports.)

## Format: JSON Schema 2020-12, not protobuf, not OpenAPI verbatim

**Protocol buffers are the wrong tool here.** The boundary is synchronous and in-process
(`call(name, args) -> String`), and the wire format is specified and pinned: JSON with base64url and
DER, proven byte for byte by Appendix B. Protobuf would either change that wire format, which the
vectors forbid, or add a second encoding nobody speaks. Its one real virtue — generated types in many
languages — JSON Schema also has.

**OpenAPI is close but not native.** It is built around HTTP paths, verbs and status codes, and this
boundary has none. Modelling 39 methods as 39 `POST` paths does work and buys the whole tooling
ecosystem, and `pact-cloud` already generates an OpenAPI 3.1 document from its route table
(`gateway/src/api/v1/openapi.ts`), so the pattern is familiar in this workspace.

**Take the schema dialect without the HTTP framing.** OpenAPI 3.1's dialect *is* JSON Schema
2020-12, which is also what the cloud emits (`z.toJSONSchema`). So the source of truth is one
JSON Schema document; a short script emits a real OpenAPI document from it for anyone who wants
stock codegen. We get the tooling without pretending the boundary is a web API.

**The source of truth is a plain data file**, `pact-identity/contract/contract.json`, hand-written,
with no compiler in front of it. Neither port may own it — the port that owns the schema stops being
a port — and a data file is language-neutral (protobuf's actual virtue), readable in a diff, and
consumable by Rust, Go, JS and a third party with a stock validator. If hand-writing the JSON proves
unpleasant, the fallback is the cloud's arrangement: a small zod source compiled to that JSON, with
the JSON staying the committed artifact everyone reads.

## What each phase costs — the constraint that sets the phases

The Wasm core is pinned, and `js/inputs.mjs` names exactly what a pin is built from:

| Change | A build input? | Cost |
|---|---|---|
| `contract/**`, the generators, `CONTRACT.md`, docs | no | free |
| `go/**` — generated arg structs, validation | no | free |
| `js/**` except `build.sh` and `builder.json` — the parity harness, a `.d.ts` | no | free |
| `crates/pact/**` — the CLI | no | free |
| **`crates/pact-identity/**`, `crates/pact-identity-wasm/**`** | **yes** | re-pin in the container → re-vendor into `pact-cloud` → re-pin the ceremony page → cloud gate → staging deploy |

So everything except changing the Rust library is cheap, and the phases follow that line rather than
tidiness.

**One trap to write down now.** If the Rust library ever `include_str!`s the contract file — the
obvious way to validate at the boundary — that file becomes a build input that `js/inputs.mjs` does
not list, and the pin acquires a hole: the source could change while `verify.mjs` still says the pin
is of this commit. Whoever does Phase 4 adds it to `INPUTS` in the same commit. (Today there is no
`build.rs` and no `include_str!` in either library crate; every `include_str!` is in the CLI's
`main.rs`, which is not an input, and each includes one of the CLI's own files.)

## Phases

**Phase 1 — the file exists, and the NAMES are pinned to it. Free.**
`contract/contract.json` lists the 39 methods with `params`, `result` and error codes, referencing
shared `$defs` for the domain types. `CONTRACT.md` becomes generated from it (`contract/render.mjs`),
so its tables cannot drift — the same move as the cloud's `openapi.ts`, whose header says "Generated,
not written… The three cannot disagree." The parity harness's coverage gate takes the surface from
the contract file instead of regexing two dispatchers, while still cross-checking both dispatchers, so
a name in a dispatcher but not in the contract fails, and the reverse fails too.

**Honest limit: Phase 1 pins names only. The shapes are still prose that nothing checks.** Saying
otherwise would be the defect class the umbrella's `CLAUDE.md` names — a claim true of what its test
looked at and false of what it was cited for. Names are checkable statically; shapes are not, because
the parity harness learns shapes by running cases, and its gate only asserts that each name has one
whole-compared case that succeeded.

**Phase 2 — the shapes become checkable. Still free, and this is the phase that matters.**
The parity harness validates every observed answer against the contract's `result` schema with a
stock JSON Schema validator. A drifted schema then fails against real data from BOTH ports, and
"compared whole" gains its second meaning: compared against the declared shape. Optionally, generate
the Go port's arg structs from the contract, which makes one port's decoding provably the contract's
and costs nothing because Go is not a build input.

**Phase 3 — consumers get types. Free.**
`contract/emit-ts.mjs` → `js/contract.d.ts`, so `call('validate_chain', {…})` is typed for the wallet
page and the Worker; today wasm-bindgen types only `call(name: string, args: string): string`, which
says nothing about any method. `contract/emit-openapi.mjs` → an OpenAPI 3.1 document for stock codegen
in other languages.

**Phase 4 — the Rust library validates against the contract. Costs a re-pin.**
Worth doing only if Phase 2 finds real drift, or to put the "the boundary never throws" guarantee on
a schema instead of on tests. Bundle it with the next change that re-pins for a reason of its own: a
re-pin is a container build, a vendor, a ceremony re-pin, the cloud's gate and a deploy (the umbrella's
`CLAUDE.md` has the list), and that is worth sharing.

**Phase 5 — the wire contract's schema bundle, for external implementers. Free.**
From the same `$defs`: the certificate, the chain, the envelope and header, the card, the error codes.
Publish it beside SPEC.md with the Appendix B vectors, so somebody writing a native implementation
gets types, vectors and the 47-MUST map without reading prose to learn a shape. This is what the
original ask — "so native code can be built on top of it" — actually needs.

## Why this is worth doing: the drift is not hypothetical

- `version` was dispatched by one port and not the other until the coverage gate was written.
  (`js/parity.mjs` records it.)
- `card_decode` dropped its entire `leaf` member in one port, and no key list noticed, "because a key
  list only ever looks at the keys someone thought to name". (Also `parity.mjs`.)
- `decide` answered with `tool: null` in Rust and with no `tool` member at all in Go — a SHAPE
  divergence, found on 2026-09-20 only once the parity gate stopped counting a refusal as a success.
  Until that day `validate_chain`, the six chain rules, had never had a successful answer compared
  between the ports: fourteen cases, all refusals. (The round-2 plan's G3.) A `result` schema is
  exactly the check that does not depend on somebody having thought to write the succeeding case.
- The same review found the vault's Argon2id parameters unbounded on the path that reads a document
  an attacker wrote. `CONTRACT.md` gave them no range then (it does now), so neither port was wrong
  by it. A schema has `minimum` and `maximum`, and a missing one is visible in a way a missing
  sentence is not.
- Answering "do both ports expose the same 39 functions?" means regexing two dispatchers whose syntax
  differs. Doing it while writing this proposal produced a wrong answer twice — 37 against 39 —
  because Go declares two of the names through a shared function rather than an inline closure, and
  a `sed` character class silently ate letters. With a contract file it is a lookup, not an exercise.

## What I would not do

- Not protobuf, for the reasons above.
- Not a code generator that writes `api.rs`. It is hand-tuned, heavily commented, and every edit
  re-pins the Wasm and ripples into a cloud deploy. Generated types there, if ever, not generated
  dispatch.
- Not one IDL serving both contracts as a single published artifact. Same types, two views; an
  external implementer should not have to read our in-process function list to learn the wire format.
