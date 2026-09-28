# pact-identity

The PACT 2.0 identity core: the certificate profile and chain validation of SPEC §14, the sealed
envelopes of §13 in both forms, the §3 card codec, PKCS #10 requests and issuance per §9, the
receiving rules as one pure decision function, and the vault and derived roots of §2.1 and §9. One
Rust crate, compiled to WebAssembly for the browser, Cloudflare Workers and Node, and natively for
the `pact` CLI; an independent Go port under `go/` that the same vectors tie to it.

It is the part of PACT that every host shares: a self-hosted node (pact-gateway, through the Go
port) and a hosted platform (through the Wasm) call the same functions and get the same answers.
Nothing here knows about any one host.

## Using it

**The contract.** `CONTRACT.md` is the boundary every port presents: a function name and JSON
arguments in, JSON out, no state — `call(name, args)` in Wasm and JavaScript, `Call(name, args)` in
Go. It is rendered from `contract/contract.json`, which both ports are validated against on every
gate run (`js/parity.mjs`), so the document, the Rust core and the Go port describe one contract.

**Go.** The module is `github.com/pact-cloud/pact-identity/go` (package `pactidentity`). The
repository is private, so Go must fetch it over SSH and not through the public proxy:

```sh
export GOPRIVATE=github.com/pact-cloud/*
git config --global url.git@github.com:.insteadOf https://github.com/   # or per process: GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=url.git@github.com:.insteadOf GIT_CONFIG_VALUE_0=https://github.com/
go get github.com/pact-cloud/pact-identity/go@v0.3.3
```

```go
import pactidentity "github.com/pact-cloud/pact-identity/go"

out := pactidentity.Call("version", json.RawMessage(`{}`))
```

Go versions are the tags `go/vX.Y.Z` (the module lives in `go/`); each names the same commit as
`vX.Y.Z`.

**Wasm.** Take the release asset, not a build of your own: the bytes are pinned, and only the pinned
bytes are what every other host runs. Each GitHub release `vX.Y.Z` carries:

| Asset | What |
|---|---|
| `pact-identity-wasm-web-X.Y.Z.tgz` | `pkg-web/` exactly as pinned: the `.wasm`, its wasm-bindgen glue and types, `package.json`, `.gitignore` |
| `pact-identity-exportcorpus-X.Y.Z.tgz` | `exportcorpus/`: the export's fixture corpus (SPEC §9.2) — `cases.json` and every zip it names, each hostile file with the refusal it must produce and each valid one with what it holds — for a host that does not import the Go package `github.com/pact-cloud/pact-identity/go/exportcorpus` |
| `manifest.json` | `js/manifest.json` of the tagged commit (the sha256 and size of every package file, the builder image by digest, the source inputs), plus `version`, `commit`, `tags`, `protocol_commit` and the sha256 and size of every other asset |
| `SHA256SUMS` | every other asset, `<hex>  <name>` |
| `pact-X.Y.Z-darwin-arm64`, `-linux-arm64`, `-linux-amd64` | the `pact` CLI. The Linux builds link `libpcsclite` dynamically (the PIV feature): `apt install libpcsclite1` |

```sh
gh release download v0.3.3 -R pact-cloud/pact-identity -D vendor/
( cd vendor && shasum -a 256 -c SHA256SUMS ) && tar -xzf vendor/pact-identity-wasm-web-0.3.3.tgz -C vendor/
```

Check every unpacked file against `manifest.json`'s `files["pkg-web/<name>"]` before shipping it.
`js/worker.mjs` is the recipe for Cloudflare Workers (the web package over a `CompiledWasm`
module), `js/index.mjs` for Node and the browser.

**Versions.** One semver version for the crates, the Go module and the Wasm package, written in six
places and held equal by `node scripts/version.mjs --check` (a gate step); what each release changed
is in `CHANGELOG.md`. Before 1.0.0 a minor version may change the contract. `make release
VERSION=X.Y.Z` cuts a release locally (gate, version commit, pin, tags, assets in `dist/X.Y.Z/`),
`make publish VERSION=X.Y.Z` pushes it and creates the GitHub release, and `make verify-release
VERSION=X.Y.Z` downloads a published one and checks it — against its sums and manifest, against
the pin at its tag, and against a fresh container build of that tag. Nothing leaves the machine
before `make publish`; there is no CI (see "The gate is local").

| Path | What |
|---|---|
| `crates/pact-identity` | the core (`der`, `keys`, `canonical`, `hpke`, `x509`, `address`, `csr`, `card`, `envelope`, `vault`, `api`) |
| `crates/pact-identity-wasm` | the `wasm-bindgen` boundary: `call(name, args) -> json` |
| `crates/pact-limits` | SPEC §12's per-caller call budgets: token buckets, the rules as data, one pure decision (`decide`) over a state store the host implements; compiled into the core as contract §6.3 |
| `js/` | loaders (`index.mjs` for Node and the browser, `worker.mjs` for Workers), `build.sh`, `reproduce.sh` (the canonical, containerised build), `manifest.json` + `verify.mjs`, and the Node proofs `check.mjs` and `intrude.mjs` |
| `go/` | the Go port and its `pact-identity-go` adapter binary (built by the Go side; one JSON request per line on stdin, one answer per line out) |
| `contract/` | `contract.json` — the boundary as data, and the source `CONTRACT.md` is rendered from (`render.mjs`); `schema.mjs` + `schema.test.mjs`, the JSON Schema subset it is written in; `contract.mjs`, which judges one answer by it |
| `scripts/` | the release: `release.sh`, `publish.sh`, `verify-release.sh` (behind the `Makefile`), `build-cli.sh`, `version.mjs`, `changelog.mjs`, `release-manifest.mjs`, `verify-assets.mjs`; `js/release.test.mjs` runs them against stubs |
| `githooks/` | this repository's hooks (`git config core.hooksPath githooks`): rustfmt and clippy at commit, the pin's state after it, `gate.sh` at push |

## Build and prove

`sh gate.sh` runs everything below except the two builds, and is what the pre-push hook runs.

```sh
cargo test                      # unit + vector tests: the Appendix B certificates rebuilt byte for byte, every chain /
                                # newest-leaf / certificate_renewed case, and every v2 envelope opened and re-sealed
                                # from its ephemeral seed
sh js/build.sh                  # wasm-pack: js/pkg-web (browser, Workers) and js/pkg-node (Node), built on THIS machine
sh js/reproduce.sh              # the canonical build OF HEAD, in a container named by digest, compared with
                                # js/manifest.json; `--pin` writes the manifest and installs those bytes (after a
                                # commit changed a build input, and only once that input is committed)
node js/verify.mjs              # recomputes the SHA-256 of js/pkg-* against the manifest: passes after a --pin,
                                # and not after a build.sh, whose bytes are this machine's (see below)
node js/check.mjs               # Appendix B through the Wasm bindings, vectors read from SPEC.md
node js/intrude.mjs             # the seed's intrusion scenarios with the Wasm core as the defender, compared verdict
                                # by verdict with the seed's own run; none may reproduce
node js/intrude.mjs --port go   # the same against go/bin/pact-identity-go
node js/live.mjs --endpoint https://host/slug [--card card.vcf] [--insecure]   # --insecure REQUIRES --card
                                # the black-box battery of js/live-scenarios.json aimed at a LIVE endpoint, judged
                                # by the answer's code; `pact vectors intrude --against … [--card …] [--allow-insecure]`
                                # runs the same file from the Rust CLI (it embeds it). The last scenario is a
                                # control that must get THROUGH — and whose ANSWER each driver opens with the
                                # attacker's own key, because four strings shaped like an envelope are not one; it
                                # leaves a pending request behind
node --test contract/schema.test.mjs   # the contract's own validator: a value per keyword that must fail it, and
                                # a keyword it does not implement, which `compile` must REFUSE
node contract/render.mjs --check  # CONTRACT.md is what contract/contract.json and the template render.
                                # `js/parity.mjs` validates every answer of both ports against that same
                                # file, so the document and the gate cannot describe different contracts
node js/musts.mjs               # every MUST in pact-protocol/SPEC.md names something that holds it, or says who does
node js/record.mjs             # regenerate PROOFS.md: every MUST with its holder, every parity case (it prints both counts)
node js/record.mjs --check     # ...and fail if it is stale (what gate.sh runs)
node js/check-no-1x.mjs         # no tracked file carries a PACT 1.x name; js/pact1x-markers.txt is
                                # pact-protocol's list, byte for byte (`--selftest` proves the matcher)
node scripts/version.mjs --check  # the one version, in all six places it is written
```

Toolchain: Rust 1.92, `wasm-pack` 0.15 (installs a matching `wasm-bindgen`), the
`wasm32-unknown-unknown` target, Node ≥ 20. Crates: `ed25519-dalek` 2, `x25519-dalek` 2,
`curve25519-dalek` 4, `p256` 0.13, `sha2` 0.10, `hmac` 0.12, `aes-gcm` 0.10, `chacha20poly1305` 0.10,
`argon2` 0.5, `serde_json` (with `preserve_order`, so a caller's `params` serialise in its own member
order, as the vectors require), `base64` 0.22, `getrandom` 0.2 (`js` on wasm32). DER, the X.509
profile, PKCS #10 and HPKE are hand-rolled to the seed library's bytes rather than taken from crates:
the profile is exact, and every byte is under this crate's control.

## The Wasm build

`js/manifest.json` is the authority on the size and the hash of `pact_identity_wasm_bg.wasm`; about
620 KiB, most of it Argon2id and the P-256 field arithmetic (release: `opt-level = "z"`, LTO, one
codegen unit, `panic = "abort"`, no `wasm-opt`; `WASM_OPT= sh js/build.sh` runs it where binaryen
is installed, and typically takes 15–25 % off — the pinned build does not).

**The pinned bytes are one container's.** A pin is worth something only if somebody else can make
the bytes again, and cargo does not make that easy: it gives each crate a different metadata hash
on a different host, and that hash is part of every symbol's name, so one commit built on a Mac and
in a Linux container differed by a thousand bytes of layout, and a toolchain that has the std sources installed writes their local path — host triple
included — into panic locations where one without them writes `/rustc/<commit>/…`. The second is
fixed in `js/build.sh` by remapping. The first is fixed the usual way, by pinning the build
platform: `js/reproduce.sh` runs `js/build.sh` in `rust:1.92.0` named BY DIGEST
on `linux/arm64`, with wasm-pack fetched from its release and checked against a hash, and
`js/manifest.json` records that builder beside the hash. `make verify-release` rebuilds it from a
published release's tag and fails if a byte differs; nothing rebuilds it on another machine on every
push. `rust-toolchain.toml` pins the compiler for everything else.

**Style, then commit, then compile — in that order, and the tooling holds it.** The pin is of a
COMMIT: `js/reproduce.sh` builds `git archive HEAD`, never the working tree, and `--pin` refuses
while a build input (`js/inputs.mjs` has the list) is uncommitted. `js/manifest.json` records the
identity of the inputs it was built from, and `node js/verify.mjs` compares it with HEAD's before
it hashes a byte — so "the source moved and the pin did not" is learned in a second, locally,
instead of from a container five minutes after a push, or (as on 2026-09-19) not at all. Style
cannot move the pin after the fact because style is never applied after the fact: the
pre-commit hook (`githooks/pre-commit`) runs rustfmt (`rustfmt.toml`) over staged Rust and re-stages it, then requires
clippy with warnings as errors; its post-commit hook says when a commit has left the pin behind;
and the pre-push hook runs `gate.sh`, which refuses a stale pin. This exists because the order
was once the other way round: a clippy style lint nobody had ever run was obeyed after a pin, the
fix moved a line, the line number was in the binary (`#[track_caller]`), and the pin stopped
matching. After a change under `crates/`:

```sh
git commit …                    # the hook styles it and lints it
sh js/reproduce.sh --pin        # the canonical build of THAT commit; writes js/manifest.json
git commit js/manifest.json …   # a release (make release) re-pins its own version commit the same way
```

**The gate is local, and there is no CI.** `sh gate.sh` is the list above as one command — all
of it except the two builds, since the Wasm that ships is the pinned one and a native rebuild would
write this machine's bytes over it. It reads the private sibling `pact-protocol` (SPEC.md, the seed
under `vectors/lib`), which a runner's `GITHUB_TOKEN` cannot see, and the owner's decision
(2026-09-20) is that no CI credential will be made for it: this project builds, gates and deploys
from the owner's machine. So this repository's pre-push hook runs `gate.sh` on every push, and
`make release` runs it before a version is cut. A CI job once held this list and failed at its
first step on every run it ever had; the first real run of the list found a clippy error that job
had never once reported. The gate needs `../pact-protocol` checked out beside this repository.

**Workers.** Workers Builds has no Rust toolchain, so a Worker vendors the released `pkg-web`
files and checks them against the release's `manifest.json` before it ships (`node js/verify.mjs
<file>` does it for one file against this tree's `js/manifest.json`). wasm-bindgen's bundler target does not run on workerd; the web package does,
initialised synchronously over a `CompiledWasm` module — `js/worker.mjs` is the recipe, with
`{ "type": "CompiledWasm", "globs": ["**/*.wasm"], "fallthrough": true }` in `wrangler.jsonc`. That
path has not been executed under workerd from this repository; a host that runs it tests it there.

**Browser.** `js/index.mjs` picks the Node package under Node and otherwise the web package, fetching
the `.wasm` beside it. `wasm-pack test --headless --chrome crates/pact-identity-wasm` runs the
boundary's own test in headless Chrome; wasm-pack fetches the newest chromedriver, so when the
installed Chrome is one version behind pass `--chromedriver <path>` to a matching one from Chrome for
Testing (verified here with Chrome 152: 1 passed).

**Keys in Wasm memory** are readable by any script in the same context. The core is therefore never
a root's long-term home: the vault is opened into it for one issuance and the material is zeroed
when the call returns; a root held in a passkey or a security key signs through the external-signing
seam (`root_tbs`/`leaf_tbs` produce the bytes to sign, `assemble_*` builds the certificate from the
signature the host hands back).
