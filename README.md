# pact-identity

The PACT 2.0 identity core: the certificate profile and chain validation of SPEC §14, the sealed
envelopes of §13 in both forms, the §3 card codec, PKCS #10 requests and issuance per §9, the
receiving rules as one pure decision function, and the vault. One Rust crate, compiled to
WebAssembly for the browser, Cloudflare Workers and Node, and natively for the `pact` CLI; an
independent Go port under `go/` that the same vectors tie to it. `CONTRACT.md` is the boundary every
port presents: bytes in, JSON out, no state.

| Path | What |
|---|---|
| `crates/pact-identity` | the core (`der`, `keys`, `canonical`, `hpke`, `x509`, `address`, `csr`, `card`, `envelope`, `vault`, `api`) |
| `crates/pact-identity-wasm` | the `wasm-bindgen` boundary: `call(name, args) -> json` |
| `js/` | loaders (`index.mjs` for Node and the browser, `worker.mjs` for Workers), `build.sh`, `reproduce.sh` (the canonical, containerised build), `manifest.json` + `verify.mjs`, and the Node proofs `check.mjs` and `intrude.mjs` |
| `go/` | the Go port and its `pact-identity-go` adapter binary (built by the Go side) |

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
node js/check.mjs               # Appendix B through the Wasm bindings, vectors read from SPEC.md: 109/109
node js/intrude.mjs             # the 115 intrusion scenarios with the Wasm core as the defender, compared verdict by
                                # verdict with the seed's run: 111 blocked, 4 residual by decision, 0 reproduce
node js/intrude.mjs --port go   # the same against go/bin/pact-identity-go
node js/live.mjs --endpoint https://host/slug [--card card.vcf] [--insecure]
                                # the 28 black-box scenarios aimed at a LIVE endpoint, judged by the answer's code;
                                # `pact vectors intrude --against … [--card …] [--allow-insecure]` is the same 28 from
                                # the Rust CLI, and js/live.test.mjs holds the two lists to each other. The last
                                # scenario is a control that must get THROUGH; it leaves a pending request behind
node js/musts.mjs               # every MUST in pact-protocol/SPEC.md names something that holds it, or says who does
node js/record.mjs             # regenerate PROOFS.md: every MUST with its holder, every parity case (it prints both counts)
node js/record.mjs --check     # ...and fail if it is stale (what gate.sh runs)
                                # and why: 46 MUSTs, 33 held here, 13 declared elsewhere
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
`js/manifest.json` records that builder beside the hash. CI rebuilds it on every push, on a hosted
runner that is not the machine the pin was written on, and fails if a byte differs.
`rust-toolchain.toml` pins the compiler for everything else.

**Style, then commit, then compile — in that order, and the tooling holds it.** The pin is of a
COMMIT: `js/reproduce.sh` builds `git archive HEAD`, never the working tree, and `--pin` refuses
while a build input (`js/inputs.mjs` has the list) is uncommitted. `js/manifest.json` records the
identity of the inputs it was built from, and `node js/verify.mjs` compares it with HEAD's before
it hashes a byte — so "the source moved and the pin did not" is learned in a second, locally,
instead of from a container five minutes after a push, or (as on 2026-09-19) not at all. Style
cannot move the pin after the fact because style is never applied after the fact: the umbrella's
pre-commit hook runs rustfmt (`rustfmt.toml`) over staged Rust and re-stages it, then requires
clippy with warnings as errors; its post-commit hook says when a commit has left the pin behind;
and the pre-push hook runs `gate.sh`, which refuses a stale pin. This exists because the order
was once the other way round: a clippy style lint nobody had ever run was obeyed after a pin, the
fix moved a line, the line number was in the binary (`#[track_caller]`), and the pin stopped
matching. After a change under `crates/`:

```sh
git commit …                    # the hook styles it and lints it
sh js/reproduce.sh --pin        # the canonical build of THAT commit; writes js/manifest.json
git commit js/manifest.json …   # then re-vendor into pact-cloud (gateway/vendor/pact-identity/VENDORED.md)
```

**The gate is local, and CI holds one job.** `sh gate.sh` is the list above as one command — all
of it except the two builds, since the Wasm that ships is the pinned one and a native rebuild would
write this machine's bytes over it. It reads the private sibling `pact-protocol` (SPEC.md, the seed
under `vectors/lib`), which a runner's `GITHUB_TOKEN` cannot see, and the owner's decision
(2026-09-20) is that no CI credential will be made for it: this project builds, gates and deploys
from the owner's machine. So the umbrella's pre-push hook runs `gate.sh` whenever a push touches
`pact-identity/` or moves the `pact-protocol` pointer. A `gate` job used to hold this list in
`.github/workflows/pact-identity.yml` and failed at its first step on every run it ever had; it is
gone, and the first real run of the list found a clippy error that job had never once reported.
What CI still runs is `reproduce`, the container rebuild described above, which needs no secret.

**Workers.** Workers Builds has no Rust toolchain, so the gateway vendors the built `js/pkg-web`
files and checks `pact_identity_wasm_bg.wasm` against `js/manifest.json` with `node js/verify.mjs
<file>` before it ships. wasm-bindgen's bundler target does not run on workerd; the web package does,
initialised synchronously over a `CompiledWasm` module — `js/worker.mjs` is the recipe, with
`{ "type": "CompiledWasm", "globs": ["**/*.wasm"], "fallthrough": true }` in `wrangler.jsonc`. That
path is documented from the gateway's own notes and has not been executed under workerd from this
repository; phase 2.0 runs it through the gateway's vitest pool.

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
