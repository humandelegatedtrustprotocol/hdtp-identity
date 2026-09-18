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
| `js/` | loaders (`index.mjs` for Node and the browser, `worker.mjs` for Workers), `build.sh`, `manifest.json` + `verify.mjs`, and the Node proofs `check.mjs` and `intrude.mjs` |
| `go/` | the Go port and its `pact-identity-go` adapter binary (built by the Go side) |

## Build and prove

```sh
cargo test                      # unit + vector tests: the Appendix B certificates rebuilt byte for byte, every chain /
                                # newest-leaf / certificate_renewed case, and every v2 envelope opened and re-sealed
                                # from its ephemeral seed
sh js/build.sh                  # wasm-pack: js/pkg-web (browser, Workers) and js/pkg-node (Node), then js/manifest.json
node js/verify.mjs              # recomputes the SHA-256 of both .wasm files against the manifest
node js/check.mjs               # Appendix B through the Wasm bindings, vectors read from SPEC.md: 107/107
node js/intrude.mjs             # the 115 intrusion scenarios with the Wasm core as the defender, compared verdict by
                                # verdict with the seed's run: 111 blocked, 4 residual by decision, 0 reproduce
node js/intrude.mjs --port go   # the same against go/bin/pact-identity-go
node js/musts.mjs               # every MUST in pact-protocol/SPEC.md names something that holds it, or says who does
                                # and why: 44 MUSTs, 33 held here, 11 declared elsewhere
```

Toolchain: Rust 1.92, `wasm-pack` 0.15 (installs a matching `wasm-bindgen`), the
`wasm32-unknown-unknown` target, Node ≥ 20. Crates: `ed25519-dalek` 2, `x25519-dalek` 2,
`curve25519-dalek` 4, `p256` 0.13, `sha2` 0.10, `hmac` 0.12, `aes-gcm` 0.10, `chacha20poly1305` 0.10,
`argon2` 0.5, `serde_json` (with `preserve_order`, so a caller's `params` serialise in its own member
order, as the vectors require), `base64` 0.22, `getrandom` 0.2 (`js` on wasm32). DER, the X.509
profile, PKCS #10 and HPKE are hand-rolled to the seed library's bytes rather than taken from crates:
the profile is exact, and every byte is under this crate's control.

## The Wasm build

`pact_identity_wasm_bg.wasm` is **639,118 bytes** (`js/manifest.json` is the authority; this line is prose and drifted from it once) (release: `opt-level = "z"`, LTO, one codegen unit,
`panic = "abort"`, no `wasm-opt` — binaryen is not installed here; `WASM_OPT= sh js/build.sh` runs it
when it is, and typically takes 15–25 % off). Argon2id and the P-256 field arithmetic are most of it.

**In CI.** `.github/workflows/pact-identity.yml` runs the same list. It cannot use
`actions/checkout`'s `submodules: true`, because every repository here is private and a runner's
`GITHUB_TOKEN` is scoped to the one it is running in — git answers "Repository not found" for a
sibling, which reads like a missing repository rather than a missing permission, and this job failed
that way on every run it had before 2026-09-15. It now checks out `pact-protocol` by name, at the
commit this tree pins, using a **`PACT_PROTOCOL_TOKEN`** secret: a fine-grained PAT with read-only
Contents on that repository (a read-only deploy key via `ssh-key` works too). Without the secret the
job stops at its first step and says so, rather than failing at checkout for a reason that looks
unrelated. `pact-cloud` is not fetched; nothing here reads it.

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
