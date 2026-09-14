# `pact` — the PACT 2.0 command line

One native binary, built from the same core as the Wasm module (`crates/pact-identity`), so a
self-hoster needs nothing installed beside it. Two halves:

- **The implementer's tools.** `card show|check`, `chain check`, `cert show`, `csr new|check`,
  `key new`, `vectors gen|check|intrude`. Every verdict is the core's; the terminal formats it.
- **The wallet.** `id create|issue|renew|ledger|show|backup|restore`, `contacts export|import`.
  The rules of SPEC §9 are enforced by the core's `wallet_issue` — proof of possession on every
  request, a root's own key refused, one live leaf per identity (a second endpoint is a move and
  must be asked for as one), `notBefore` monotonic over the ledger, at most 398 days — and the
  terminal adds its discipline: the passphrase from a prompt (twice when a vault is made), never
  from an argument; `PACT_PASSPHRASE_FILE` for scripts, read once and refused when anyone but its
  owner can read it; the vault and every key written mode 0600; a new endpoint asks the passphrase
  again even in the same session; no command ever prints a root key — there is no `id export`.

```
$ pact --help
Commands:
  card      A contact card: read it as a receiver would
  chain     A chain of leaf and root: validate it (SPEC §14.2)
  cert      One certificate: what it says and whether it is in the profile (§14.1)
  csr       Certificate signing requests: a host makes one, a wallet checks one (§9)
  key       Leaf keys for a host
  vectors   Appendix B: regenerate, prove, and aim the intrusion scenarios at a live endpoint
  id        The wallet: an identity is a root in a vault, and this is where leaves come from
  contacts  The wallet's contact book, which outlives any host
```

A host and a wallet, end to end:

```
pact key new --out host.key                                   # the host's leaf key, 0600
pact csr new --key host.key --endpoint https://agent.alina.example/mcp --dns --out host.csr
pact id create --name "Alina Rao" --vault alina.pact-vault.json   # passphrase asked twice
pact id issue --vault alina.pact-vault.json --csr host.csr --valid 1y --chain-out chain.pem
pact chain check --chain chain.pem --expect-endpoint https://agent.alina.example/mcp
pact id renew --vault alina.pact-vault.json --csr next.csr    # same endpoint, fresh key
pact id issue --vault … --csr other.csr --move                # another address: a move
```

Certificates and requests are read as DER or PEM (detected by `-----BEGIN`); leaves are written as
PEM. Human-readable lines go to stderr so stdout stays a clean PEM for pipes.

`pact vectors check --spec pact-protocol/SPEC.md` proves Appendix B natively (85 checks: the four
`v: 1` envelopes, the seven certificates rebuilt from their labelled seeds, every chain,
newest-leaf and `certificate_renewed` case, every `v: 2` envelope opened and re-sealed from its
ephemeral seed). `pact vectors gen` writes the same document from the seeds; Ed25519 certificates
and signatures reproduce byte for byte, ECDSA signatures are one valid signature per run, and the
P-256 leaf key is emitted in the full PKCS #8 form (the seed's Node emits the minimal form; both
parse). `pact vectors intrude --against https://host/slug` sends the black-box scenarios a live
endpoint can be judged on by its answer code alone — a stranger in the small form, a replay, a
forged signature, an unknown `kid`, a header member the version does not list, the wrong suite,
an expired leaf, a chain of one, a sealed `tools/list` from a stranger, an envelope an hour old —
and prints blocked / REPRODUCES per scenario. It writes nothing on the target.

Build: `cargo build --release -p pact` → `target/release/pact`, about 1.8 MB, no runtime
dependencies. Tests: `cargo test -p pact` (unit tests, and `tests/cli.rs` driving the binary).

**Distribution is the owner's decision:** release binaries from the repository for macOS and Linux,
a Homebrew tap, or both.
