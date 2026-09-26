# `pact` — the PACT 2.0 command line

One native binary, built from the same core as the Wasm module (`crates/pact-identity`), so a
self-hoster needs nothing installed beside it. Two halves:

- **The implementer's tools.** `card show|check`, `chain check`, `cert show`, `csr new|check`,
  `key new`, `vectors gen|check|intrude`. Every verdict is the core's; the terminal formats it.
- **The wallet.** `id create|issue|renew|ledger|show|backup|restore`, `contacts export|import`.
  An identity is two files under one passphrase (SPEC §9): the **vault**, `<name>.pact-vault.json`,
  the root and nothing else, written when the identity is made and again only when a card takes
  its root (`card-attach`) — the copy a person keeps; and its **record**, `<name>.pact-record.json`,
  the ledger and the contact book, which every signing writes. Both are found at the vault's real
  location (through a link, beside the file it leads to), and made, backed up and restored
  together or not at all. A vault with no record beside it has no ledger there, so the leaf it
  issues next is a replacement of whatever was live, said before it is signed, and the record
  starts with it. Every command that reads the record opens the vault first, so a mistyped path
  or a wrong passphrase is refused rather than read as an empty book.
  The rules of SPEC §9 are enforced by the core's `wallet_issue` — proof of possession on every
  request, a root's own key refused, one live leaf per identity (a second endpoint is a move and
  must be asked for as one), `notBefore` monotonic over the ledger, at most 398 days — and the
  terminal adds its discipline: the passphrase from a prompt (twice when a vault is made), never
  from an argument; `PACT_PASSPHRASE_FILE` for scripts, read once and refused when anyone but its
  owner can read it; the vault and every key written mode 0600; a new endpoint asks the passphrase
  again even in the same session, and `--yes` does not skip that — with `PACT_PASSPHRASE_FILE` set
  the file is read again, so what the re-check proves is that the file still opens the vault, not
  that a person is present; a backup refuses to write over a file unless told `--force`; no command
  ever prints a root key — there is no `id export`.

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

Nothing that would destroy a key is done quietly: `pact key new` refuses a path that is taken (the
live leaf was issued to the key that is there) and takes `--force` to say otherwise, as `pact id
backup` does; `pact id create --key-out` and `pact id restore` refuse outright. Every reason a
command has to refuse is found before the passphrase is asked and before anything is written, so a
refusal leaves nothing behind.

`pact vectors check --spec pact-protocol/SPEC.md` proves Appendix B natively (the seven certificates rebuilt from their labelled seeds, every chain,
newest-leaf and `certificate_renewed` case, every `v: 2` envelope opened and re-sealed from its
ephemeral seed). `pact vectors gen` writes the same document from the seeds; Ed25519 certificates
and signatures reproduce byte for byte, ECDSA signatures are one valid signature per run, and the
P-256 leaf key is emitted in the full PKCS #8 form (the seed's Node emits the minimal form; both
parse). `pact vectors intrude --against https://host/slug` sends the black-box scenarios a live
endpoint can be judged on by its answer code alone — a stranger in the small form, a replay, a
forged signature, an unknown `kid`, a header member the version does not list, the wrong suite,
an expired leaf, a chain of one, a sealed `tools/list` from a stranger, an envelope an hour old —
and prints blocked / REPRODUCES per scenario. It writes nothing on the target.

## A root on a smartcard

Every other way of holding a root keeps it as bytes somewhere a person can copy. A PIV applet — a
YubiKey's, typically — does not: the key is generated on the card, cannot be read off it, and signs
certificates through the core's external-signing seam. "There is no export" becomes a property of
the hardware rather than a promise this code makes.

There are two ways onto a card, and they answer different questions about loss. **Choose on
purpose:**

| | `pact id create --piv 9c` | `--key-out`, then `pact card-attach` |
|---|---|---|
| Where the key was made | on the card | here, in software |
| The vault holds | the certificate, no key | the key, as it always has |
| A lost card means | **the identity is gone** — a second card is a second identity, not a spare | an inconvenience: the vault still signs |
| A copied vault means | nothing: there is no key in it | a copied identity, as with any software root |

The first is the stronger arrangement and the one with no safety net. The second is weaker by
exactly the window in which the key existed as a file, and recoverable for exactly the same reason.

### The card must already hold a key and a certificate

Generating keys on a card is the card vendor's job, not this tool's. With Yubico's `ykman`:

```
ykman piv keys generate --algorithm ECCP256 9c pub.pem
ykman piv certificates generate --subject 'CN=PACT root' 9c pub.pem
```

The certificate matters: PIV has no command that reads a bare public key, so the slot's certificate
is how `pact` learns which key is there. A slot with a key and no certificate answers "slot 9c holds
no certificate".

**P-256 only.** SPEC §14.1 allows an Ed25519 or a P-256 root; PIV's Ed25519 support is too new to
rely on across cards, so a card-held root is P-256, and a slot holding anything else is refused by
name. **Slot 9c** (Digital Signature) is the default because it is the slot that asks for the PIN on
every signature — a root should not sign quietly.

### The two routes

```
# The root is born on the card and never leaves it.
pact id create --name "Alina Rao" --vault ~/alina.pact-vault.json --piv 9c

# Or: made here, imported there, and the vault keeps a copy.
pact id create --name "Alina Rao" --alg p256 --vault ~/alina.pact-vault.json --key-out root.pem
ykman piv keys import 9c root.pem
ykman piv certificates generate --subject 'CN=Alina Rao' 9c root.pem
pact card-attach --vault ~/alina.pact-vault.json --slot 9c   # asks for the PIN once: see below
rm root.pem          # it is the root, in the clear, for as long as it exists

pact card-status --vault ~/alina.pact-vault.json      # reader, card, slot, key, and which mode
pact id issue --vault ~/alina.pact-vault.json --csr req.pem     # asks for the PIN, signs on the card
```

`pact id issue` and `pact id renew` behave exactly as they do for a software root — the same ledger,
the same one-live-leaf rule, the same endpoint, origin and dates shown before anything is signed —
and differ only in who makes the signature. The card is opened and checked against the identity's
root *before* the question, so a card that is absent, or holds another key, is said then rather than
after a person has agreed.

**Attaching asks the card to sign.** A PIV slot keeps its certificate and its key in two separate
objects and nothing makes them agree, so a slot can hold exactly the right certificate over a key
that is not the root's — `ykman piv keys import` into a slot whose certificate was generated for an
earlier key leaves a card there. Reading the certificate cannot tell. `pact card-attach` therefore
has the card sign a fresh, domain-separated challenge and verifies it under the root the vault
pins, which costs one PIN at a one-time operation and is the difference between a clear refusal now
and an unexplained failure at every issuance later. Every issuance verifies the signature under the
pinned root for the same reason, before the certificate is assembled.

**The availability cost.** A renewal needs the card present. That is fine for something yearly and
deliberate, and it is worth knowing before a leaf expires while the card is in another country.

**The PIN** comes from a prompt, or from `PACT_PIN_FILE` for a script — held to the same rule as the
passphrase file: mode 0600, nobody else may read it.

### Why this is a native binary and not the browser

PIV lives on the card's CCID (smartcard) interface. WebHID carries HID devices and Chrome blocks
FIDO HID from it outright; WebUSB cannot claim an interface a kernel driver already owns, and the
CCID driver owns this one on macOS, Linux and Windows; `chrome.platformKeys` is ChromeOS
enterprise-managed. PC/SC is the only door, and only a native binary can open it.

So a card-held root is used from this command line, and from nowhere in a browser: the wallet page
derives its root from a passkey (SPEC §2.1) and never sees a card. There was once a plan for a
browser extension to reach the card through Chrome's native messaging with this binary as the
host; the extension was removed on 2026-09-16 and that host was never built. This section stays so
that nobody tries WebHID again and concludes it is merely fiddly.

### Building without a card reader

The smartcard door is the `piv` feature, on by default. `cargo build --no-default-features -p pact`
drops it for a machine with no PC/SC headers (a bare Linux container: `apt install libpcsclite-dev`
puts them back), and the card commands then say so rather than failing obscurely.

Build: `cargo build --release -p pact` → `target/release/pact`, about 1.8 MB, no runtime
dependencies. Tests: `cargo test -p pact` (unit tests, and `tests/cli.rs` driving the binary).

**Distribution is the owner's decision:** release binaries from the repository for macOS and Linux,
a Homebrew tap, or both.
