# pact-identity — the contract every port implements

One library, several homes: a Rust core (`crates/pact-identity`) compiled to WebAssembly for the
browser, Cloudflare Workers and Node (`crates/pact-identity-wasm`, loaders in `js/`), compiled
natively for the `pact` CLI (`crates/pact`), and an independent Go port (`go/`) that the vectors tie
to the first. This file is the boundary all of them present: **bytes in, JSON out**, no state, the
same names, the same shapes. The specification is `pact-protocol/SPEC.md` (2.0.0-draft) and, where
the spec leaves a byte to the implementer, `pact-protocol/vectors/lib/*.mjs` — the seed library —
which every port must match byte for byte on the vectors in `pact-protocol/vectors/pact-2.0-vectors.json`
and on the `v: 1` vectors in SPEC.md Appendix B.

## 0. Conventions

- **Bytes in JSON** are base64url without padding (`b64url`). The vector file alone uses hex.
- **Instants** in JSON are RFC 3339 UTC strings with second precision (`"2026-09-13T12:00:00Z"`);
  `ts` and `exp` inside an envelope header stay integer Unix seconds, as the spec says.
- **Keys**: a private key is PKCS #8 DER; a public key is SubjectPublicKeyInfo DER. Algorithms are
  `"ed25519"` and `"p256"`. A **fingerprint** is `"sha256:" + b64url(SHA-256(SPKI))`; a **key id** is
  the 32 raw bytes of that hash.
- **Every function returns one JSON object.** Success shapes are listed per function. Failure is
  `{"error": "<code>", "why": "<one line>"}`, where `code` is a spec error where one applies
  (`envelope_invalid`, `chain_required`, `certificate_renewed`, `bad_request`, `pending_approval`) and
  otherwise one of `parse`, `profile`, `unsupported`, `key`, `vault`, `internal`. Ports never throw
  across the boundary.
- The Wasm boundary takes `&str` JSON and `&[u8]` DER and returns `String` JSON. The Go port exposes
  the same functions as Go functions on `[]byte`/`string` returning structs, plus a `pact-identity-go`
  binary that reads one JSON request on stdin (`{"fn": "<name>", "args": {...}}`) and writes the
  JSON answer, so the JavaScript intrusion driver can aim the same scenarios at both ports.

## 1. Keys

| Function | Input | Output |
|---|---|---|
| `generate_key` | `{"alg": "ed25519"\|"p256"}` | `{"alg", "pkcs8", "spki", "fingerprint"}` |
| `key_from_seed` (vectors and tests only) | `{"alg", "seed": b64url(32)}` | as above; Ed25519 seed used directly, P-256 scalar = seed mod n, 0 → 1 (seed `keys.mjs`) |
| `public_key` | `{"pkcs8"}` | `{"alg", "spki", "fingerprint"}` |
| `key_info` | `{"spki"}` | `{"alg", "fingerprint", "key_id": b64url}` |
| `sign` | `{"pkcs8", "data": b64url}` | `{"sig"}` — Ed25519 pure, or ECDSA P-256/SHA-256 in ASN.1 DER |
| `verify` | `{"spki", "data", "sig"}` | `{"valid": bool}` |

`sign` is the leaf key's one signing primitive; a host signs exactly four structures with it
(SPEC §13.5) and the CLI refuses any other use.

## 2. Certificates (SPEC §14.1–§14.3)

| Function | Input | Output |
|---|---|---|
| `build_root` | `{"cn", "pkcs8", "not_before", "serial"?: b64url(8..20 bytes)}` | `{"der", "fingerprint"}` |
| `root_tbs` / `assemble_root` | `{"cn", "spki", "not_before", "serial"?}` → `{"tbs", "sig_alg"}`; `{"tbs", "sig", "sig_alg"?}` → `{"der"}` | the external-signing seam: a root in a passkey or security key signs `tbs` in the host, the core assembles. `sig_alg` is the AlgorithmIdentifier as base64url DER — the TBS's own third field; `assemble_*` reads it from the TBS and, when one is handed back, requires it to be equal, so the algorithm outside a certificate can never differ from the one inside |
| `build_leaf` | `{"cn", "root_cn", "root_pkcs8", "host_spki", "endpoint", "dns_name"?, "not_before", "not_after", "serial"?}` | `{"der"}` |
| `leaf_tbs` / `assemble_leaf` | as `build_leaf` with `root_spki` in place of `root_pkcs8` → `{"tbs", "sig_alg"}`; `{"tbs", "sig", "sig_alg"?}` → `{"der"}` | the same seam for leaves, the same `sig_alg` |
| `parse_certificate` | `{"der"}` | `{"kind": "root"\|"leaf"\|"other", "subject", "issuer", "serial", "not_before", "not_after", "alg", "spki", "fingerprint", "key_id", "ski", "aki", "ca", "path_len", "key_usage": [ints], "eku": [oids], "uris": [], "dns": [], "sig_alg": oid, "profile_error": null\|string, "bytes": int}` |
| `profile_error` | `{"der", "kind": "root"\|"leaf"}` | `{"error": null\|string}` — the exact strings of `x509.mjs profileError`. Parsing itself refuses, with a `parse` error, what DER has one encoding for and the certificate spells another way: the AlgorithmIdentifier inside the TBS differing from the one outside (`signature algorithm inside and outside differ`), a BOOLEAN that is not `0xFF` or is an explicit FALSE, a non-minimal INTEGER, a BIT STRING with unused bits set, a validity of other than two times, an extension of other than two or three parts or whose OCTET STRING holds more than one TLV, a P-256 key that is not the uncompressed point |
| `validate_chain` | `{"chain": [leaf, root], "now", "expected_root"?, "expected_endpoint"?}` | accept: `{"ok": true, "leaf_spki", "leaf_fingerprint", "root_fingerprint", "endpoint", "not_before", "not_after", "alg"}`; refuse: `{"ok": false, "rule": 1..5, "reason"}` |
| `compare_leaves` | `{"pinned", "presented"}` | `{"order": "same"\|"newer"\|"superseded"\|"conflict"}` |
| `is_normal_https` | `{"url"}` | `{"normal": bool}` |
| `address_guard` | `{"endpoint", "self_endpoint"?, "guest": bool}` | `{"ok": true}` or `{"ok": false, "why"}` — refuses a host that is a loopback, link-local, private, unspecified or CGNAT literal (`localhost`, `*.localhost`, `127/8`, `10/8`, `172.16/12`, `192.168/16`, `169.254/16`, `100.64/10`, `0.0.0.0`, `::1`, `::`, `fc00::/7`, `fe80::/10`, IPv4-mapped forms), and, for a guest, an endpoint equal to `self_endpoint`. DNS resolution is the host's; `ip_is_private` is exposed so the host applies the same predicate to what it resolves |
| `ip_is_private` | `{"ip"}` | `{"private": bool}` |

Serial numbers: random 8 bytes by default; when `serial` is supplied it is used as given, which is
how the vectors reproduce (`serial = SHA-256("serial/" + label)[0..8]`). Times encode as UTCTime
before 2050 and GeneralizedTime from 2050; the root's `not_after` is always `99991231235959Z`.
Signature algorithm OIDs, extension order, criticality, key-usage bit encoding and every other byte
follow `x509.mjs` — the vector certificates must reproduce exactly from the same inputs.

The wallet's monotonic rule is the caller's: `not_before` = the later of (now − 1 h) and (previous
leaf's `not_before` + 1 s); the core enforces `not_after − not_before ≤ 398 d` and refuses otherwise.

## 3. Certificate signing requests (PKCS #10, SPEC §9)

A CSR is `CertificationRequest ::= SEQUENCE { certificationRequestInfo, signatureAlgorithm, signature }`
with an exact profile of its own: `version` 0; `subject` one UTF-8 `commonName`; the host's SPKI;
`attributes [0]` holding exactly one `extensionRequest` (`1.2.840.113549.1.9.14`) whose value is one
`subjectAltName` extension (non-critical) with exactly one URI and optionally one `dNSName` equal to
its host; the signature is by the CSR's own key with that key's own algorithm (proof of possession).
Strict DER, nothing trailing.

| Function | Input | Output |
|---|---|---|
| `csr_new` | `{"cn", "host_pkcs8", "endpoint", "dns_name"?}` | `{"der"}` |
| `csr_check` | `{"der", "root_spkis": [b64url...]}` | `{"ok": true, "cn", "spki", "fingerprint", "alg", "endpoint", "dns_name"}` or `{"ok": false, "why"}` — refuses a bad signature (no proof of possession), a key equal to any root in `root_spkis` (the root-key refusal), an endpoint that is not normal https, an endpoint the address guard refuses |
| `issue_from_csr` | `{"csr", "root_cn", "root_pkcs8", "root_spkis", "now", "previous_not_before"?, "valid_days": ≤398 (default 365)}` | `{"der", "endpoint", "not_before", "not_after"}` — `csr_check` first, then `build_leaf` under the monotonic rule |
| `issue_tbs_from_csr` | as above with `root_spki` | `{"tbs", "sig_alg", ...}` for the seam, assembled with `assemble_leaf` |

## 4. Cards (SPEC §3)

| Function | Input | Output |
|---|---|---|
| `card_encode` | `{"fn", "cert", "seal"?: "none"\|"optional"\|"required", "extra"?: [lines]}` | `{"vcard"}` — folded per RFC 6350 at 75 octets, CRLF, exactly as `card.mjs` |
| `card_decode` | `{"vcard", "now"}` | `{"fn", "version": 2, "seal", "cert", "root", "endpoint", "expired": bool, "ignored": [names], "bytes": int}` or `{"error": "bad_request", "why"}` with the exact `why` strings of `card.mjs` |
| `card_compat_encode` (Appendix C) | `{"fn", "cert", "seal"?, "gateway"?}` | a `X-PACT-VERSION:1` card carrying `X-PACT-ENDPOINT` and `X-PACT-KEY` from the leaf, for a peer known to be 1.x |

`card_decode` is intake: it refuses no version, a version it does not implement, zero or several
certificates, a certificate that does not parse, no issuer key identifier, no endpoint or several, or a
validity over 398 days; an expired leaf is reported, not refused. The address guard is a separate call
the host makes with its own endpoint in hand.

## 5. Envelopes (SPEC §13)

Suites: `PACT-SEAL-P256` (DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM) for a P-256 recipient,
`PACT-SEAL-X25519` (DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305) for an Ed25519
recipient converted by the RFC 7748 §4.1 and RFC 8032 §5.1.5 maps. HPKE Base mode, single shot,
`info` = `PACT-SEAL-v2` (`PACT-SEAL-v1` for a `v: 1` header). All-zero DH output refused. The
header is the AAD, canonicalised per RFC 8785; the signature is over `protected ‖ enc ‖ ct`.

| Function | Input | Output |
|---|---|---|
| `suite_for` | `{"spki"}` | `{"suite"}` |
| `hpke_seal` | `{"suite", "recipient_spki", "info", "aad", "plaintext", "ephemeral_seed"?}` | `{"enc", "ct"}` — `ephemeral_seed` exists for vectors and the intrusion suite; production callers omit it and the core draws 32 fresh bytes |
| `hpke_open` | `{"suite", "recipient_pkcs8", "info", "aad", "enc", "ct"}` | `{"plaintext"}` |
| `seal_request` | `{"recipient_leaf", "sender_pkcs8", "form": "chain"\|"leaf", "sender_chain"?: [leaf, root], "method", "params", "msg_id", "ts", "exp"?: ts+600, "cty"?: call, "ephemeral_seed"?}` | `{"protected", "enc", "ct", "sig"}` |
| `seal_result` | `{"recipient_spki", "sender_pkcs8", "form", "sender_chain"?, "result"?, "error"?, "msg_id", "ts", "exp"?, "ephemeral_seed"?}` | the envelope, `cty: application/pact-result+json` |
| `open_result` | `{"envelope", "my_pkcs8", "msg_id", "now", "pins": [{"root", "endpoint", "leaf", "state"}], "expected_root"?, "expected_endpoint"?}` | `{"ok": true, "result"?, "error"?, "root", "endpoint", "form", "leaf_update"?: b64url}` or `{"error": "envelope_invalid", "why"}` — the caller side of §13.2: opens, requires `result` xor `error` plus one of `chain`/`leaf`, validates the chain to `expected_root` and `expected_endpoint` or finds the named leaf among `pins`, refuses a superseded leaf, verifies `sig`, checks `cty` and `msg_id` |
| `follow_renewed` | `{"answer": {"code": "certificate_renewed", "data": {"chain"}}, "pinned_root", "pinned_leaf", "dialed", "now"}` | `{"follow": bool, "why"?, "leaf"?} ` — §14.4: validate to the pinned root and the dialed address, and follow only when the chain is newer than or equal to the pin |

**Plaintext shapes.** A request plaintext is `{"method", "params", "chain" | "leaf"}`. A result
plaintext is `{"result": <object>, "chain" | "leaf"}` or `{"error": {"code", "message", "data"?},
"chain" | "leaf"}` — the responder's proof beside the result, as §13.2 requires; the wrapper is the
clarification this library fixes and Phase 0.5 folds into the spec.

### 5.1 `decide` — the receiving rules as one pure function

`decide` implements SPEC §13.3 in order, §6.1 tiers, §5.3 new addresses with the removal tombstone,
§14.3 and §14.4, over state the host supplies. It changes nothing; it returns what it decided and the
effects the host must apply. `envelope.mjs receive()` is its specification, line for line.

Input:

```json
{
  "now": "2026-09-13T12:00:00Z",
  "envelope": {"protected": "…", "enc": "…", "ct": "…", "sig": "…"},
  "node": {
    "endpoint": "https://agent.bharat.example/mcp",
    "accept_new_hosts": "auto" | "ask",
    "chain": ["<leaf>", "<root>"],
    "keys": [{"kid": "sha256:…", "leaf": "<leaf der>", "pkcs8": "…", "current": true}],
    "former": ["sha256:…"],
    "sibling_kids": ["sha256:…"],
    "pins": [{"root": "sha256:…", "endpoint": "https://…", "leaf": "<leaf der>", "state": "active" | "pending_out" | "blocked"}],
    "tombstones": [{"root": "sha256:…", "leaf": "<leaf der>", "at": "2026-…"}],
    "former_endpoints": [{"root": "sha256:…", "endpoint": "https://…", "at": "2026-…"}],
    "seen": ["msg-id", "…"]
  }
}
```

`keys` are the leaves this endpoint holds for the identity served at the path the envelope arrived
at: the current one and superseded ones the host keeps until their `notAfter` (the core drops a
non-current key past its `notAfter` itself). `former` are the key ids of leaves once held and no
longer, for `certificate_renewed`. `sibling_kids` are the key ids held for *other* identities on the
same origin, so a key held for another identity is `envelope_invalid`, never answered with a chain.

Output:

```json
{
  "result": {"code": "ok", "tier": "contact" | "pending" | "guest" | "pending_new_address",
             "root": "sha256:…", "endpoint": "https://…", "method": "tools/call", "tool": "send_message",
             "params": {…}, "form": "chain" | "leaf", "leaf": "<leaf der the signature verified under>",
             "replayed"?: true, "why"?: "…",
             "address_claim"?: "sha256:…", "forced"?: "tombstone", "decision"?: "ask"},
  "effects": [
    {"op": "seen", "msg_id": "…"},
    {"op": "pin_update", "root": "…", "endpoint": "…", "leaf": "…"},
    {"op": "former_endpoint", "root": "…", "endpoint": "…", "at": "…"},
    {"op": "event", "event": "new_address" | "renewal", "root": "…", "endpoint"?: "…"},
    {"op": "pending", "root": "…", "endpoint": "…", "leaf": "<leaf der>", "why": "ask" | "returned after removal"}
  ]
}
```

The other results, each with an empty `effects` list unless stated: `{"code": "envelope_invalid",
"why"}` — and when `why` is `guest may only redeem or request` it also carries `root` and `leaf`, so a
host holding a 1.x pin of that leaf's key can upgrade the pin (Appendix C row 6) and decide again; `{"code": "chain_required"}`; `{"code": "certificate_renewed", "data": {"chain": [...]}}`;
`{"code": "pending_approval"}`; and `{"code": "ok", "replayed": true}` for a seen `msg_id`.
The `why` strings are the seed's, verbatim, so the intrusion suite reads both ports alike.

Order, as `receive()` has it (freshness also refuses `exp − ts` over 30 days, §13.1, as `exp too far from ts`): decode `protected` → header members exactly `cty,exp,kid,msg_id,suite,ts,v`
→ `v` = 2 and a known suite → `kid` held (current, or superseded and not past `notAfter`), else a
sibling's → `envelope_invalid`, a former → `certificate_renewed`, unknown → `envelope_invalid` → suite
fits the held leaf's key → HPKE open → plaintext members exactly `chain,method,params` or
`leaf,method,params`, method `tools/call` or `tools/list` → **small form**: leaf fingerprint matched
against pins not blocked, the held leaf within validity, `sig` verifies, else `chain_required` in every
case; then freshness (`cty` is a call, `now < exp`, `|now − ts| ≤ 300 s`, non-empty `msg_id`, replay) →
tier by pin state → **full form**: `validate_chain` at `now` with no expectation (`envelope_invalid`
with `chain rule N: reason`), `sig` under the chain's leaf key, freshness; root unpinned → tombstone
within 30 days with a newer leaf → `pending_new_address` forced `ask`, else guest; guest binding: the
method is `tools/call`, the tool `redeem_invite` or `request_contact`, `params.arguments.card`
decodes, its certificate byte-equals the chain's leaf, `address_claim` names a pin at that endpoint
or a former endpoint within 30 days; root pinned and blocked → guest; superseded → guest; conflict →
`envelope_invalid`; another endpoint → `ask` pending or `auto` re-pin with the former endpoint recorded
and a `new_address` event; newer at the pinned endpoint → `pin_update` and a `renewal` event; then
`pending_out` allows `contact_accepted`/`contact_rejected` only, else `pending_approval`; else contact.

A `pending_new_address` result is the host's to answer as SPEC §5.3 words it: the `update_contact` that
brought the new address answers `{"status": "pending"}`; every other call from that address, until the
owner decides, answers `pending_approval`.

## 6. Vault (SPEC §9; the format shared by the ceremony, the CLI and the extension)

A vault is one JSON document:

```json
{"format": "pact-vault/1",
 "kdf": {"name": "argon2id", "m_kib": 65536, "t": 3, "p": 1},
 "salt": "<b64url 16>", "nonce": "<b64url 12>", "ct": "<b64url>"}
```

The key is Argon2id(passphrase, salt) → 32 bytes; the cipher is AES-256-GCM; the AAD is the RFC 8785
canonical JSON of the document without `ct`. The plaintext is:

```json
{"v": 1,
 "roots": [{"fingerprint", "cn", "pkcs8", "cert", "created"}],
 "ledger": [{"root", "leaf", "endpoint", "not_before", "not_after", "issued_at", "origin"?}],
 "contacts": [{"root", "endpoint", "name", "leaf"?, "added"}]}
```

| Function | Input | Output |
|---|---|---|
| `vault_seal` | `{"passphrase", "plaintext": {…}, "kdf"?, "salt"?, "nonce"?}` | `{"vault": {…}}` — `salt`/`nonce` are for tests only |
| `vault_open` | `{"passphrase", "vault": {…}}` | `{"plaintext": {…}}` or `{"error": "vault", "why"}` (a wrong passphrase and a tampered document are one message) |
| `wallet_issue` | `{"vault_plaintext", "root_fingerprint", "csr", "now", "valid_days"?, "move"?}` | `{"der", "endpoint", "not_before", "not_after", "ledger_entry", "new_host": bool, "warnings": [...]}` — the wallet's rules: `csr_check` with the vault's roots as `root_spkis`; `new_host` true when no ledger entry names that endpoint's host, with the warning `new host: this endpoint's host has never been issued to`; the **live leaf is the newest one issued** (§14.3) and a second endpoint while it is unexpired is refused unless `move: true`, which instead warns `move: the live leaf at the previous endpoint is superseded once contacts see this one`; `not_before` monotonic over the ledger; `valid_days` absent means 365 and an explicit 0 is refused |

Passphrases never appear in arguments of the CLI; the ceremony and the extension hold them in memory
only for the call, and an empty passphrase seals nothing (`bad_request`). What the core zeroizes
when a call returns: every private key it decoded, the PKCS #8 bytes it decoded them from, the
HPKE ephemeral, shared secret, key, nonce and the HMAC chaining buffers, the vault's derived key
and its decrypted bytes. What it does not: the JSON argument and answer strings — including a
`pkcs8` member and a vault's decoded plaintext as a JSON value — and wasm-bindgen's copies of
those strings in linear memory, which are freed but not cleared. A host that must not leave key
material behind treats the strings it passes and receives as its own to clear.

## 7. Gates

1. `cargo test` and `go test ./...` each: rebuild the seven vector certificates byte for byte from
   `leaf_keys_pkcs8_hex` and the labelled seeds (root keys are derived from `seed("root/alina")` etc.,
   exactly as `gen.mjs`), open the four `v: 1` vectors from SPEC.md Appendix B, prove every chain
   case, newest-leaf case, `certificate_renewed` case and `v: 2` envelope, and reproduce the three
   envelopes' `enc`/`ct` from their ephemeral seeds.
2. `js/check.mjs` runs the same proof through the Wasm bindings in Node, reading vectors from SPEC.md
   as the seed's `check.mjs` does.
3. `js/intrude.mjs` replays every scenario of `pact-protocol/vectors/intrude.mjs` with Mallory built
   on the seed library and the defender on a port: `--port wasm` (default) or `--port go`. Every
   scenario's verdict must match the seed's: blocked, residual, never REPRODUCES — and the run fails
   if the two suites do not hold the same scenarios, so neither side's count is written down here.
4. `js/parity.mjs` feeds both ports the same arguments — a missing one, bytes that will not decode,
   an explicit `valid_days: 0`, a mismatched `sig_alg`, a name that straddles the vCard fold — and
   compares the answers member by member. The vectors prove the bytes a peer sees; this proves the
   codes, the words and the shapes a *caller* sees, which no vector carries.
5. `wasm-bindgen-test` in headless Chrome for the browser build; the gateway's vitest pool for the
   Worker build (phase 2.0); `extension/ npm test` for the wallet that loads `pkg-web`.
