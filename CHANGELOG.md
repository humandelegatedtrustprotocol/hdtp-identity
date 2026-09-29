# Changelog

One version for everything in this repository: the Rust crates (`pact-identity`,
`pact-identity-wasm`, `pact-limits`, the `pact` CLI), the Go module `github.com/pact-cloud/pact-identity/go` and the
Wasm package. A release is tagged `vX.Y.Z` and `go/vX.Y.Z` on one commit (`make release`), and its
GitHub release carries the Wasm package, the CLI binaries, `manifest.json` and `SHA256SUMS`.
Versions follow semver; before 1.0.0 a minor version may change the contract (`CONTRACT.md`).

Entries go under `## Unreleased` as they land; `make release` dates them.

## Unreleased

- **The parity gate generates its own cases** (the port-parity plan of 2026-09-29, S1): for every
  function the contract declares, `{}`, the hostile object, each required member absent and `null`
  (held to CONTRACT §0's `<name> is required`), each optional string `""`, each optional member of
  the wrong type, an undeclared member, and each required member absent beside each other member of
  the wrong type (read order), and each member that holds a key holding one outside the profile —
  1108 cases today (1103 when written; the hostile object is now sent only to the 15 functions that
  declare one of its members, and the key outside the profile came with cluster G), varied from one
  named hand-written case per function that succeeds on both ports. 463 cases failed when they were
  written (459 generated, and 4 written beside them), and none fails today; each was listed in `js/cases/known-divergences.json` with
  the audit finding that closes it, and the run fails on any other failure, on an entry whose case
  passes, and on an entry nobody has.
- The coverage gate fails when a declared error code is not produced by both ports in one case they
  answered alike (S2, TC-1); all 118 are. It used to print the count and pass.
- `js/cases/hostile.json` is the one hostile object: the generated cases send it to both ports, Go's
  `TestCallNeverPanics` reads it and now fails on an answer of `internal` (its `recover()` turned a
  panic into a JSON object, which the sweep accepted), and the core has the same sweep
  (`tests/boundary.rs`) (TC-14). Since a member a function does not declare is refused before any is
  read, each function is sent the hostile members it declares (the whole object reached no body),
  and both sweeps fail on the undeclared-member refusal and when fewer than ten functions are reached.
- **One copy of each duplicated constant** (S6): `contract/contract.json` carries `Windows` (the
  skew, the envelope lifetime, the tombstone and claim windows, the leaf ceiling, how far ahead a
  signing request may expire), `KdfDefault` beside `Kdf`/`KdfArgs`'s bounds, `CanonicalNumbers`
  (the 19-row ECMAScript number table each port's test carried a copy of, C11) and `LimitsIdle`; a
  test in each port holds its constants to them (`tests/constants.rs`, `vault.rs`, `canonical.rs`;
  `go/constants_test.go`, `review_test.go`). Parity cases sit at the edges they read: the tombstone
  and claim windows a second inside and exactly at the end (C13), and the most passes and lanes, one
  lane more and one KiB less than `Kdf` allows (C12).
- §13.1#1 (`enc` is exactly the suite's Npk) has holders that build an `enc`: parity cases one byte
  short and one byte long under both suites, through `decide` and `open_result` (a byte moved across
  the enc/ct boundary, so the forgery is signed), and a test in each port (TC-3). It cited a Go test
  about small-order Ed25519 points. 13.3#2 cites the Go twin of its Rust test and says what the
  library holds of it (TC-7).
- `js/musts.mjs` prints the MUSTs held by one port's tests alone and fails one that says neither why
  nor what it leaves unheld; a `gap` names that part, and is printed and counted (TC-8). §2.2's
  software path is a named gap: `wallet_issue` checks none of the three conditions in either port,
  and returns a leaf that fails chain rule 3 for a vault entry holding another key (measured). 2.2#1
  and 2.2#4 no longer cite Go tests that do not test them, and 2.2#3 no longer says the library
  checks something in the challenge's place.
- The four Appendix B readers here (`js/seed.mjs`, the CLI's `pact vectors check`, the core's
  vector tests, the Go port's) are held to one list of cases, `js/appendix-b-reader.json`, refusals
  word for word (TC-12). The core tests' reader found the end marker from the start of the file and
  had no test; the CLI says `the document has no Appendix B` and `Appendix B block <n> is not JSON`,
  as the others do, where it said `no Appendix B in the document` and serde's words.
- **A member a function does not declare is refused** (CONTRACT §0; T16, F1), in both ports, before
  any member is read: `{"error": "bad_request", "why": "<fn> takes no member \"<m>\""}`, the first
  such member in sorted order. Both ports accepted one and went on; the Rust core read six that
  `build_leaf` and `leaf_tbs` never declared (`uris`, `usage`, `extra`, `ca`, `aki`, `alg_oid`), so
  the Wasm built a CA leaf, a leaf with no URI or one under another algorithm's name where the Go port
  built a profile leaf. They are gone from the boundary, and `extra` and `alg_oid` from the typed
  `LeafSpec`, which nothing else ever set. Each port's dispatcher lists every function's members, held
  to `contract/contract.json` by a test in each (`every_function_declares_the_contracts_members`,
  `TestEveryFunctionDeclaresTheContractsMembers`). The Go port reads a call's arguments once, into a
  map by exact name: its struct decoding matched `{"CN": …}` to `cn`, a member the core never saw.
- **The Go port reads every member where the core reads it** (S3; clusters A and J of the port-parity
  audit), for the keys, certificates, CSR, signing request, card, vault and ledger functions. It
  decoded the arguments into a struct first: a required member left out was its zero value (a root
  built with an empty commonName, a leaf issued under an empty issuer, a profile judged as a leaf with
  no `kind`, a vault opened with the empty passphrase), and a member of the wrong type was named
  before any member was read, so two missing members were named differently by the two ports. Each
  body now reads its members in the core's order with readers that answer as the core's do
  (go/api_args.go), and names an absent one `<name> is required`. `issue_from_csr` and
  `issue_tbs_from_csr` check the request before `root_cn`, `now` and `valid_days`, and answer bytes
  that do not read as `parse`, as the core does, where this port said `bad_request` for everything
  (R27, T15, F3).
- **A zero value is a value at the envelope boundary too** (cluster B): the Go port's `seal_request`
  and `seal_result` seal `ts: 0`, `exp: 0`, `method: ""` and `cty: ""` as given, as the core and the
  seed do, where it read them as absent (a `ts` of 0 refused, an `exp` of 0 made ts+600, an empty
  method or cty replaced by its default); an absent `params` is `{}`, as the contract's note says,
  where it was refused as not JSON (T7, F8, R17, R18, C2, F9). `hpke_seal` and `hpke_open` require
  `info`, `plaintext`, `enc` and `ct`, which were read as empty (R15, F7); `ephemeral_seed` of any
  length but 32, `""` included, is `bad_request` `ephemeral_seed is 32 bytes` in both functions,
  where it was `parse` in one and a fresh seal in the other (R16, T13). The members are read in the
  core's order, the chain judged when the proof member is made, before the result (F10, R19). The
  typed `SealRequest` and `SealResult` keep their zero-value defaults (the node sets `Exp` and never
  `Cty`); an absent `Params` there is `{}` too.
- **The objects inside a member are read by hand, in both ports, and named by their path** (T9, F11,
  F12, F13, R20, R22): `decide`'s node state and envelope, `open_result`'s envelope and pins. A member
  one lacks, or holds of the wrong type, is `<path> is required` (`node.pins[0].leaf`,
  `envelope.sig`), `bad_request` to `decide` and, for the envelope, `envelope_invalid` to
  `open_result`. The core said `decide input does not read`, `envelope members` or serde's own words
  (`pins: missing field root`) for every fault, and the Go port decided or opened on the zero value
  (a node with no endpoint was `ok`; a pin with no root opened an answer). `pins: null` is no pins,
  as §0 says of null (the core refused it); an absent `envelope` to `open_result` is `bad_request`
  `envelope is required`, where both ports said `envelope_invalid` (S1-1). A node state that says no
  `accept_new_hosts` is `auto`, as the contract says (the Go port held a moved contact, T8), and one
  that says anything but `auto` or `ask` is refused. `follow_renewed` reads the peer's answer as it
  was sent: a code or data of the wrong type is `{follow: false}`, as the core answers, not a
  refusal of the call (F14).
- **An empty string is a value at the boundary** (cluster D; F4, R07, T14, R26): `expected_root` or
  `expected_endpoint` given as `""` to `validate_chain` or `open_result` is compared and refused, as
  the core compares it, where the Go port read it as not given and accepted any root or address.
  The typed `ChainOpts` and `OpenOpts` keep `""` as not given for a Go caller (the node's first
  certification passes an empty root). `FollowRenewed` holds a renewed chain to its pinned root and
  dialed address even when they are empty, as the core does; it followed one from any root. A
  `dns_name` given as `""` to `csr_new`, `build_leaf` or `leaf_tbs` is refused in both ports,
  `dns_name is empty`: the core wrote an empty dNSName, which rule 5 then refuses, and the Go port
  wrote none.
- **Three required members absent are `<name> is required`, as §0 says every one is** (S1-2, S1-3,
  which the generated cases found): `wallet_issue`'s `vault_plaintext` and `record_plaintext` (they
  said `…: the root lives there` and `…: the ledger lives there`, which a document that is not an
  object still says), `limits_decide`'s `now` (it said `now is a time in milliseconds`, which a
  `now` that is not one still says), and `export_read_end`'s `lines`, which both ports read as 0
  lines and refused the file for its count instead. The contract's notes said the other words, and
  say these now.
- The core reads three functions in the contract's order where the Go port already did: `card_decode`
  reads `vcard` before `now` (R25); `key_from_seed` reads `alg` before the seed (T21, R01; the Go port's
  `KeyFromSeed` also judges the algorithm first now); `vault_seal` answers `empty passphrase` before a
  missing plaintext, as its note says (T21).
- `version` and `prf_salt` declare `bad_request`: they refuse a member they do not declare, like every
  function.
- **A member of the wrong type is refused, never read as absent** (cluster C; F5, R02, C3, T21), in
  both ports, as CONTRACT §0 now says: a base64url member that is not a string answers `parse`
  `not base64url`, and any other `bad_request` in words that name it (`<name> is required`, or the
  function's own). The core read an optional one of the wrong type as absent: a `serial` of 7 built a
  root with a random serial, `guest: "yes"` let a guest name this host, `expected_root: 7` accepted
  any root, `exp: "7"` sealed ts + 600, an `aad` of 7 sealed with none. `card_encode` refuses an
  `extra` item that is not a string, `null` included (the core dropped it and wrote the card
  without it); `key_from_seed` answers a `seed` that is not a string as bytes that do not decode, and
  `export_read` refuses a `manifest`, `contacts_csv` or `threads_csv` that is not a string, in both
  ports, where both read them as absent. `key_from_seed`, `card_encode` and `vault_seal` declare
  `parse`, which the bytes rule gives them and both ports answered. Generated cases hold every
  optional member of the wrong type to that answer.
- **An integer is one the core reads as an integer** (S3-1): the Go port read `-0` as 0 — it sealed
  an `exp` of -0, decided a limits `now` of -0 and judged `valid_days: -0` out of range — where the
  core refuses it, as serde_json reads -0 as a float. A vault document whose KDF numbers are spelled
  `1.0`, `8192.0` or `1e0` has the canonical header the whole numbers have, and opened in the Go port;
  it is `kdf parameters out of range` there too, as is an `m_kib` of 8192.5, which the Go port cut to
  8192 and refused as a wrong passphrase (C5). Parity sends these as raw text (`RawArgs`, js/port.mjs),
  which `JSON.stringify` cannot write.
- **What one JSON parser refuses and the other reads is refused by both** (cluster K; R40, F21, and
  S3-2): a number infinite as a double (`1e400`) and containers nested more than 127 deep. The core's
  serde_json refused both in its own words (`args: number out of range at line 1 column 10`,
  `args: recursion limit exceeded …`); the Go port's encoding/json read them, so the Go port decided
  `ok` on a sealed call whose body held `1e400` where the Wasm said `does not open`, opened such a
  result, and read such a manifest or line. Both ports scan the arguments first, after half a
  surrogate pair, and answer `args: a number is outside the range of a double` or `args: nested more
  than 127 deep`, the first in the text; the Go port's JSON text readers (an envelope's header and
  body, a manifest, a line of messages.jsonl, a vault's plaintext) refuse the same, so each answers as
  the core's does. Arguments that do not parse are `args is a JSON object` in the core too, as in the
  Go port's `Call`; `why` never carries serde's or encoding/json's words, internal answers included.
- Go, typed (T21): `SigningRequestCheck(nil, …)` is `request is required`, as the core answers a
  request that is not an object (it named the first member, `csr is required`); `LimitsRules.Check`
  answers a member the map does not hold `<name> is a number`, as a document without it is answered
  (it read 0 and said `is at least 1`); `LimitsDecide` refuses a `Kind` nobody has, `Which`
  `charge.kind` (it charged no bucket and allowed the call). The crate's types cannot hold either.
- **An IPv6 literal with a zone id is not the normal form** (cluster F; T1, C1, R09): the Go port read
  `https://[2001:db8::1%eth0]/mcp` — and `%25eth0`, `%x@evil.example`, `%x?y` — with netip, which
  takes any zone and prints it back, so it was normal https there: a leaf naming one passed chain
  rule 5, a request naming one was issued, `address_guard` passed a zoned global address, and a
  zoned private one was refused for being private where the core refused it as not the normal form.
  Every reader of an endpoint now refuses a `%` inside the brackets, as the core and the seed do.
  `ip_is_private` answers `true` for an IPv6 literal with a zone (R10, F15): the core could not read
  one and answered `false`, and the Go port judged the address and ignored the zone, so
  `2001:db8::1%eth0` was public to both and `fe80::1%eth0` to the core. It drops one `[` and one `]`
  and no more (R11): the core dropped every bracket, so `[[::1]]` was loopback there.
- **A key outside the profile is refused where it is read** (cluster G; R12, T2, R13, T3, T4, F6,
  R14): Ed25519 with no parameters and uncompressed P-256 are the profile's two algorithms, and any
  other key — RSA, P-384, a bare X25519 key, an Ed25519 key with a NULL after its OID — is
  `unsupported`, `unsupported key type <OID>`, in both ports and the seed, whether it arrives as a key,
  in a certificate or in a request. The Go port read one as a key with no algorithm, so
  `parse_certificate` answered an `alg` the contract does not have, `compare_leaves` compared,
  `card_decode` took the card, chain rule 1 said `key algorithm not in the profile`, `csr_check` said
  `request key algorithm not in the profile`, `issue_from_csr` answered that as `bad_request`, and
  `root_tbs` declared ECDSA over an X25519 key. Both ports read a bare X25519 key as a third
  algorithm: `key_info` named `x25519`, which the contract's Alg does not have, `build_leaf` built a
  leaf around one, `verify` answered `valid: false`, and the core sealed to one where the Go port
  refused it and refused a request carrying one for its signature. Sixteen functions that answered
  `unsupported` without declaring it, in one port or both, declare it: the certificate builders and
  readers, the request functions, `hpke_seal` and `hpke_open`, `seal_request` and `seal_result`,
  `open_result` and `wallet_issue`; `decide` too, whose node state's held and pinned leaves are read the
  same way (the Go port made their error `parse`), as are `open_result`'s pins in the leaf form. The
  parity gate puts such a key into every top-level member that holds one.
- An Ed25519 key whose 32 bytes decode to no point is `parse` `Ed25519 key is not a point` in the Go
  port and the seed, as the core answers (S4-1, found here): both read it as a key, so a leaf
  carrying one validated there and was refused at chain rule 1 by the core. A point of small order is
  a point, and a non-canonical spelling of one reads as the libraries of both ports read it (410
  inputs, every one answered alike by both ports and the seed).
- A suite that is not the recipient key's is `envelope_invalid` `suite does not fit the key` at
  `hpke_seal`, as the Go port and the core's own `open_result` say it; the core said `unsupported`
  (F6, R14). A seal to an Ed25519 key of small order meets an all-zero DH output and is
  `envelope_invalid` `all-zero DH output: low-order point` in both ports, through `hpke_seal`,
  `seal_request` and `seal_result`; the core said `internal`, a code no input is to reach, and a leaf
  holding such a key validates (T4). `seal_request` and `seal_result` declare `envelope_invalid`.
- `wallet_issue` answers a request refused by its reader with the reader's class, as the core does:
  `unsupported` for a key outside the profile, `parse` for bytes that do not read, where the Go port
  said `bad_request` for both.
- **Removed public API** (cluster G): Go `AlgX25519`, `PublicKey.X`, `PublicKey.AlgOID`; Rust
  `Alg::X25519`, `keys::OID_X25519` and `keys::x25519_spki`. `Alg::sig_oid` returns the OID, not a
  `Result`: no algorithm left has none.
- **Go: an open is by a key of the suite's own algorithm** (T5). Under PACT-SEAL-X25519 a P-256 key has
  no seed, and the open used the empty seed's scalar — SHA-512 of nothing, clamped, a public constant —
  so any P-256 key opened a seal to the Ed25519 key that maps to that constant's point, through `Open`,
  `hpke_open` and `decide` (measured: two P-256 keys each opened one, and a node holding that key's leaf
  beside a P-256 key decided on a stranger's call). The private key is held to the suite before its
  material is read, as the core holds it: `does not open`.
- **Go: a key that is not one is refused by name, never a panic** (T18, the plan's S7). Every exported
  function that takes a key, or an options struct holding one — `BuildRoot`, `RootTBS`, `BuildLeaf`,
  `LeafTBS`, `CSRNew`, `IssueFromCSR`, `IssueTBSFromCSR`, `SealRequest`, `SealResult`, `OpenResult`,
  `Seal`, `Open`, `SignDetached`, `AlgorithmOf`, `SuiteForKey` — refuses a nil key, the zero value, or a
  key given an `Alg` by hand without its material, before reading a field of it: `bad_request`, `<who>
  is required` (`the root's key is required`, `the recipient's public key is required`). Measured
  before, per entry point: a nil key panicked in `BuildRoot`, `BuildLeaf`, `RootTBS`, `LeafTBS`,
  `CSRNew`, `IssueFromCSR`, `IssueTBSFromCSR`, `Seal`, `SignDetached`, `VerifyDetached`, `PKCS8`,
  `Public` and `Signer`, and each options struct but `SealOpts` and `OpenOpts` panicked at its zero
  value; a zero-value or `Alg`-only private key panicked in the builders, `CSRNew`, `SignDetached`,
  `Public`, `Signer`, and as the sender of `SealRequest` and `SealResult`. The rest answered as if a
  key were there: `RootTBS`, `LeafTBS`, `BuildLeaf` and `IssueTBSFromCSR` built around a zero-value
  public key's empty SubjectPublicKeyInfo, `PKCS8()` wrote a key with an empty scalar, `AlgorithmOf`
  and `SuiteForKey` named an `Alg` with no key behind it, and `Open` and `OpenResult` answered for the
  envelope. `PrivateKey.Public()` and `.Signer()`, which have no error to answer with, answer nil for
  such a key; `Signer.Sign` on a nil or empty signer refuses, and `VerifyDetached` with such a key is
  false. `AlgorithmOf(nil)` is `the key is required` (it said `unsupported key type`).
- **Bytes a port did not write are read by one rule, and it forgives no whitespace** (cluster H;
  X9, T10, R23, R24, T11, C7, C8, C9, C10): base64url, forgiving the padding and the standard
  alphabet's `+` and `/`, and nothing else (CONTRACT §0), in the arguments and in every string a
  port reads that it did not write — a card's certificate, the chain in a peer's plaintext, a pin's
  leaf, a held key, a vault's salt, nonce and ciphertext. `js/b64url-arguments.json` is the one list
  of cases, read by both ports' tests. The core forgave every Unicode whitespace character and the
  Go port space, tab, CR and LF, so a key with a vertical tab in it was a key to the Wasm and `parse`
  to the Go port; the contract forgives neither. The Go port read the strings it did not write with
  `FromB64url`, which skipped any character it did not know: a card whose certificate carried a
  stray `!` was taken by the Go port and refused by the core (and the cloud, which runs it); a chain
  member in a peer's plaintext with one validated, where the core refused it; a vault whose `ct`
  carried one opened; a pin that did not read was `superseded leaf`, and a held key that did not
  read was `does not open`, told to the peer where the core refuses the call as the host's state
  that does not read (`parse`, or `unsupported` for a key outside the profile). A chain member in
  the plaintext that does not read is `envelope_invalid` `plaintext shape` from `open_result` too,
  where the core answered a `parse` error of the call. An empty `X-PACT-VERSION` is `no
  X-PACT-VERSION` in the core, as the seed and the Go port say it (it said `version not
  implemented`). The seed's card.mjs and envelope.mjs read by the same rule (pact-protocol PR #10).
- `open_result` reads the first pin for the chain's root, as the core does and as `decide` reads a
  node's pins in both ports (S5-2, found here): the Go port read every pin for the root, so a second
  one newer than the chain, or one that did not read, refused an answer the first accepted.
- **Removed public API** (cluster H): Go `FromB64url`, which could not fail. `DecodeB64url`, the
  strict reader the port's boundary used unexported, is exported in its place.
- **One KDF reader in each port, shared by `vault_seal` and `vault_open`** (cluster I; S5, R28,
  R30, T12, C4, C5, F17): never truncating, members by their exact names and no others (`kdf holds
  name, m_kib, t and p, and nothing else: <member>`). A caller's `kdf` that is not an object is
  `bad_request` `kdf is required` (the core sealed under the default; the Go port answered `parse`
  `kdf does not read`, before the passphrase and the plaintext); a `name` that is not a string is
  `unknown kdf` (the core read it as `argon2id`); a parameter of another type or spelling is
  `kdf parameters out of range` (the Go port said `parse`). A document's `kdf` has all four members:
  one with no `kdf`, a `kdf` that is not an object or has no `name` is `unknown kdf`, where the core
  opened it under the default; a parameter it lacks is `kdf parameters out of range`, where the core
  took the default and the Go port zero. A document that is not an object is `not a pact-vault/1
  document` in both (the core said the passphrase was wrong). The Go port reads the header in the
  core's order: `salt`, `nonce` and `ct` before the key is derived.
- **The salt floor has one sentence, the ports' own** (R29, C6): `vault` `salt is at least 8
  bytes`, at both ends, before Argon2id is asked; `contract/contract.json`'s new `VaultSaltMin` is
  the number, held by a test in each port. The core answered Argon2id's `salt is too short`, the Go
  port `not a pact-vault/1 document`. Argon2id's own errors, which no argument now reaches, are
  `internal` in fixed words.
- **Every derivation is held to the range** (T19): the core's typed `vault::seal` handed any `Kdf` to
  Argon2id, so a typed caller could write a document both ports refuse; the Go port's typed
  `VaultSeal` refuses an empty passphrase, as the core's does and only the Go boundary did.
- **`wallet_issue` holds both documents to their schemas** (F18, R31): the vault's `roots` (a list,
  each entry a `VaultRoot`: `the vault's root <i> does not read: <member>`), `prf` and `passkey`; the
  record's `roots`, `contacts` (each a `VaultContact`), `passkey` and `backup_verified_at`, beside
  the ledger it already held. The Go port decoded the documents into typed structs, so a member of
  the wrong type anywhere was `arguments do not read`, and a `pkcs8` of `""` was a card-held root;
  the core read a wrong type as absent, skipped an entry that was not an object, and carried the
  rest. A root key that does not read is refused in its reader's class (`parse`; `unsupported` for a
  key outside the profile), where the Go port said `bad_request` `the root key does not parse`. The
  CLI reads a record through the same `check_record`, so a record it opens is held the same way.
- **A certificate is read in one order and refused in one set of words** (R33): a `keyUsage` BIT
  STRING with no initial octet (`03 00`, which X.690 §8.6.2 says is no BIT STRING) is refused by the
  core as the Go port refused it (the core read it as a keyUsage of no bits); an `[3]` with nothing in
  it is `not a v3 certificate with extensions` in both (the Go port said `certificate shape`); the Go
  port reads the fields in the core's order (the validity's count before the outer algorithm, the
  key before the names and the times, an extension's criticality before its OID) and keeps each
  reader's own error where it answered `certificate shape` or `time not in the DER form` for a
  SEQUENCE whose contents did not read. The seed refuses the three alike (pact-protocol PR #10).
- Removed (cluster I): Go's `KDF.UnmarshalJSON`. A Go caller that decodes a vault document into
  `Vault` with encoding/json gets encoding/json's reading of `kdf`; the port reads one with
  `VaultOpenDoc`.
- **JS loader:** `call(name, null)` hands `null` to the core, which answers `args is a JSON object`
  as the Go port does; it used to be made `{}` (`js/index.mjs`, `js/worker.mjs`). Only `args` left
  out is `{}`. The parity case `args that are null` sends `null` for the first time (TC-2).
- **A guest's answer says whether a pin stands behind it** (CW-11): `decide`'s guest answer carries
  `demote`, true when the root is pinned and the caller is a guest anyway (the pin is blocked, or the
  leaf is older than the pinned one), and its `why` is one of `unknown root`, `blocked` and
  `superseded leaf` (`GuestWhy` in the contract). The node demoted a caller by matching those words
  and the cloud re-derived the fact from its rows; both can read the member. The contract gives the
  guest answer its own shape (`method` `tools/call`, a guest tool, `form` `chain`, and `why`,
  `demote` and `address_claim` always present) and the other `ok` answers none of the three.
- `parse_certificate` judges a certificate that is neither a root nor a leaf as a root only when it is
  a CA and self-issued, as the contract says and the core did; the Go port judged every CA as a root,
  so a CA-flagged leaf under another name got a root's refusal there and a leaf's in the core (T17).
- **A name the contract does not have is `unsupported`, whatever the arguments are** (R34): the name is
  judged first, in both ports, before half a surrogate pair, a number past the largest double or
  arguments that are not an object. The core read the arguments first, so `nope([])` was
  `bad_request` `args is a JSON object` there and `unsupported` in the Go port, and both answered a
  surrogate or `1e400` beside an unknown name as a refusal of the arguments. CONTRACT §0 says so, and
  `js/boundary-text.json`'s `unknown_name` holds both ports' tests to it for text parity cannot send.
- CONTRACT §0's list of failure codes is rendered from the contract's `ErrorCode` (R35): it named
  `chain_required`, `certificate_renewed` and `pending_approval`, which are codes of `decide`'s
  answer and never a failure, and `profile`, which is no code at all. It no longer says the Go port
  exposes every function as a typed Go function: the export section is `Call` and the two whole-file
  conveniences.
- A header whose `ts` or `exp` is written `-0` is `header member types` in both ports, as the core
  reads it (S3-1, in the header): the Go port read it as 0 and went on to the time window. Parity
  cases hold `-0` in `ts` and `exp`, and a `ts` written with a fraction, through `decide` and
  `open_result`.
- `pact id ledger` marks as current the entry the ledger rules call live (X8): each root's newest by
  notBefore, the first of equals, and none when that one has expired. It marked the newest of the
  unexpired entries and the last of equals. The rule is written once, `ledger::live_entry`, which
  `ledger_check` uses too.
- Removed, no caller (standing rule 2): Rust `der::ia5`, and `export::csv::read` outside the tests
  (X12; Go's `csvRead` moved into its tests the same way); Go `LeafOpts`'s `CA`, `Usage`, `AKI`,
  `Extra` and `AlgOID`, and the `ExtraExtension` type — they existed "so the intrusion suite can build
  what a wallet never would", and nothing in this repository, the node or the cloud's battery set
  them. `LeafOpts.URIs` stays; the node's tests set it.
- Parity cases put a leaf at exactly `max_leaf_days` and one second past it (C15's residual).
- **`limits_buckets`, a contract function** (X2): the buckets a charge is charged to, in charge order,
  each with its key, rate and burst — the rows `limits_decide` reads, which a host fetches first. The
  Wasm could decide a charge and not say which rows it reads, so a host on it had to derive the key
  scheme and the identity rate a second time. It reads `rules` and `charge` as `limits_decide` does,
  by the same reader, in its words.
- **`media_holds_private_key`, a contract function** (CW-07, R38): whether a media file's bytes are key
  material, by the rule both ports' export readers apply to a media file. A host that streams media
  asks it; the cloud kept a third copy in TypeScript. **Key material is read leniently now, in both
  ports**, wherever it is looked for (cells, message bodies, manifest members, media): a base64 word
  forgives a last character whose spare bits are set, and a DER length may take any definite form of
  up to four octets, minimal or not. SPEC §9.2 refuses anything "that decodes as a private key", and
  a key spelled so decodes to the key under atob, Node's Buffer and OpenSSL; the ports read it as no
  key where the cloud's copy refused it. So an export or an import holding such a spelling is refused
  (a message leaves with its file) where the node and the CLI passed it. `js/key-material.json` is
  the one list of cases. Every other reader stays strict: an argument's bytes are still base64url by
  CONTRACT §0's rule.

## 0.4.1 — 2026-09-28

- **Correction to 0.4.0.** Its entry, and commit 3746e32, said the open no longer derives the
  recipient's public key; that was true of the Rust core and false of the Go port, whose
  `ParsePKCS8` still derived it on every read (14.2 us for P-256, 16.0 us for Ed25519), and the Go
  `decide` reads the held key on every open. It is true of both from this release.
- **Breaking (Go):** `PrivateKey` holds its Ed25519 seed or P-256 scalar and nothing derived from
  it. `Public` is a method, `Public()`, and the `Ed` and `EC` fields are gone; `Signer()` expands a
  key once for a caller that needs its public key and a signature. `ParsePKCS8` is 1.7 us (P-256)
  and 0.48 us (Ed25519). A P-256 scalar outside [1, n-1] is still refused, `P-256 scalar out of
  range`.
- Go: `Open` and `OpenResult` refuse a missing private or public key by name (`the recipient's key
  is required`, `the recipient's public key is required`, `bad_request`), where 0.4.0 panicked on a
  nil `RecipientPublic`. The Rust API's types cannot be nil; the JSON boundary of both ports names
  the member (`recipient_spki is required`, `my_spki is required`).
- **Fix of a regression in 0.4.0:** a leaf-form seal, a CSR, a root certificate and an issued leaf
  expanded an Ed25519 key twice, once for its public key and once to sign, once 0.4.0 made the key
  its seed. They expand it once (`PrivateKey::signer`, Go `Signer()`). `seal_result`, Ed25519
  sender, leaf form: 95.9 us in 0.4.0, 85.3 us now (85.4 us in 0.3.6).

## 0.4.0 — 2026-09-28

- `pact-limits`, a new crate: SPEC §12's per-caller call budgets as one pure decision over a state
  store the host implements (layer 2 of pact-gateway `docs/release/two-layer-limits-2026-09-28.md`).
  Token buckets with the cloud's keys, the rule set as data (no default in the library), and the
  cloud's `RateLimiter.take` arithmetic operation for operation. Two rules the cloud has no code for
  yet: the guest total charged before the open, and the cap on waiting requests. It is compiled into
  the core, so into the Wasm; the Go port is `go/limits.go`.
- Two contract functions (§6.3, section `limits`), in both ports: `limits_rules_check` (whether a
  rules document can be enforced, and the first reason it cannot) and `limits_decide` (one call:
  allowed, or refused with `retry_after` and the bucket, and the rows to write).
- `js/cases/limits-vectors.json`: 3840 steps of the cloud's TypeScript (`limits.ts`, sha256 in the
  file), run over SQLite by `js/limits-vectors.mjs` and replayed by the crate, the Wasm and the Go
  port, every row compared bit for bit.
- **Breaking:** `hpke_open` takes `recipient_spki` and `open_result` takes `my_spki`: the
  recipient's own public key, as its leaf certificate holds it, in both ports (`hpke::open` and
  `OpenResultArgs::my_public` in Rust; `Open(id, priv, pub, …)` and `OpenOpts.RecipientPublic` in
  Go). The open no longer derives it from the private key, which for P-256 was a scalar
  multiplication on every open. A public key that is not the private key's refuses (`kid is not
  this key`, or `does not open`), never a plaintext. `decide` takes the key from the held leaf it
  already parses, so its arguments do not change. No path takes the old arguments.
- An Ed25519 private key is its seed: reading one no longer derives the public key, which the open
  never used. Signing and `public()` derive what they need; signatures are byte for byte the same
  (Appendix B, both ports).
- serde_json reads floating-point numbers correctly rounded (`float_roundtrip`). Its default parser
  read `15.029461111111111` one ulp high, so a stored bucket handed to `limits_decide` would have
  read differently from what the host wrote.

## 0.3.6 — 2026-09-28

- SPEC 2.2.4: `version` answers spec 2.2.4. The change is §12's call budgets, which are token
  buckets sized by the contacts an identity may hold, and `get_card`'s `limits` members. Both are
  the hosts' to enforce and advertise; this library holds neither. §12 carries no MUST before or
  after, and `js/musts.json` is unchanged: there are still 88 MUSTs. No behaviour changes.

- `gate.sh` writes the export corpus for a random owner with `pact vectors corpus`, and the Go port
  reads it: `TestReadExportZipAnswersTheCorpusWrittenForAnotherOwner` holds every case to the
  refusals its `cases.json` names. The committed valid export read as that owner is its control.
  The test skips without `PACT_REISSUED_CORPUS`, and the gate fails unless it passed. Until now
  the Go port had read a corpus written for another owner only once, by hand.

## 0.3.5 — 2026-09-28

- **`pact vectors corpus --owner <root> --out <dir>`** writes the export corpus for another owner
  root. The committed corpus names one fixed owner, so on a host whose identities cannot hold that
  root, 27 hostile files were refused at the owner check, before the check each one targets: those
  results were UNREACHED, not proven.
  - The CLI embeds `go/exportcorpus`. A build script reads the file list from `cases.json`.
  - It replaces the owner's fingerprint in the stored members, the same length, so every offset
    and stated size stays.
  - It writes each changed member's CRC-32 again.
  - It replaces a changed member's sha256 in the manifest only where the old one was true of the
    old bytes, so a file whose defect is a wrong hash keeps it.
  - `cases.json`'s refusals follow the new owner.
  - It refuses a root the corpus gives someone else, a deflated member holding the owner, and
    writing over an existing file.
  - The committed corpus is unchanged, and the ports' own tests still read it.
  - Test: `the_corpus_reissued_for_another_owner_reaches_every_check` reads the corpus under two new
    owners with the CLI's reader. Each hostile file gets its named refusal and each valid file is
    read whole. The committed valid export is refused as another identity's under each owner.
- **A rate limit is no longer a verdict.** `pact vectors intrude` and `js/live.mjs` scored a
  `rate_limited` answer as REPRODUCES for an attack and CONTROL REFUSED for the control. It refuses
  the attempt before the target judges the attack.
  - A `rate_limited` answer, or HTTP 429, is now paused for its `retry_after` (the answer's, or the
    `Retry-After` header; 10 s when neither names one) and posted again, up to three times.
  - A pause longer than 60 s is not waited for.
  - A post still rate-limited is UNREACHED, and the run fails saying it was rate-limited.
  - The two drivers' constants are held equal by a test.

## 0.3.4 — 2026-09-27

- SPEC 2.2.3: `version` answers spec 2.2.3. The only change is 9.2#3's wording: the notice names
  what the file holds, and a book's notice names the contact list alone. `js/musts.json` re-reads
  that row, and there are still 88 MUSTs. It is held by the pact CLI's book-notice test, which
  0.3.3 already gave the book's words. Nothing here writes a full export's notice: that is the
  hosts'. No behaviour changes.

## 0.3.3 — 2026-09-27

SPEC 2.2.2: `version` answers spec 2.2.2, and `js/musts.json` holds each of its 88 MUSTs.

**This patch version changes the contract and the Go API.** The preamble above keeps that for a
minor version; 0.3.3 breaks it, to carry SPEC 2.2.2 to the node and the cloud now:
- `export_read_end` requires `media`;
- `WriteExportZip` returns `([]ExportLeftOut, error)`;
- the Go port's `ContactRowOf` and `VaultContactOf` are gone.

- **What a contact controls never stops an export** (SPEC 2.2.1, 9.2#22–25). The writers now:
  - write a `reply_to` as null when the message it names is not in the file. A host writing in
    batches names the file's msg_ids in `export_write_messages`'s new optional `msg_ids`;
  - leave out a message whose body is a private key and list it in `left_out: [{id, reason}]`;
  - keep only §8's names in `their_permissions`, once each;
  - cut `display_name` to 200 characters, on a character boundary.
  
  Go's `WriteExportZip` also leaves out every message carrying a file whose bytes are a key, with
  the file. It now returns `([]ExportLeftOut, error)`: **a change to its Go signature.** The reader
  still refuses each of these in a file someone else wrote.
- **The manifest lists the text members only** (SPEC 2.2.2, 9.2#11). `files` names `contacts.csv`,
  `threads.csv` and `messages.jsonl`, never a media member. A media member is bound by its name, the
  sha256 of its bytes, and counted by `counts.media`. The number of files an export can carry is no
  longer bounded by the manifest's 64 KiB; 5000 media files make a manifest of a few hundred bytes.
  - `export_read` refuses a `files` entry naming anything else.
  - `export_write` no longer lists media.
  - **`export_read_end` takes `media` (required).** This is the hashes of the directory's media
    members, which `export_read` answers. It refuses one no message names. This is a contract
    change: a host passes the list it already has.
- **Key material** (SPEC 2.2.2, 9.2#15, #28):
  - A manifest whose `owner_name` or `tool` holds a private key is refused on read.
  - `export_write` refuses one, naming the member.
  - Both hosts refuse a media file whose bytes are a key, in DER or PEM: `media/<h>: holds a private
    key`. These are the Go port's `ReadExportZip` and the pact CLI. The rule over a file's bytes is
    tested in each port with PKCS #8 and SEC1, in DER and in PEM, against a document and DER that is
    no key.
- **One instant grammar** (SPEC 2.2.2, 9.1#3, 9.2#13). An instant is `YYYY-MM-DDTHH:MM:SS`, an
  optional `.` fraction, then `Z`: upper-case T and Z, no offset, and no `,` before the fraction.
  This now holds everywhere either port reads one: the export, the ledger, a signing request's
  `expires`, and every `now` argument.
  - The Go port read a `,` fraction, an offset and a lower-case `t`/`z` in places; the Rust core
    read a lower-case `t`/`z`.
  - `$defs.InstantIn` says the same.
  - Read-side parity cases hold it in a contact's `added`, a thread's `created_at`, the manifest's
    `exported_at` and a message's `time`: a lower-case `z` or `t`, a `,` fraction and an offset are
    each refused, in both ports.
- `WriteExportZip` runs the reader's rules on what it was handed before it writes the first byte.
  Before, a refusal could come after part of the file was written.
- `export_merge` keeps what the person decided about a held contact. When a file brings the leaf of
  a contact held without one, the row is written for the leaf, but a blocked contact stays blocked
  and the held permissions stay. Every difference in `status` or `permissions` is a conflict, and
  `conflicts[].field` gains `status` and `permissions`. Permissions compare as a set.
- `redirect_allowed` (the signing request's redirect) refuses upper-case IPv6 hex and a host name
  with an empty label.
- `export_read_end`'s lean reader answers exactly as the parsed arguments would, and outside the
  Wasm build it runs under `catch_unwind`.
- **Removed:** the Go port's `ContactRowOf` and `VaultContactOf`. Nothing called them; `book_rows`
  is the one mapping from a wallet's book to rows.
- The pact CLI:
  - `contacts export` now gives a book's own notice, which names the contact list and not the
    conversations and files a book does not hold. Its test shows the notice is given before the
    file is written, including when the write itself fails.
  - It reads the export's bounds from the core's constants instead of its own copies.
- The bounds of `$defs.ExportLimits` are held to the Rust and Go constants by a test in each port.
  The at-most-one attachment is a named constant in both.
- **The corpus** is now 44 cases (41 hostile, 3 accepted), 45 files and 465,320 bytes. New files:
  - `local-names-differ.zip` (9.2#6): every local header names a path that climbs out, and the
    central directory is true. It is accepted.
  - One file per size bound, each deflated so the repository holds kilobytes: contacts.csv over
    4 MiB, contacts.csv over 5000 rows, threads.csv over 16 MiB, a media file over 5 MiB.
  - `root-cert-not-a-root.zip`: a certificate outside §14.1's profile.
  - `media-is-a-key.zip`: a host-stage file.
  - `media-listed-in-files.zip` replaces `media-name-not-hash.zip`.

  `js/cases/export-reader.mjs` adds one read-side parity case per rule of 9.2#10, #13 and #15 that
  no file reached. Both hosts' corpus tests count the accepted files from `cases.json`.
- `js/musts.json`'s citations were corrected where they claimed more than the cited test shows:
  - 9.#2 cited `TestAnExportWrittenIsReadBackWhole`, which holds no key material;
  - 9.2#10 cited one file for every bound;
  - 9.2#15 held only its first half;
  - 9.2#3's test did not show the notice's order.

  Host MUSTs now name the node's tests where they exist, with `elsewhere_names`, and name the
  node's and the cloud's MUST tables.
- Deliberate deviations from the plan of record (pact-gateway `docs/release/identity-boundary-build-2026-09-27.md`):
  - the Go port's CSV is hand-written, not `encoding/csv`. That reader skips a blank line and
    rewrites a quoted CRLF to LF, and a reader that repairs what it reads is not the rule both
    ports hold;
  - the CLI's `zip` takes `deflate-flate2` (flate2's pure-Rust miniz_oxide), not `deflate`, which
    would also bring zopfli.
- `js/cases.test.mjs` takes a section's cases split across files (`<section>-<part>.mjs`) only when
  the section's file imports and calls the part; before, `export-reader.mjs` failed it.
- `zip` is pinned exactly (`=8.6.0`).
- `deny.toml` holds the sources: crates.io and nothing else.
- `gate.sh` runs `cargo deny check licenses sources` with cargo-deny 0.20.2, pinned; another
  version stops the gate with the install command.

## 0.3.2 — 2026-09-27

- **Fixed: the export's readers held many times what they were handed.** In 0.3.1 `export_read` built
  every row as a tree of JSON values, beside two copies of each cell, before it wrote its answer. The
  C2 builder measured it through the Wasm core: the linear memory grew about 2.2 KB per row of
  threads.csv, about 16× the CSV — 35 MB at 16k threads, 137 MB at 60k, 260 MB at 120k — and a Wasm
  instance's memory never shrinks. `export_read_end` held each id three times over, 618 bytes an
  id. In 0.3.2:
  - the CSV is read in two passes, as slices of the text, and each thread is written into the
    answer as it passes; no row is held as a value, and a thread id is remembered as a 32-byte
    digest, never a copy;
  - `export_read_end` reads its lists straight from the argument text, borrowed and sorted, never
    copied;
  - only a word that could begin a private key's DER (base64 `M`) is decoded when the cells are
    searched for key material.
  - Measured through the Wasm core: 4.9× the CSV at 16k threads (was 15.2×) and 4.8× at 64k. The
    largest threads.csv the bound allows (16 MiB, 120,684 threads) now grows the memory by 67.9 MB,
    where it was 271.2 MB. `export_read_end` now holds 1.7× its lists (was 5.1×).
  - The Go port allocates 6.5–6.8× the CSV (was 28–30×) and 4.4–4.7× the lists (was 10.3–10.9×).
  - A 64 MiB messages.jsonl read in batches of 500 lines stays under 2.3 MB of linear memory
    throughout.
  - Held by memory tests in the core (`tests/memory.rs`, its own peak), the Go port (bytes
    allocated) and the Wasm build (`js/export-memory.test.mjs`, linear memory), each a bound per
    byte handed in, at N and 4N rows.

## 0.3.1 — 2026-09-27

- **Fixed: the export's readers and writers were quadratic in the rows of a file.** In 0.3.0
  `export_read` scanned the threads it had read for each new thread id, and the other functions
  scanned the lists the file sizes too. The scans were for contacts' roots, thread ids, message
  msg_ids and reply_tos, media, the directory, a cell's permissions, and the held rows of
  `export_merge`, and in Go also the streamed media and the manifest's keys. Measured through the
  Wasm core, `export_read` of 200 contacts took 0.22 s at 2k threads, 0.76 s at 4k, 3.1 s at 8k and
  12.2 s at 16k; a 14.7 MB file of 120k threads, within the 16 MiB bound, ran for more than 9
  CPU-minutes. Every such lookup is now a set or a map, in both ports. In 0.3.1 the same reads take
  19, 28, 50 and 96 ms, and the largest file the bounds allow (5000 contacts, 163,962 threads,
  16 MiB) is read in about 1 s. Guarded in both ports by a growth test that fails if a function
  takes more than 8× as long on 4× the rows, and by an absolute ceiling of 10 s for that largest
  file (js/export-limits.test.mjs).

## 0.3.0 — 2026-09-27

- `ledger_check` (contract §6.1, section `ledger`): the wallet's ledger rules as facts — the refusal
  of a second home, `new_host`, `known_endpoint`, `previous_not_before`, the live leaf, and the move
  notice's kind (`renew`, `move`, `new_host`, `move_back`, `no_ledger`). `wallet_issue` in both ports
  applies it, and so does the `pact` CLI's `id issue` for a card-held root; the CLI's own copy of the
  one-live-leaf rule is gone. `id issue` prints the move notice before it signs a move.
- `signing_request_check` (contract §3.1, section `signing`) and `$defs.SigningRequest`: a web
  wallet's checks of a host's signing request before a person sees it — the members and their
  bounds, the asking origin against the redirect's, the redirect (https, or http to `localhost`,
  `127.0.0.0/8` or `[::1]`; no userinfo, no fragment), the ten-minute expiry window, `renew` or
  `move`, `valid_days` 1–398, the `state` and `expect_root` shapes, `root_cert` against `expect_root`,
  and the CSR through `csr_check`.

- The export (SPEC §9.2; contract §6.2, section `export`): `export_read`, `export_read_messages`,
  `export_read_end`, `export_write`, `export_write_messages`, `export_manifest` and `export_merge`,
  with `$defs` `ExportManifest`, `ContactRow`, `ThreadRow`, `MessageRow`, `Attachment`,
  `DirectoryEntry` and the bounds as `ExportLimits`. The core never opens a zip: a host hands it
  the central directory, the text members and the messages in batches, and every rule that can be
  decided on those is decided once. A strict RFC 4180 reader and writer are written in the crate
  (the Wasm core gains no dependency), and the written bytes are the same from both ports.
- The Go port's `ReadExportZip` and `WriteExportZip` (`archive/zip`), conveniences over those
  functions, and `ContactRowOf` / `VaultContactOf` between the wallet's book and a row (removed in
  0.3.3: nothing called them).
- `go/exportcorpus`: a valid export, a valid book, and 35 hostile files, each
  naming its refusal. (Corrected in 0.3.3: this entry said "one hostile file per check of §9.2". The
  size bounds past the manifest's, the certificate profile and most column and member rules had no
  file.) (`cases.json`), generated by `go run ./exportcorpus/gen` and held to the
  generator by a test; the Go port, the pact CLI and `js/parity.mjs` all read the whole of it.
- The pact CLI: `contacts export --out FILE` writes the wallet's book as an unencrypted zip, saying
  so first, and `contacts import` reads a book or a whole export (checked whole), keeping its
  contacts. It reads zips with the `zip` crate (deflate through flate2's miniz_oxide only), in the CLI
  alone.
- `deny.toml`, and a `cargo deny check licenses` step in `gate.sh`, which needs
  `cargo install cargo-deny --locked`.

- SPEC 2.2.0: `version` answers spec 2.2.0, and `js/musts.json` holds each of its 81 MUSTs (29 new,
  9.#2 re-read). `WriteExportZip` refuses a message whose file is not among those exported.
- `book_rows` (contract §6.2): the wallet's book as `contacts.csv` rows, the one mapping the `pact`
  CLI's `contacts export` and the Go port's `ContactRowOf` use (`ContactRowOf` removed in 0.3.3).
- Arguments holding half a UTF-16 surrogate pair are refused by every function of both ports, in one
  answer, before anything reads them (CONTRACT §0).
- The release carries `pact-identity-exportcorpus-X.Y.Z.tgz`: `go/exportcorpus`'s `cases.json` and
  zips under `exportcorpus/`, listed in `manifest.json` and `SHA256SUMS`, and checked against the tag
  by `make verify-release`.

## 0.2.0 — 2026-09-27

The first release of pact-identity as a repository of its own (split from the umbrella
`pact-gateway` on 2026-09-27). What 0.1.0 was is unchanged in behaviour; what is new is how it is
named, depended on and released.

- The Go module is `github.com/pact-cloud/pact-identity/go` (it was
  `github.com/tech-sumit/pact-gateway/pact-identity`); the crates name this repository.
- Releases: `make release`, `make publish`, `make verify-release`; one version across the crates,
  the Go module (`ModuleVersion`) and the Wasm package, held equal by `scripts/version.mjs --check`.
- The library no longer reads or describes a hosting platform: the MUST holders that cited one are
  that platform's to keep, `js/musts.mjs` checks the node's names only, and test hosts are `.example`.
- The repository's own hooks (`githooks/`): rustfmt and clippy at commit, `gate.sh` at push.
- `js/check-no-1x.mjs`: no tracked file carries a PACT 1.x name; its marker list is held
  byte-identical to pact-protocol's.
