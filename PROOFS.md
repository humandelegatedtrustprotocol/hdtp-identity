# What is proven, and by what

**Generated — do not edit.** `node js/record.mjs` rewrites this file; `node js/record.mjs --check`
regenerates and fails on any difference, which is what CI runs. Both lists come from the things
that prove them rather than from prose beside them: the MUSTs from `pact-protocol/SPEC.md` through
the same extractor `js/musts.mjs` uses, with holders from `js/musts.json`; the parity cases from
`js/parity.mjs --manifest`, which writes its manifest only after the comparison agreed — so no
case can be listed here that did not pass.

Specification: **2.1.3**. **49** normative sentences, **425** cross-port parity cases over **38** guarded functions.

Every answer of both ports is validated against `contract/contract.json` (**39** functions, spec 2.1.3): **850** answers held to the shape it declares, **0** did not. Of **77** declared error codes, **62** were produced by a case here; the rest are declared for a caller's benefit and no argument in this suite reaches them.

## The 49 normative sentences of the specification

A sentence carrying MUST, MUST NOT or REQUIRED, one row each, in document order. **36** are
held by a test or an intrusion scenario in this repository; **13** belong to a wallet, a host
or a node, and name the artefact that holds them there — checked against the sibling repository
whenever it is on disk. A row with nothing in its last column would fail `js/musts.mjs`.


### 2. Identity, certificates and mTLS

| # | The sentence | Held by |
|---|---|---|
| `2.#1` | When both proofs are present their leaf keys MUST match, else `envelope_invalid`. | `scenario:Mallory seals with Alina's chain inside and her own signature` |

### 2.1 Deriving the root from a passkey

| # | The sentence | Held by |
|---|---|---|
| `2.1#1` | A wallet MUST use exactly these values. | `rust:derivation_vectors`, `go:TestDerivationVectors`, `rust:derivation_refuses_what_would_silently_differ`, `go:TestDerivationRefusesWhatWouldSilentlyDiffer` |
| `2.1#2` | A wallet MUST NOT present this as a guarantee: whether a given provider carries the PRF secret across its own sync is that provider's property and not the protocol's, and a wallet that has not verified it SHOULD say so rather than imply otherwise. | *wallet, by declaration* |
| `2.1#3` | A wallet holding more than one credential for its origin MUST name the intended credential when it knows which one that is, and MUST prove the derived root before signing (§2.2). | `rust:a_vault_entry_that_disagrees_with_its_own_certificate_signs_nothing`, `go:TestVaultRulesMirrorTheCore` |
| `2.1#4` | A wallet that derives its root MUST still be able to export it (§9). | `rust:issues_from_the_vault`, `go:TestVault` |

### 2.2 Proving a root before using it

| # | The sentence | Held by |
|---|---|---|
| `2.2#1` | Before issuing any certificate, a wallet MUST establish that the root it is about to sign with is the root the identity already has. | `rust:a_vault_entry_that_disagrees_with_its_own_certificate_signs_nothing`, `go:TestVaultRulesMirrorTheCore` |
| `2.2#2` | A wallet MUST refuse to sign unless all three hold: | `rust:a_card_whose_certificate_and_key_disagree_gets_no_leaf`, `rust:another_card_signs_nothing_for_this_identity`, `rust:a_card_that_swaps_its_key_after_the_check_signs_nothing_that_is_kept` |
| `2.2#3` | The challenge MUST be domain-separated from certificate bytes — the ASCII `PACT root proof v1` followed by a newline and at least 32 random bytes — so that proving possession can never be made to sign a certificate. | `cloud:gateway/src/ceremony/ceremony.js`, `cloud:gateway/scripts/check-ceremony.mjs` |
| `2.2#4` | A wallet MUST validate a chain it has assembled (§14.2) against the expected root and endpoint before returning it. | `rust:a_leaf_the_card_signed_validates_to_that_root_at_its_endpoint`, `go:TestWalletIssue` |
| `2.2#5` | **A root certificate is issued once.** A wallet MUST NOT rebuild a root certificate for an identity that already has one. | `rust:a_root_the_card_signed_is_a_root`, `go:TestWalletIssue` |

### 3. Contact cards (vCard)

| # | The sentence | Held by |
|---|---|---|
| `3.#1` | A receiving implementation MUST NOT treat `FN` as identifying, and SHOULD NOT present it as a contact's whole identity: where two pinned contacts render alike, show the fingerprint alongside. | `gateway:TestCollidingNamesCarryTheirFingerprint`, `gateway:TestLookAlikeNamesCollideToo`, `gateway:TestNoPeerFacingSurfaceCanSetAPetname` |
| `3.#2` | A receiver MUST reject a card without `X-PACT-CERT`, one whose certificate does not parse as §14.1 describes — no issuer key identifier or one that is not the 32 bytes a key identifier is, no endpoint or several, a validity longer than 398 days — and a card whose `X-PACT-VERSION` names a major version it does not implement, each with `bad_request`. | `scenario:a card without a certificate`, `scenario:two X-PACT-CERT properties`, `scenario:a card of the retired generation`, `scenario:a card whose leaf names its issuer in three bytes` |
| `3.#3` | A receiver MUST also refuse, at intake and again before every dial, an endpoint whose host resolves to a loopback, link-local or private address — the resolve-and-vet guard §6.2 applies to media URLs — unless the owner has configured that network on purpose, and a guest's endpoint that names the receiver's own address, which no honest card carries. | `go:TestAddressGuardRefusesEverySpellingOfLoopback`, `go:TestAddressGuard`, `rust:guards`, `scenario:a guest whose leaf names the receiver's own address` |
| `3.#4` | A writer MUST NOT put a control character into a card — in `FN`, in `X-PACT-SEAL`, or in a property it adds: a card is lines, a line break writes a property of the writer's choosing, and a reader takes the first of a name, so a name of `x`, a line break and `X-PACT-SEAL:none` made a card that requires sealing into one that does not. | `rust:nothing_that_goes_into_a_card_may_carry_a_line_break`, `go:TestNothingThatGoesIntoACardMayCarryALineBreak` |

### 4. Invites

| # | The sentence | Held by |
|---|---|---|
| `4.#1` | The same URL serves two audiences by content negotiation: a browser gets the human landing page; a client sending `Accept: application/pact-invite+json` (or appending `?format=json`) gets `{"card","card_sig","chain"}` — the signed card and the issuer's chain (§2), whose leaf MUST byte-equal the card's `X-PACT-CERT` and which the redeemer MUST validate (§14.2) before use, so it can seal its very first call. | `gateway:TestLandingNoOracle404`, `cloud:gateway/test/invite-landing.test.ts` |

### 5.2 Manual flow (vCard shared over existing channels)

| # | The sentence | Held by |
|---|---|---|
| `5.2#1` | "pending"}` any stranger gets, while nothing is recorded and the owner is never bothered: blocked MUST be indistinguishable from never-met (§12). | `scenario:a blocked sender is answered exactly as an unknown one`, `scenario:a blocked contact naming its leaf is answered as a stranger would be` |

### 6.2 Core tools

| # | The sentence | Held by |
|---|---|---|
| `6.2#1` | A `msg_id` MUST be a non-empty string — idempotency keyed on nothing protects nothing. | `scenario:an empty msg_id` |
| `6.2#2` | `ok` — a card refresh, or `status: pending` from a new address under `ask` (§5.3). The caller's chain is the authority: the card's certificate MUST equal the chain's leaf | `scenario:a guest whose card carries a different certificate than the chain` |
| `6.2#3` | `get_status` answers from that fixed four-value vocabulary; an implementation whose upstream presence source knows richer states MUST map any state not listed to `busy`. | `gateway:TestOwnerPresenceTracksLiveSessionsOnly` |

### 9. Hosting

| # | The sentence | Held by |
|---|---|---|
| `9.#1` | A leaf's key does not outlive its leaf: a host MUST stop using the key of a leaf that has expired and MUST destroy it, keeping the key id so that an envelope still sealed to it is answered `certificate_renewed` (§14.4) — past its date every verifier refuses the leaf (§14.2 rule 4), so the key can do nothing legitimate, and a renewal has never needed it. | `gateway:TestAnExpiredCurrentLeafLosesItsKeyInBothPlaces`, `gateway:TestALeafThatRunsOutStopsBeingServedAndLosesItsKey`, `cloud:gateway/test/leaf-expiry.test.ts` |
| `9.#2` | **Moving** is the person issuing a leaf to the new host, the data carried across as an archive — the person's contacts and their conversations, with the media in them, and nothing that is the host's own: no settings, no credentials, no invites, no record of the host's leaves; the archive's format is each host's own, a host that makes one MUST NOT put key material of any kind in it, and a host that imports one MUST refuse any key material in it and SHOULD refuse, rather than ignore, anything else it does not recognise — and the new host reaching every contact by §5.3, *before* the person tells the old host to leave, so that no contact meets a gap. | `gateway:TestAnExportCarriesContactsAndChatsAndNothingElse`, `gateway:TestAnImportRefusesAnythingAnExportDoesNotCarry`, `gateway:TestTheCloudsLeaveFileImports`, `cloud:gateway/test/leave-20.test.ts`, `cloud:gateway/test/import-20.test.ts` |
| `9.#3` | An address an identity has vacated MUST NOT be assigned to another identity until the last leaf issued for it has expired, so a contact that missed the move never reaches a stranger where it expects a friend. | `cloud:gateway/test/move-20.test.ts`, `cloud:gateway/test/leave-20.test.ts` |
| `9.#4` | A host that exports an identity toward a destination that cannot carry its chain MUST say so before the export; the remedy is a destination that can. | `cloud:gateway/src/leave/convert.ts` |
| `9.#5` | It issues one live leaf per identity at a time — a second endpoint is a move, not a second home, because contacts keep one pin and the newest leaf wins — and MUST NOT issue a second while one is live except as its replacement. | `rust:issues_from_the_vault`, `go:TestWalletIssue`, `go:TestVaultRulesMirrorTheCore` |

### 13.1 Format

| # | The sentence | Held by |
|---|---|---|
| `13.1#1` | base64url HPKE encapsulated key, of exactly the suite's `Npk` (RFC 9180 §7.1): 65 bytes for `PACT-SEAL-P256`, an uncompressed P-256 point, and 32 for `PACT-SEAL-X25519`. A receiver MUST refuse any other length (`envelope_invalid`) — `sig` covers the three members concatenated with nothing between them, so the suite's own length is what fixes the boundary; without it a byte moved from the end of `enc` to the front of `ct` leaves the signed bytes identical | `scenario:a byte moved from the encapsulated key into the ciphertext`, `go:TestSmallOrderPointsAndSPKIBits` |
| `13.1#2` | Each of the four members is base64url (RFC 4648 §5) without padding, in its one canonical spelling, and a receiver MUST refuse (`envelope_invalid`) a member written any other way: with a character outside that alphabet — padding, whitespace and the standard alphabet's `+` and `/` among them — or with a last character whose unused bits are not zero. | `scenario:a real envelope whose protected carries a stray character`, `scenario:a real envelope whose enc is padded`, `scenario:a real envelope whose ct has a line break in it`, `scenario:a real envelope whose signature is spelled with its spare bits set` |
| `13.1#3` | The suite follows the recipient's key and nothing else: a receiver MUST refuse an envelope whose `suite` is not the one its key takes (`envelope_invalid`), so no choice is left on the wire for a sender to make badly. | `scenario:the wrong suite for the recipient's key` |
| `13.1#4` | The HPKE `info` parameter is the ASCII string `PACT-SEAL-v2`, and an envelope sealed under any other info string MUST NOT open. | `scenario:sealed with a stale info string` |
| `13.1#5` | The HPKE ephemeral MUST be fresh for every envelope — a reused one repeats the key and the nonce, and two ciphertexts under them leak the XOR of their plaintexts — and both sides MUST refuse an all-zero DH output, which a low-order X25519 point produces (RFC 9180 §7.1.4). | `scenario:HPKE ephemeral reuse leaks the XOR of two plaintexts; production sealing cannot take a seed` |
| `13.1#6` | `msg_id` is REQUIRED and MUST be non-empty — replay protection keyed on an empty string protects nothing. | `scenario:an empty msg_id` |
| `13.1#7` | A protected header carrying a member not listed for its `v`, or one whose type is not the one listed — `v`, `ts` and `exp` are JSON integers, `suite`, `kid`, `msg_id` and `cty` JSON strings — MUST be rejected (`envelope_invalid`): the header is the AAD, and two implementations that disagree about what was signed cannot interoperate. | `scenario:a header with an extra member`, `scenario:a header without suite`, `scenario:a header whose ts and exp are strings`, `scenario:a v: 1 header, the retired generation` |

### 13.2 The `sealed_call` tool

| # | The sentence | Held by |
|---|---|---|
| `13.2#1` | The plaintext of a request envelope is one bare JSON object (no JSON-RPC framing) of `method`, `params`, and exactly one of `chain` and `leaf`; the method MUST be `tools/call` or `tools/list`. | `go:TestV2Envelopes`, `rust:decide_on_the_vector_envelopes`, `scenario:a sealed tools/list from a stranger` |
| `13.2#2` | A sender MUST carry `chain` on first contact and in its first envelope to each contact after a renewal, and MAY carry it at any time. | `scenario:after chain_required, the chain is sent and the leaf is learned`, `scenario:a known contact from its known host sends the small form and is a contact` |
| `13.2#3` | **The result of a sealed request MUST be sealed back to the caller** (same format, `kid` naming the caller's leaf key, the request's `msg_id` for correlation, `cty: application/pact-result+json`, and the responder's own `chain` or `leaf` in the plaintext beside the result, by the same rule — the chain when the caller has not seen this leaf, the fingerprint after; a result plaintext is one bare JSON object of `result`, the inner result, or `error`, an error object of §12, and exactly one of `chain` and `leaf`); result envelopes are never dispatched — the receiving caller decodes, opens, validates the chain or finds the named leaf among its pins, verifies the signature and correlates; a caller that cannot verify a result asks with `get_card`, which always answers with the chain — and the request-side steps of §13.3 (idempotency, tiering) do not apply to them. | `rust:a_result_seals_back_and_opens_on_the_caller_side`, `go:TestSealAndOpenResult` |
| `13.2#4` | `chain` MUST validate (§14.2), `sig` MUST verify under its leaf key, and its leaf MUST byte-equal the `card` argument's `X-PACT-CERT`. | `scenario:a guest whose card carries a different certificate than the chain`, `scenario:a sealed tools/list from a stranger` |
| `13.2#5` | Error results follow the sealing rule too: once a request envelope has been successfully opened, an error result MUST be sealed back like any other result — a plaintext error is only for an envelope that could not be opened at all, where there is no proven key to seal toward. | `gateway:TestARefusalPastTheOpenIsSealed`, `gateway:TestAPlaintextRefusalPastTheOpenIsNotThePeersAnswer` |

### 13.3 Opening

| # | The sentence | Held by |
|---|---|---|
| `13.3#1` | Receivers MUST validate in this order, rejecting at the first failure: decode `protected`; check `v` and `suite` supported; resolve `kid` to a leaf key this endpoint holds for the identity served at the path the envelope arrived at — the current one, or a superseded one not yet past its `notAfter` — and otherwise answer `certificate_renewed` with the current chain when `kid` names a key this endpoint once held for that identity, `envelope_invalid` when it never did or holds it for another identity (§14.4); check that `suite` is the one the leaf's key takes (§13.1); HPKE-open; require the plaintext to carry exactly `method`, `params` and one of `chain` or `leaf`; with `leaf`, find the leaf it names among the pins of active and pending contacts and verify `sig` under its key, answering `chain_required` to any failure, and proceed at that pin's tier and endpoint; with `chain`, validate it (§14.2), verify `sig` under its leaf key, and resolve the tier (§6.1) — when the chain's root is pinned, a leaf older than the pinned one is a guest, a different endpoint is §5.3, a newer leaf at the pinned endpoint replaces it; when it is not pinned, apply the guest binding of §13.2; enforce time — `now < exp`, and `\|now − ts\| ≤ 300 s`, since every 2.0 envelope is delivered directly; enforce `msg_id` idempotency (a replayed envelope is acknowledged with its original result, never re-executed); then dispatch. | `go:TestDecideOnVectors`, `rust:decide_on_the_vector_envelopes`, `scenario:a guessed kid learns nothing`, `scenario:an envelope for Alina's key delivered at Mallory's path on a shared host` |
| `13.3#2` | Idempotency records for seen `msg_id`s MUST be retained until `min(exp, ts + 300 s)` — the end of the window in which the envelope could be presented again and accepted. | `scenario:an envelope that asks to be remembered for a year`, `rust:an_envelope_asking_to_be_remembered_for_a_year_is_refused` |
| `13.3#3` | A **blocked** sender's envelopes MUST be processed exactly as an unknown sender's — the guest card-binding rules of §13.2 apply and a sealed `tools/list` is rejected `envelope_invalid` — so sealing never becomes an oracle distinguishing blocked from unknown (§12); a guest envelope whose inner call carries no `card` argument is likewise rejected `envelope_invalid`. | `scenario:a blocked sender is answered exactly as an unknown one` |

### 13.4 Negotiation

| # | The sentence | Held by |
|---|---|---|
| `13.4#1` | `none` — the recipient does not accept envelopes (`sealed_call` absent; senders MUST NOT seal); `optional` — both accepted; senders MAY seal; `required` — unsealed substantive calls are refused (plain `tools/list` still answers with whatever the transport identity earns), and senders MUST seal. | `gateway:TestSealNoneRefusesEnvelopes`, `gateway:TestPlaintextToSealRequiredAccountRefused` |

### 13.5 Stated trade-offs

| # | The sentence | Held by |
|---|---|---|
| `13.5#1` | That key signs exactly four structures — a TLS handshake, a certificate signing request, a card, an envelope — each distinguishable by its first bytes, and an implementation MUST NOT sign anything else with it. | *node, by declaration* |

### 14.1 Profile

| # | The sentence | Held by |
|---|---|---|
| `14.1#1` | A certificate's `signatureAlgorithm` MUST be its issuer key's own algorithm; a verifier takes the algorithm from the key, never from the certificate, so a mismatch is simply a certificate the key did not sign. | `scenario:leaf declaring ECDSA but signed by an Ed25519 root`, `go:TestInnerAndOuterAlgorithmMustAgree`, `rust:inner_and_outer_algorithm_must_agree` |
| `14.1#2` | The algorithm identifier inside the `tbsCertificate` and the outer `signatureAlgorithm` MUST be byte-equal and carry no parameters, as RFC 5280 §4.1.1.2 requires — a certificate that reads one way to a verifier of this profile and another to a TLS stack is exactly what §14.1 exists to exclude. | `scenario:one algorithm inside the TBS, another outside it`, `go:TestDERDeviationsAreRefused`, `rust:der_deviations_are_refused` |
| `14.1#3` | So an ECDSA signature on a certificate MUST be the twin with `s ≤ n/2`, the *low-S* form: an issuer normalises what it signs, including a signature a hardware token made, and a verifier refuses the other twin as outside the profile, at card intake as much as in a chain. | `scenario:a P-256 leaf whose signature was swapped for its twin`, `rust:every_p256_signature_is_the_low_s_twin`, `rust:chain_cases`, `go:TestEveryP256SignatureIsTheLowSTwin`, `go:TestCertificatesReproduce` |

### 14.2 Chain validation

| # | The sentence | Held by |
|---|---|---|
| `14.2#1` | When the verifier already holds a fingerprint for the identity in question — from a pin, or from the issuer key identifier of a card's certificate — the two MUST be equal. | `scenario:Alina's leaf presented under Mallory's root`, `scenario:the leaf presented as its own root`, `go:TestChainCases`, `rust:chain_cases` |
| `14.2#2` | When the verifier knows which address is in question — the URL it dialed, the endpoint it pinned, the endpoint in the card — the URI MUST equal it byte for byte — both are the normal form of §14.1, so nothing is normalised at comparison time. | `scenario:endpoint: userinfo in the URI`, `scenario:endpoint: uppercase host`, `scenario:endpoint: trailing slash`, `go:TestNormalFormPorts`, `rust:normal_form` |
| `14.2#3` | A `dNSName` beside the URI MUST equal its host, and the address guard of §3 — no loopback, link-local or private host; never the verifier's own endpoint from a guest — applies before any dial. | `scenario:endpoint: dNSName of another host`, `scenario:a guest whose leaf names the receiver's own address` |
| `14.2#4` | A verifier therefore MUST NOT refuse a chain on the root's `notBefore` — including a root whose `notBefore` is later than the leaf's, which is the ordinary case for a new identity, since §14.1 backdates a first leaf up to an hour for clock skew while the root was made minutes ago. | `scenario:a root whose notBefore is years away is not a refusal` |

### 14.3 The newest leaf wins

| # | The sentence | Held by |
|---|---|---|
| `14.3#1` | A verifier that does confirm a pin, by whatever means and at whatever moment it chooses, MUST NOT treat an unanswered or failed confirmation as a reason to refuse a contact or to un-pin one: an endpoint that is down, slow, or behind a network the verifier cannot reach at this moment is not a compromised endpoint, and a rule that turned unreachability into revocation would hand any carrier the power to disconnect two people by dropping one request. | `gateway:TestAnUnansweredConfirmationChangesNoPin` |

## The 425 cross-port parity cases

Each case feeds one argument shape to both the Rust core (through its WebAssembly bindings) and
the Go port and compares the whole answer — code, shape and `why` string. A function marked
*whole on success* has at least one case whose successful answer is compared member by member,
which is the only kind that notices a member going missing; a refusal compared whole proves both
ports refuse alike. `js/parity.mjs` fails if any guarded function lacks either.

At the run that generated this file: **425** cases, **0** disagreements, **38** of **38** functions compared whole on success.

### `address_guard` — 32 cases · whole on success

- address_guard https://255.255.255.255/mcp
- address_guard https://127.0.0.1/mcp
- address_guard https://127.0.0.1:8443/mcp
- address_guard https://localhost/mcp
- address_guard https://localhost:8443/mcp
- address_guard https://[::1]/mcp
- address_guard https://[::1]:8443/mcp
- address_guard https://10.0.0.5:8443/mcp
- address_guard https://192.168.1.1:443/mcp
- address_guard https://169.254.169.254/mcp
- address_guard https://100.64.0.1:9000/mcp
- address_guard https://0.0.0.0/mcp
- address_guard https://[fe80::1]:9999/mcp
- address_guard https://[fd00::1]/mcp
- address_guard https://[::ffff:10.0.0.1]/mcp
- address_guard https://api.localhost/mcp
- address_guard https://localhost./mcp
- address_guard https://127.1/mcp
- address_guard https://2130706433/mcp
- address_guard https://0x7f000001/mcp
- address_guard https://0177.0.0.1/mcp
- address_guard allows https://agent.alina.example/mcp
- address_guard allows https://agent.alina.example:8443/mcp
- address_guard allows https://203.0.113.9:8443/mcp
- address_guard on a guest naming us
- address_guard on a contact naming us
- address_guard with no endpoint
- address_guard with nothing to work from
- address_guard https://[64:ff9b::7f00:1]/mcp
- address_guard https://[2002:c0a8:101::1]/mcp
- address_guard https://[64:ff9b::808:808]/mcp
- address_guard https://[2606:4700:4700::1111]/mcp

### `assemble_leaf` — 6 cases · whole on success

- assemble_leaf with a token's high-S signature
- assemble_leaf with a low-S signature
- assemble_leaf with a sig_alg that is not the TBS's
- assemble_leaf with no signature
- assemble_leaf with nothing to work from
- assemble_leaf

### `assemble_root` — 3 cases · whole on success

- assemble_root of a TBS that is not one
- assemble_root with nothing to work from
- assemble_root

### `build_leaf` — 7 cases · whole on success

- build_leaf
- build_leaf over 398 days
- build_leaf backwards in time
- build_leaf naming https://127.0.0.1/mcp
- build_leaf naming http://a.example/x
- build_leaf naming https://a.example/x/
- build_leaf with no not_before

### `build_root` — 5 cases · whole on success

- build_root with no key
- build_root
- build_root with a serial that is too short
- build_root with an instant that is not one
- build_root with nothing to work from

### `card_decode` — 11 cases · whole on success

- card_decode of a card carrying that leaf
- card_decode of a real card
- card_decode of an empty card
- card_decode of nothing at all
- card_decode of a 1.x card
- card_decode of a card with two certificates
- card_decode of a card whose certificate is not one
- card_decode after the leaf expired
- card_decode with nothing to work from
- card_decode with no now
- card_decode of a card whose leaf names its issuer in three bytes

### `card_encode` — 13 cases · whole on success

- card_encode
- card_encode with a name outside ASCII
- card_encode with a name that straddles the fold
- card_encode with an emoji name
- card_encode with a seal nobody has
- card_encode of a certificate that is not one
- card_encode with nothing to work from
- card_encode: a name with CR LF
- card_encode: a name with a bare LF
- card_encode: a name with a NUL
- card_encode: a seal with CR LF
- card_encode: an extra line with CR LF
- card_encode: a name with a comma and a semicolon

### `compare_leaves` — 5 cases · whole on success

- compare_leaves with itself
- compare_leaves against a root
- compare_leaves of nothing
- compare_leaves with nothing to work from
- compare_leaves with pinned as null

### `csr_check` — 18 cases · whole on success

- csr_check of bytes that are not a request
- csr_check of a certificate
- csr_check with no request
- the root-key refusal
- the root-key refusal with a list that will not read
- the root-key refusal with a list of numbers
- the root-key refusal with a list of one empty string
- the root-key refusal with no list
- the root-key refusal against a key id
- csr_check with nothing to work from
- csr_check with der as null
- csr_check with root_spkis as null
- csr_check: a commonName attribute with a third element
- csr_check: a CertificationRequestInfo that is a SET, not a SEQUENCE
- csr_check: a signatureAlgorithm with a trailing NULL
- csr_check: a key outside the profile AND a malformed attribute set: which is said first
- csr_check on another port, asking for the host's dNSName
- csr_check on another port, asking for some other dNSName

### `csr_new` — 5 cases · whole on success

- csr_new with no key
- csr_new naming a local address
- csr_new naming nothing
- csr_new with a dns_name that is not the host
- csr_new with nothing to work from

### `decide` — 50 cases · whole on success

- decide on an envelope from a pinned contact
- decide on a pinned contact's call that names no tool
- decide on an envelope for a key nobody holds
- decide on a real envelope from a stranger
- decide on an envelope whose signature is wrong
- decide on a header that is not JSON
- decide with no node at all
- decide on an envelope long past its exp
- decide on an envelope whose exp is in the year 71,000
- decide with nothing to work from
- decide on an envelope whose enc is not base64url
- decide on an envelope whose ct is not base64url
- decide on a real envelope whose protected carries a stray character
- decide on a real envelope whose enc carries a stray character
- decide on a real envelope whose sig carries a stray character
- decide on a real envelope whose protected has a line break in it
- decide on a real envelope whose protected has a space in it
- decide on a real envelope whose enc is padded
- decide on a real envelope whose enc uses the standard alphabet
- decide on a real envelope whose enc has a line break in it
- decide on a real envelope whose enc has a space in it
- decide on a real envelope whose ct is padded
- decide on a real envelope whose ct uses the standard alphabet
- decide on a real envelope whose ct has a line break in it
- decide on a real envelope whose ct has a space in it
- decide on a real envelope whose sig is padded
- decide on a real envelope whose sig uses the standard alphabet
- decide on a real envelope whose sig has a line break in it
- decide on a real envelope whose sig has a space in it
- decide on a real envelope whose enc is spelled with its spare bits set
- decide on a real envelope whose ct is spelled with its spare bits set
- decide on a real envelope whose sig is spelled with its spare bits set
- decide when a held key's own leaf will not parse
- decide in the small form when a pin's leaf will not parse
- decide when the pinned leaf of the sender's root will not compare
- decide when a tombstone's instant will not parse
- decide when a tombstone's leaf will not compare
- decide with two tombstones for one root, the FIRST of them stale
- decide on a peer who returns after removal: the answer that succeeds
- decide with no now
- decide, small form: the pin names its leaf
- decide, small form: an unreadable pin that names some OTHER leaf is never parsed
- decide, small form: an unreadable pin that names no leaf has to be parsed
- decide, small form: a pin whose named leaf is not its leaf
- decide: a pending_out contact's sealed tools/list, small form
- decide: a pending_out contact's sealed send_message waits, small form
- decide: a pending_out contact's sealed tools/list, chain form
- decide: a pending_out contact's sealed send_message waits, chain form
- decide: a pending_out contact's sealed tools/list, chain form, the pin moving
- decide: a pending_out contact's sealed send_message waits, chain form, the pin moving

### `derive_seed` — 10 cases · whole on success

- derive_seed with an info string that is not one of the three
- derive_seed with the wrong case in the domain separator
- derive_seed with a short prf
- derive_seed with no info
- derive_seed with no prf
- derive_seed with prf as null
- derive_seed with prf that is not base64url
- derive_seed for pact/root/1
- derive_seed for pact/store-key/1
- derive_seed for pact/store-id/1

### `follow_renewed` — 13 cases · whole on success

- follow_renewed on a chain to another root
- follow_renewed on a chain that is not one
- follow_renewed on the same leaf
- follow_renewed with nothing to work from
- follow_renewed on an answer that is some other code
- follow_renewed on a certificate_renewed answer with no data at all
- follow_renewed on a certificate_renewed answer whose data has no chain
- follow_renewed on a chain that is null
- follow_renewed on a chain that is not a list
- follow_renewed on a chain whose members are not base64url
- follow_renewed on a chain of none
- follow_renewed to a leaf OLDER than the one pinned
- follow_renewed with no now

### `generate_key` — 5 cases · whole on success

- generate_key
- generate_key of a P-256 key
- generate_key with no algorithm
- generate_key with an algorithm nobody has
- generate_key with nothing to work from

### `hpke_open` — 3 cases · whole on success

- hpke_open of a ciphertext that is not one
- hpke_open with nothing to work from
- hpke_open of what hpke_seal made

### `hpke_seal` — 3 cases · whole on success

- hpke_seal with a suite nobody has
- hpke_seal with nothing to work from
- hpke_seal

### `ip_is_private` — 25 cases · whole on success

- ip_is_private "10.0.0.1"
- ip_is_private "8.8.8.8"
- ip_is_private "::1"
- ip_is_private "[::1]"
- ip_is_private "not-an-ip"
- ip_is_private ""
- ip_is_private "0177.0.0.1"
- ip_is_private "::ffff:10.0.0.1"
- ip_is_private "100.64.0.1"
- ip_is_private "224.0.0.1"
- ip_is_private "255.255.255.255"
- ip_is_private with nothing to work from
- ip_is_private 64:ff9b::7f00:1
- ip_is_private 64:ff9b::a9fe:a9fe
- ip_is_private 64:ff9b::808:808
- ip_is_private 64:ff9b:1::1
- ip_is_private 2002:7f00:1::1
- ip_is_private 2002:808:808::1
- ip_is_private fec0::1
- ip_is_private ::7f00:1
- ip_is_private ::808:808
- ip_is_private 2606:4700:4700::1111
- ip_is_private ::ffff:127.0.0.1
- ip_is_private ::1
- ip_is_private ::

### `is_normal_https` — 26 cases · whole on success

- is_normal_https "https://agent.alina.example/mcp"
- is_normal_https "https://agent.alina.example:8443/mcp"
- is_normal_https "https://agent.alina.example:443/mcp"
- is_normal_https "https://agent.alina.example/mcp/"
- is_normal_https "https://agent.alina.example/"
- is_normal_https "https://agent.alina.example"
- is_normal_https "http://agent.alina.example/mcp"
- is_normal_https "https://AGENT.alina.example/mcp"
- is_normal_https "https://user@agent.alina.example/mcp"
- is_normal_https "https://agent.alina.example/mcp?q=1"
- is_normal_https "https://agent.alina.example/mcp#f"
- is_normal_https "https://agent.alina.example/./mcp"
- is_normal_https "https://agent.alina.example/a/../mcp"
- is_normal_https "https://agent.alina.example/%2f"
- is_normal_https "https://agent.alina.example/%41"
- is_normal_https "https://agent.alina.example/a b"
- is_normal_https "https://agent.alina.example:0/mcp"
- is_normal_https "https://agent.alina.example:99999/mcp"
- is_normal_https "https://agent.alina.example:08443/mcp"
- is_normal_https "https://[2001:db8::1]:8443/mcp"
- is_normal_https "https://[2001:db8::1]8443/mcp"
- is_normal_https ""
- is_normal_https "not a url"
- is_normal_https "https://"
- is_normal_https with no url
- is_normal_https with nothing to work from

### `issue_from_csr` — 8 cases · whole on success

- issue_from_csr with an explicit zero validity
- issue_from_csr over 398 days
- issue_from_csr with a negative validity
- issue_from_csr of a request that is not one
- issue_from_csr refusing the root's own key
- issue_from_csr
- issue_from_csr refusing a root given as a key id
- issue_from_csr with no now

### `issue_tbs_from_csr` — 1 case · whole on success

- issue_tbs_from_csr

### `key_from_seed` — 5 cases · whole on success

- key_from_seed with a short seed
- key_from_seed with an unknown algorithm
- key_from_seed with nothing to work from
- key_from_seed
- key_from_seed of a P-256 key

### `key_info` — 16 cases · whole on success

- args that are not an object
- args that are a list
- args that are null
- key_info of an spki that is not one
- key_info with no argument
- key_info of bytes that are not base64url ("!!!")
- key_info of bytes that are not base64url ("")
- key_info of bytes that are not base64url ("AA=")
- key_info of bytes that are not base64url ("a b c")
- key_info of bytes that are not base64url ("~~~~")
- key_info of a number
- key_info of an RSA key
- key_info with nothing to work from
- key_info with spki as null
- key_info
- key_info of a P-256 key

### `leaf_tbs` — 2 cases · whole on success

- leaf_tbs
- leaf_tbs with no issuer

### `no_such_function` — 1 case · not a dispatched function

- a function nobody defines

### `open_result` — 17 cases · whole on success

- open_result of a request envelope
- open_result with nothing to work from
- open_result of what seal_result made
- open_result with a key the envelope is not sealed to
- open_result whose header names a suite that is known and is not this key's
- open_result with the wrong key AND the wrong suite: which is said first
- open_result in the leaf form, naming a leaf no pin holds
- open_result in the leaf form, from a held leaf that has run out
- open_result in the leaf form, with a signature that is not the held leaf's
- open_result in the leaf form, from a held leaf: the answer that succeeds
- open_result on a real answer whose protected carries a stray character
- open_result on a real answer whose ct carries a stray character
- open_result on a real answer whose enc is padded
- open_result on a real answer whose sig has a line break in it
- open_result with no now
- open_result, leaf form: the pin names its leaf
- open_result, leaf form: a pin whose named leaf is not its leaf

### `parse_certificate` — 18 cases · whole on success

- parse_certificate of a root
- parse_certificate of a leaf
- parse_certificate of nothing
- parse_certificate of a truncated certificate
- parse_certificate of bytes that are not DER
- parse_certificate of that leaf
- parse_certificate of a leaf with a keyUsage that is an OCTET STRING
- parse_certificate of a leaf with a subjectKeyIdentifier that is a BIT STRING
- parse_certificate of a leaf with a subjectAltName that is a SET
- parse_certificate of a leaf with an authorityKeyIdentifier that is an OCTET STRING
- parse_certificate of a leaf with a basicConstraints holding a NULL
- parse_certificate of a leaf with a basicConstraints holding only an INTEGER
- parse_certificate of a root whose basicConstraints is TRUE, 5, 0
- parse_certificate of a root whose basicConstraints is a pathLenConstraint of 128
- parse_certificate of a leaf with a 129-bit OID arc
- parse_certificate with nothing to work from
- parse_certificate with der as null
- parse_certificate of a leaf naming its issuer in three bytes

### `prf_salt` — 1 case · whole on success

- prf_salt

### `profile_error` — 7 cases · whole on success

- profile_error of a leaf read as a root
- profile_error of a root read as a leaf
- profile_error with a kind nobody has
- profile_error of that leaf
- profile_error with nothing to work from
- profile_error of a leaf read as a leaf
- profile_error of a root read as a root

### `public_key` — 7 cases · whole on success

- public_key of a key that is not one
- public_key with no argument
- public_key of an RSA key
- public_key with nothing to work from
- public_key
- public_key of a P-256 key
- public_key from an Ed25519 PKCS #8 whose algorithm carries a NULL

### `root_tbs` — 3 cases · whole on success

- root_tbs
- root_tbs with no key
- root_tbs with a serial that is too long

### `seal_request` — 12 cases · whole on success

- seal_request with no recipient
- seal_request with a form nobody has
- seal_request with a method nobody has
- seal_request with an empty msg_id
- seal_request whose exp is a month past its ts
- seal_request
- seal_request with no msg_id at all
- seal_request with an ephemeral_seed, which neither port takes
- seal_request with nothing to work from
- seal_request in the chain form with no sender_chain
- seal_request whose sender_chain is not base64url
- seal_request whose sender_chain is not a list

### `seal_result` — 6 cases · whole on success

- seal_result
- seal_result with no recipient
- seal_result with neither a result nor an error
- seal_result with nothing to work from
- seal_result of a real result
- seal_result whose sender_chain is not base64url

### `sign` — 6 cases · whole on success

- sign with a public key
- sign with no data
- sign with nothing to work from
- sign
- sign with a P-256 key
- sign with an Ed25519 PKCS #8 whose algorithm carries a NULL

### `suite_for` — 5 cases · whole on success

- suite_for an spki that is not one
- suite_for an Ed25519 key
- suite_for a P-256 key
- suite_for an RSA key
- suite_for with nothing to work from

### `validate_chain` — 36 cases · whole on success

- validate_chain of a real chain
- validate_chain against the root and endpoint it really has
- validate_chain of a P-256 chain
- validate_chain of a leaf whose ECDSA signature is the high twin
- validate_chain of a leaf with a keyUsage that is an OCTET STRING
- validate_chain of a leaf with a subjectKeyIdentifier that is a BIT STRING
- validate_chain of a leaf with a subjectAltName that is a SET
- validate_chain of a leaf with an authorityKeyIdentifier that is an OCTET STRING
- validate_chain of a leaf with a basicConstraints holding a NULL
- validate_chain of a leaf with a basicConstraints holding only an INTEGER
- validate_chain under a root whose basicConstraints is TRUE, 5, 0
- validate_chain under a root whose basicConstraints is a pathLenConstraint of 128
- validate_chain of a leaf dated 30 February
- validate_chain of a chain of one
- validate_chain of a chain of three
- validate_chain of an empty chain
- validate_chain with no chain at all
- validate_chain of leaf and leaf
- validate_chain of root and root
- validate_chain the wrong way round
- validate_chain against the wrong root
- validate_chain against another endpoint
- validate_chain before the leaf begins
- validate_chain after the leaf ends
- validate_chain with an instant that is not one
- validate_chain of members that are not base64url
- validate_chain of members that are not strings
- validate_chain with nothing to work from
- validate_chain with chain as null
- validate_chain with no now
- validate_chain with a now that is there and is not an instant
- validate_chain with a now that is empty
- validate_chain of a leaf naming its issuer in three bytes
- validate_chain of a leaf on another port carrying its host's dNSName
- validate_chain half a second after the leaf's last second
- validate_chain in the leaf's last second, with a fraction

### `vault_open` — 11 cases · whole on success

- vault_open of what vault_seal made
- vault_open with a passphrase that is wrong
- vault_open of a document that is not a vault
- vault_open of no document at all
- vault_open of a document with a KDF one pass over the ceiling
- vault_open of a document with a KDF below the floor
- vault_open of a document with a KDF whose m_kib does not fit in 32 bits
- vault_open of a document with a KDF with no passes
- vault_open of a document with a KDF with too many lanes
- vault_open of a document with a KDF nobody implements
- vault_open with nothing to work from

### `vault_seal` — 11 cases · whole on success

- vault_seal
- vault_seal with a nonce that is not 12 bytes
- vault_seal with an empty passphrase
- vault_seal with no plaintext
- vault_seal with a KDF one pass over the ceiling
- vault_seal with a KDF below the floor
- vault_seal with a KDF whose m_kib does not fit in 32 bits
- vault_seal with a KDF with no passes
- vault_seal with a KDF with too many lanes
- vault_seal with a KDF nobody implements
- vault_seal with nothing to work from

### `verify` — 4 cases · whole on success

- verify a signature that is not one
- verify with an empty signature
- verify with nothing to work from
- verify a signature the other port made

### `wallet_issue` — 8 cases · whole on success

- wallet_issue
- wallet_issue for a root the vault does not hold
- wallet_issue of the root's own key
- wallet_issue for a second address
- wallet_issue as a move
- wallet_issue with an empty vault
- wallet_issue with nothing to work from
- wallet_issue: a request carrying a CARD-held sibling root's key
