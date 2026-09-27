# What is proven, and by what

**Generated — do not edit.** `node js/record.mjs` rewrites this file; `node js/record.mjs --check`
regenerates and fails on any difference, which is what gate.sh runs. Both lists come from the things
that prove them rather than from prose beside them: the MUSTs from `pact-protocol/SPEC.md` through
the same extractor `js/musts.mjs` uses, with holders from `js/musts.json`; the parity cases from
`js/parity.mjs --manifest`, which writes its manifest only after the comparison agreed — so no
case can be listed here that did not pass.

Specification: **2.2.2**. **88** normative sentences, **727** cross-port parity cases over **48** guarded functions.

Every answer of both ports is validated against `contract/contract.json` (**49** functions, spec 2.2.2): **1454** answers held to the shape it declares, **0** did not. Of **92** declared error codes, **77** were produced by a case here; the rest are declared for a caller's benefit and no argument in this suite reaches them.

## The 88 normative sentences of the specification

A sentence carrying MUST, MUST NOT or REQUIRED, one row each, in document order. **62** are
held by a test or an intrusion scenario in this repository; **26** belong to a wallet, a host
or a node, and name the artefact that holds them there — checked against the sibling repository
whenever it is on disk. A row with nothing in its last column would fail `js/musts.mjs`.


### 2. Identity, certificates and mTLS

| # | The sentence | Held by |
|---|---|---|
| `2.#1` | When both proofs are present their leaf keys MUST match, else `envelope_invalid`. | `scenario:Mallory seals with Alina's chain inside and her own signature` |

### 2.1 Deriving the root from a passkey

| # | The sentence | Held by |
|---|---|---|
| `2.1#1` | A wallet that can use a WebAuthn credential MUST **derive the root's private key from one** rather than generate and store it; a wallet that cannot — a command-line tool — generates the key and keeps it as §9 says. | *wallet, by declaration* |
| `2.1#2` | A wallet MUST use exactly these values. | `rust:derivation_vectors`, `go:TestDerivationVectors`, `rust:derivation_refuses_what_would_silently_differ`, `go:TestDerivationRefusesWhatWouldSilentlyDiffer` |
| `2.1#3` | A wallet MUST NOT present this as a guarantee: whether a given provider carries the PRF secret across its own sync is that provider's property and not the protocol's, and a wallet that has not verified it SHOULD say so rather than imply otherwise. | *wallet, by declaration* |
| `2.1#4` | A wallet holding more than one credential for its origin MUST name the intended credential when it knows which one that is, and MUST prove the derived root before signing (§2.2). | `rust:a_vault_entry_that_disagrees_with_its_own_certificate_signs_nothing`, `go:TestVaultRulesMirrorTheCore` |
| `2.1#5` | A wallet that derives its root MUST still be able to export it (§9). | `rust:issues_from_the_vault`, `go:TestVault` |

### 2.2 Proving a root before using it

| # | The sentence | Held by |
|---|---|---|
| `2.2#1` | Before issuing any certificate, a wallet MUST establish that the root it is about to sign with is the root the identity already has. | `rust:a_vault_entry_that_disagrees_with_its_own_certificate_signs_nothing`, `go:TestVaultRulesMirrorTheCore` |
| `2.2#2` | A wallet MUST refuse to sign unless all three hold: | `rust:a_card_whose_certificate_and_key_disagree_gets_no_leaf`, `rust:another_card_signs_nothing_for_this_identity`, `rust:a_card_that_swaps_its_key_after_the_check_signs_nothing_that_is_kept` |
| `2.2#3` | The challenge MUST be domain-separated from certificate bytes — the ASCII `PACT root proof v1` followed by a newline and at least 32 random bytes — so that proving possession can never be made to sign a certificate. | *wallet, by declaration* |
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
| `4.#1` | The same URL serves two audiences by content negotiation: a browser gets the human landing page; a client sending `Accept: application/pact-invite+json` (or appending `?format=json`) gets `{"card","card_sig","chain"}` — the signed card and the issuer's chain (§2), whose leaf MUST byte-equal the card's `X-PACT-CERT` and which the redeemer MUST validate (§14.2) before use, so it can seal its very first call. | `gateway:TestLandingNoOracle404` |

### 5.2 Manual flow (vCard shared over existing channels)

| # | The sentence | Held by |
|---|---|---|
| `5.2#1` | "pending"}` any stranger gets, while nothing is recorded and the owner is never bothered: blocked MUST be indistinguishable from never-met (§12). | `scenario:a blocked sender is answered exactly as an unknown one`, `scenario:a blocked contact naming its leaf is answered as a stranger would be` |

### 6.1 Tiers

| # | The sentence | Held by |
|---|---|---|
| `6.1#1` | A caller at the pending tier MAY list its tools: its `tools/list` MUST answer at the pending tier, naming `contact_accepted` and `contact_rejected`, and every other call from it MUST answer `pending_approval` until the owner decides. | `scenario:a contact still pending_out lists the pending tier (baseline)`, `scenario:a contact still pending_out cannot message before accepting`, `rust:a_pending_contacts_sealed_listing_answers_at_the_pending_tier`, `go:TestAPendingContactsSealedListingAnswersAtThePendingTier` |

### 6.2 Core tools

| # | The sentence | Held by |
|---|---|---|
| `6.2#1` | A `msg_id` MUST be a non-empty string — idempotency keyed on nothing protects nothing. | `scenario:an empty msg_id` |
| `6.2#2` | `ok` — a card refresh, or `status: pending` from a new address under `ask` (§5.3). The caller's chain is the authority: the card's certificate MUST equal the chain's leaf, and a card that names another root or carries a certificate that is not that leaf MUST be refused `bad_request`, the card-intake code of §3 | `scenario:a guest whose card carries a different certificate than the chain`, `gateway:TestACardThatDisagreesWithTheProofIsABadRequest` |
| `6.2#3` | `get_status` answers from that fixed four-value vocabulary; an implementation whose upstream presence source knows richer states MUST map any state not listed to `busy`. | `gateway:TestOwnerPresenceTracksLiveSessionsOnly` |

### 9. Hosting

| # | The sentence | Held by |
|---|---|---|
| `9.#1` | A leaf's key does not outlive its leaf: a host MUST stop using the key of a leaf that has expired and MUST destroy it, keeping the key id so that an envelope still sealed to it is answered `certificate_renewed` (§14.4) — past its date every verifier refuses the leaf (§14.2 rule 4), so the key can do nothing legitimate, and a renewal has never needed it. | `gateway:TestAnExpiredCurrentLeafLosesItsKeyInBothPlaces`, `gateway:TestALeafThatRunsOutStopsBeingServedAndLosesItsKey` |
| `9.#2` | **Moving** is the person issuing a leaf to the new host, the data carried across as an archive — the person's contacts and their conversations, with the media in them, and nothing that is the host's own: no settings, no credentials, no invites, no record of the host's leaves; an archive is the export of §9.2, a host that makes one MUST NOT put key material of any kind in it, and a host that imports one MUST refuse any key material in it and MUST refuse, rather than ignore, anything else it does not recognise — and the new host reaching every contact by §5.3, *before* the person tells the old host to leave, so that no contact meets a gap. | `rust:read_export_answers_the_whole_corpus`, `go:TestReadExportZipAnswersTheWholeCorpus`, `rust:export_write_refuses_a_row_or_message_holding_a_private_key`, `go:TestAFileThatIsAKeyLeavesWithItsMessageAndIsRefusedOnRead`, `go:TestWriteExportZipRefusesWhatItsReaderRefusesBeforeTheFirstByte`, `rust:what_a_contact_controls_never_stops_an_export_and_it_reads_back`, `go:TestWhatAContactControlsNeverStopsAnExportAndItReadsBack` |
| `9.#3` | An address an identity has vacated MUST NOT be assigned to another identity until the last leaf issued for it has expired, so a contact that missed the move never reaches a stranger where it expects a friend. | *node, by declaration* |
| `9.#4` | A host that exports an identity toward a destination that cannot carry its chain MUST say so before the export; the remedy is a destination that can. | *node, by declaration* |
| `9.#5` | It issues one live leaf per identity at a time — a second endpoint is a move, not a second home, because contacts keep one pin and the newest leaf wins — and MUST NOT issue a second while one is live except as its replacement. | `rust:issues_from_the_vault`, `go:TestWalletIssue`, `go:TestVaultRulesMirrorTheCore`, `rust:ledger_check_names_each_kind_and_refuses_only_a_second_home`, `go:TestLedgerCheckNamesEachKindAndRefusesOnlyASecondHome`, `rust:ledger_check_takes_the_newest_leaf_and_not_the_newest_unexpired_one`, `go:TestLedgerCheckTakesTheNewestLeafAndNotTheNewestUnexpiredOne`, `rust:a_card_held_root_is_held_to_the_ledger_by_the_core` |
| `9.#6` | A wallet MUST NOT write a leaf, a ledger entry or a contact into the file, and writes it once, when the root is made, and again only when the root is re-bound or a hardware key takes it. | `rust:a_host_key_a_request_an_identity_a_leaf_and_a_chain_that_validates`, `rust:issues_from_the_vault` |

### 9.1 Signing requests

| # | The sentence | Held by |
|---|---|---|
| `9.1#1` | A wallet MUST refuse a request that is not a top-level navigation, as the browser's fetch metadata reports it (`Sec-Fetch-Mode: navigate`, `Sec-Fetch-Dest: document`), so that a script on another page cannot probe it. | *wallet, by declaration* |
| `9.1#2` | A wallet MUST refuse a request whose `Origin` is absent, `null`, or different from the origin of `redirect`: the host that asks is the host that collects. | `rust:signing_request_check_passes_one_request_and_refuses_one_per_rule`, `go:TestSigningRequestCheckPassesOneRequestAndRefusesOnePerRule`, `rust:redirect_allowed_is_https_or_http_to_loopback_only`, `go:TestRedirectAllowedIsHTTPSOrHTTPToLoopbackOnly` |
| `9.1#3` | A wallet MUST refuse a request with a field the table above does not list, a field that is not a string, or a field that breaks the table, and a request that has expired or expires more than ten minutes ahead. | `rust:signing_request_check_passes_one_request_and_refuses_one_per_rule`, `go:TestSigningRequestCheckPassesOneRequestAndRefusesOnePerRule`, `rust:redirect_allowed_is_https_or_http_to_loopback_only`, `go:TestRedirectAllowedIsHTTPSOrHTTPToLoopbackOnly`, `rust:instants_have_one_grammar`, `go:TestInstantsHaveOneGrammar` |
| `9.1#4` | A wallet MUST refuse a request whose CSR fails the checks of §9 — its own signature, and a key that is not a root — or names an endpoint that is not in the normal form of §14.1 or fails the address guard of §3. | `rust:signing_request_check_passes_one_request_and_refuses_one_per_rule`, `go:TestSigningRequestCheckPassesOneRequestAndRefusesOnePerRule` |
| `9.1#5` | A wallet MUST prove the root against `expect_root` (§2.2) before it signs. | *wallet, by declaration* |
| `9.1#6` | It MUST show the person the asking origin, the `recipient` as the host's own claim, the endpoint, the validity and whether the host is new. | *wallet, by declaration* |
| `9.1#7` | The wallet MUST NOT keep anything of the request once it has answered, and MUST NOT write its body to a log. | *wallet, by declaration* |
| `9.1#8` | A host MUST accept an answer only once, only with the `state` it minted for a pending request, and only a chain whose leaf carries that request's key and validates at its endpoint (§14.2). | `gateway:TestAWebWalletsAnswerIsAcceptedOnceAndOnlyWithItsState`, `gateway:TestTheStateIsConsumedByTheStatementThatChecksIt` |

### 9.2 The export

| # | The sentence | Held by |
|---|---|---|
| `9.2#1` | An exporter MUST NOT leave out a media file it holds for a message it exports: a file it cannot include is a reason to refuse the export, never to omit the file. | `go:TestWriteExportZipRefusesRatherThanOmitsAFile` |
| `9.2#2` | **Spreadsheet formulas.** A writer MUST write a CSV cell that begins with `=`, `+`, `-`, `@`, `'`, a tab or a carriage return with one `'` before it, and a reader strips one leading `'`. base64url DER cannot begin that way: it starts with `M`, from its first byte `0x30`. | `rust:csv_writes_what_it_reads_back_and_guards_every_formula_prefix`, `go:TestCSVWritesWhatItReadsBackAndGuardsEveryFormulaPrefix` |
| `9.2#3` | **Unencrypted.** Every surface that writes an export MUST tell the person, before the file is written, that it is not encrypted, that anyone who gets it can read their contact list and all their conversations and files, and that it holds no keys, so it cannot be used to speak as them. | `rust:a_host_key_a_request_an_identity_a_leaf_and_a_chain_that_validates` |
| `9.2#4` | A host that delivers an export over a network MUST NOT keep it at rest: it builds the file when the signed-in person asks and streams it to them. | *host, by declaration* |
| `9.2#5` | **Validation.** An importer MUST check the whole file before it writes anything, and MUST refuse the whole file if any check below fails: | `rust:read_export_answers_the_whole_corpus`, `go:TestReadExportZipAnswersTheWholeCorpus` |
| `9.2#6` | An importer MUST refuse any entry whose name is not exactly `manifest.json`, `contacts.csv`, `threads.csv`, `messages.jsonl`, `media/`, or `media/` followed by 64 lowercase hex digits — so no `..`, no absolute path, no backslash and no other file — and it MUST read the zip's central directory as the only index | `rust:read_export_answers_the_whole_corpus`, `go:TestReadExportZipAnswersTheWholeCorpus` |
| `9.2#7` | An importer MUST refuse a file in which one name appears twice | `rust:read_export_answers_the_whole_corpus`, `go:TestReadExportZipAnswersTheWholeCorpus` |
| `9.2#8` | An importer MUST refuse a file that lacks a member; a file MAY omit `threads.csv`, `messages.jsonl` and `media/` only when its manifest counts them zero, which is what a book does | `rust:read_export_answers_the_whole_corpus`, `go:TestReadExportZipAnswersTheWholeCorpus` |
| `9.2#9` | An importer MUST refuse an encrypted entry, a symbolic link (a Unix mode in the external attributes), and any directory but `media/` | `rust:read_export_answers_the_whole_corpus`, `go:TestReadExportZipAnswersTheWholeCorpus` |
| `9.2#10` | An importer MUST count sizes by the bytes it actually decompresses, never by the sizes a header states, and MUST refuse a manifest over 64 KiB, a `contacts.csv` over 4 MiB or 5000 rows, a `threads.csv` over 16 MiB, a line of `messages.jsonl` over 64 KiB, a media file over 5 MiB, and anything over a ceiling of the host's own (below) | `rust:read_export_answers_the_whole_corpus`, `go:TestReadExportZipAnswersTheWholeCorpus`, `go:TestAnExportWrittenIsReadBackWhole`, `rust:the_contracts_export_limits_are_the_cores_constants`, `go:TestTheContractsExportLimitsAreThePortsConstants` |
| `9.2#11` | An importer MUST refuse a text member that `manifest.files` does not list or whose sha256 differs from it, a listed member the file lacks, a `files` entry that names anything but a text member, a media member whose name is not the lowercase hex sha256 of its bytes, and counts that differ from what the file holds — `counts.media` included, which is the number of media members | `rust:read_export_answers_the_whole_corpus`, `go:TestReadExportZipAnswersTheWholeCorpus` |
| `9.2#12` | An importer MUST refuse a file whose `owner` is not the root of the identity importing it, and a contact row whose `root` is `owner` | `rust:read_export_answers_the_whole_corpus`, `go:TestReadExportZipAnswersTheWholeCorpus` |
| `9.2#13` | An importer MUST refuse a header that is not exactly the one shown, a row or a message that breaks what its column or member holds above, a message with a member not listed or one missing, and a message with more than one attachment, a message that carries an attachment and a `body` that is not empty, and a time that is not an RFC 3339 instant in UTC ending in `Z`, or whose fraction follows anything but a `.` | `rust:read_export_answers_the_whole_corpus`, `go:TestReadExportZipAnswersTheWholeCorpus`, `go:TestAMessageCarriesAtMostOneFile`, `rust:instants_have_one_grammar`, `go:TestInstantsHaveOneGrammar` |
| `9.2#14` | An importer MUST refuse a thread whose `contact`, a message whose `thread`, `contact` or non-null `reply_to`, or an attachment whose `file` names nothing in the file, and a media file that nothing names | `rust:read_export_answers_the_whole_corpus`, `go:TestReadExportZipAnswersTheWholeCorpus` |
| `9.2#15` | An importer MUST refuse any cell, any string member of the manifest or of a message, and any media file that decodes as a private key — PKCS #8 or SEC1, in DER or PEM — and MUST parse a certificate only as a certificate of §14.1's profile | `rust:read_export_answers_the_whole_corpus`, `go:TestReadExportZipAnswersTheWholeCorpus`, `rust:export_write_refuses_a_row_or_message_holding_a_private_key`, `go:TestAFileThatIsAKeyLeavesWithItsMessageAndIsRefusedOnRead`, `rust:a_media_file_is_key_material_in_der_or_pem`, `go:TestAMediaFileIsKeyMaterialInDEROrPEM` |
| `9.2#16` | It MUST show the person the contacts, and write nothing until the person agrees. | *host, by declaration* |
| `9.2#17` | An imported leaf MUST NOT replace a pin the host validated itself, and a row's `leaf` is pinned only when `[leaf, root_cert]` validates at the row's `endpoint` (§14.2). | `rust:export_merge_never_replaces_a_held_pin`, `go:TestExportMergeNeverReplacesAHeldPin`, `rust:read_export_answers_the_whole_corpus`, `go:TestReadExportZipAnswersTheWholeCorpus` |
| `9.2#18` | A host MUST NOT send a message it imported, whatever its `status`: retries belonged to the host that exported it. | *host, by declaration* |
| `9.2#19` | The import MUST end with a request for a new leaf for the importing endpoint, which the host mints itself with `expect_root` equal to `owner` — `move` for an identity new to the host, `renew` for one it already serves — and which the person completes in their wallet (§9.1). | `gateway:TestFirstLeafAfterADataOnlyImport`, `gateway:TestAnImportedSlugHoldsOnlyItsRootUntilTheFirstChainInstalls` |
| `9.2#20` | Once that leaf is installed, the host MUST call `update_contact` at every imported contact that is not blocked and whose leaf it holds (step 2), since a contact whose leaf it does not hold cannot be sealed to, and MUST report every other contact that is not blocked as unreached, without retrying it; that contact stays pinned by its root. | `gateway:TestAfterAnImportTheNextLeafHandshakesEveryImportedContact`, `gateway:TestTheCampaignWalksAnImportsContactsOnceAndNeverABlockedOne` |
| `9.2#21` | A contact that refuses the call — `update_contact` is a contact-tier tool, and that contact does not hold the identity as one — MUST then be sent `request_contact`, which that contact decides under its own policy. | `gateway:TestAfterAnImportTheNextLeafHandshakesEveryImportedContact`, `gateway:TestTheCampaignWalksAnImportsContactsOnceAndNeverABlockedOne` |
| `9.2#22` | A writer MUST write `reply_to` as `null` when the message it names is not in the file. | `rust:what_a_contact_controls_never_stops_an_export_and_it_reads_back`, `go:TestWhatAContactControlsNeverStopsAnExportAndItReadsBack` |
| `9.2#23` | A writer MUST drop from `their_permissions` every name that is not a permission of §8 and every name repeated, since the column is informative. | `rust:what_a_contact_controls_never_stops_an_export_and_it_reads_back`, `go:TestWhatAContactControlsNeverStopsAnExportAndItReadsBack` |
| `9.2#24` | A writer MUST truncate `display_name` to 200 characters, since it is the contact's own claim. | `rust:what_a_contact_controls_never_stops_an_export_and_it_reads_back`, `go:TestWhatAContactControlsNeverStopsAnExportAndItReadsBack` |
| `9.2#25` | A writer MUST leave out a message whose `body`, or whose media file, the key-material check above would refuse, with the attachment it carried, and MUST list each message it leaves out, by its `id` and the reason, in the report it gives the person; it never leaves one out silently. | `rust:what_a_contact_controls_never_stops_an_export_and_it_reads_back`, `go:TestWhatAContactControlsNeverStopsAnExportAndItReadsBack`, `go:TestAFileThatIsAKeyLeavesWithItsMessageAndIsRefusedOnRead` |
| `9.2#26` | **Ceilings.** A host MAY set import ceilings of its own, on the whole file and on counts — contacts, threads, lines of `messages.jsonl`, the characters of an `id` — and MUST name the ceiling in each refusal it makes for one. | *host, by declaration* |
| `9.2#27` | A host MUST NOT refuse to write an export because the file would exceed an import ceiling of its own, of any kind, the whole-file ceiling included; it MAY warn the person that the file exceeds them, naming each. | *host, by declaration* |
| `9.2#28` | **The owner's own strings.** A writer MUST refuse to write a manifest whose `owner_name` or `tool` the key-material check above would refuse, naming the member: those are the owner's and the host's own, not a contact's, so there is nothing to leave out. | `rust:export_write_refuses_a_row_or_message_holding_a_private_key`, `go:TestWriteExportZipRefusesWhatItsReaderRefusesBeforeTheFirstByte` |

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

## The 727 cross-port parity cases

Each case feeds one argument shape to both the Rust core (through its WebAssembly bindings) and
the Go port and compares the whole answer — code, shape and `why` string. A function marked
*whole on success* has at least one case whose successful answer is compared member by member,
which is the only kind that notices a member going missing; a refusal compared whole proves both
ports refuse alike. `js/parity.mjs` fails if any guarded function lacks either.

At the run that generated this file: **727** cases, **0** disagreements, **48** of **48** functions compared whole on success.

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

### `book_rows` — 8 cases · whole on success

- book_rows: a contact with everything, one with the least
- book_rows: an empty book
- book_rows: a contact with a member a book does not keep
- book_rows: a contact with no endpoint
- book_rows: a name that is not a string
- book_rows: a contact that is not an object
- book_rows with nothing to work from
- book_rows with an exported_at that does not read

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

- card_decode of a real card
- card_decode of an empty card
- card_decode of nothing at all
- card_decode of a 1.x card
- card_decode of a card with two certificates
- card_decode of a card whose certificate is not one
- card_decode after the leaf expired
- card_decode of a card carrying that leaf
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

### `export_manifest` — 7 cases · whole on success

- export_manifest: finished with the messages
- export_manifest: a book
- export_manifest with no partial
- export_manifest: messages without their hash
- export_manifest: a hash the host does not make
- export_manifest: a partial that already counts messages
- export_manifest: 5000 media files, the manifest under 64 KiB

### `export_merge` — 3 cases · whole on success

- export_merge: a held pin is never replaced
- export_merge with rows whose root is no fingerprint
- export_merge: a held blocked contact keeps what the person decided

### `export_read` — 60 cases · whole on success

- export_read: what export_write wrote
- export corpus valid-export.zip: export_read
- export corpus valid-book.zip: export_read
- export corpus local-names-differ.zip: export_read
- export corpus zip-slip.zip: export_read
- export corpus absolute-path.zip: export_read
- export corpus backslash.zip: export_read
- export corpus unknown-file.zip: export_read
- export corpus duplicate-name.zip: export_read
- export corpus encrypted-entry.zip: export_read
- export corpus symlink.zip: export_read
- export corpus directory.zip: export_read
- export corpus oversize-manifest.zip: export_read
- export corpus missing-contacts.zip: export_read
- export corpus missing-threads.zip: export_read
- export corpus unlisted-member.zip: export_read
- export corpus hash-mismatch.zip: export_read
- export corpus media-listed-in-files.zip: export_read
- export corpus count-mismatch.zip: export_read
- export corpus wrong-owner.zip: export_read
- export corpus owner-as-contact.zip: export_read
- export corpus bad-header.zip: export_read
- export corpus blank-row.zip: export_read
- export corpus key-in-a-cell.zip: export_read
- export corpus dangling-thread-contact.zip: export_read
- export corpus contacts-over-4-mib.zip: export_read
- export corpus contacts-over-5000-rows.zip: export_read
- export corpus threads-over-16-mib.zip: export_read
- export corpus media-over-5-mib.zip: export_read
- export corpus root-cert-not-a-root.zip: export_read
- export_read: what a contact controls, as written, reads back
- export_read with nothing to work from
- export_read with a directory entry that does not read
- export_read: contacts.csv stated over 4 MiB
- export_read: contacts.csv over 4 MiB though its entry says less
- export_read: contacts.csv of 5001 rows
- export_read: threads.csv over 16 MiB though its entry says less
- export_read: a media file stated over 5 MiB
- export_read: a contact whose status is not one of the three
- export_read: a contact whose endpoint is plain http
- export_read: a contact whose endpoint is not in normal form
- export_read: a contact whose added is not an instant
- export_read: a contact granted a permission §8 does not name
- export_read: a contact whose name is over 200 characters
- export_read: a contact whose root_cert is a leaf
- export_read: a contact whose root_cert is another identity's root
- export_read: a manifest with a member it does not hold
- export_read: a contact added at an instant with a lower-case z
- export_read: a thread created at an instant with a lower-case z
- export_read: a manifest exported at an instant with a lower-case z
- export_read: a contact added at an instant with a lower-case t
- export_read: a thread created at an instant with a lower-case t
- export_read: a manifest exported at an instant with a lower-case t
- export_read: a contact added at an instant with a comma before the fraction
- export_read: a thread created at an instant with a comma before the fraction
- export_read: a manifest exported at an instant with a comma before the fraction
- export_read: a contact added at an instant with an offset
- export_read: a thread created at an instant with an offset
- export_read: a manifest exported at an instant with an offset
- export_read: instants in the one grammar, a fraction included

### `export_read_end` — 28 cases · whole on success

- export_read_end: what was written
- export corpus valid-export.zip: export_read_end
- export corpus valid-book.zip: export_read_end
- export corpus local-names-differ.zip: export_read_end
- export corpus dangling-reply.zip: export_read_end
- export corpus unreferenced-media.zip: export_read_end
- export corpus message-count.zip: export_read_end
- export corpus messages-hash.zip: export_read_end
- export_read_end: a manifest with a lone surrogate escape
- export_read_end: a manifest with a surrogate pair
- export_read_end: a manifest with a count of -0
- export_read_end with ids holding null
- export_read_end with ids holding a number
- export_read_end with ids holding a list
- export_read_end with ids given as null
- export_read_end with ids given as a string
- export_read_end with no ids at all
- export_read_end with ids that hold the word null and an escaped quote
- export_read_end with msg_ids holding an object
- export_read_end with a manifest given as a number
- export_read_end with lines given as text
- export_read_end with media holding a number
- export_read_end with no media at all
- export_read_end: what a contact controls, as written, reads back
- export_read_end with nothing to work from
- export_read_end: a manifest whose owner_name is a private key
- export_read_end: a manifest whose tool is a private key
- export_read_end: a manifest that lists a media member in files

### `export_read_messages` — 25 cases · whole on success

- export_read_messages: what export_write_messages wrote
- export corpus valid-export.zip: export_read_messages
- export corpus valid-book.zip: export_read_messages
- export corpus local-names-differ.zip: export_read_messages
- export corpus dangling-message-thread.zip: export_read_messages
- export corpus dangling-attachment.zip: export_read_messages
- export corpus two-attachments.zip: export_read_messages
- export corpus body-with-a-file.zip: export_read_messages
- export corpus key-in-a-body.zip: export_read_messages
- export corpus unknown-message-member.zip: export_read_messages
- export_read_messages: a line with a lone low surrogate escape
- export_read_messages: a line with a surrogate pair
- export_read_messages: what a contact controls, as written, reads back
- export_read_messages with nothing to work from
- export_read_messages from line 0
- export_read_messages: a message whose direction is neither
- export_read_messages: a message whose sender is neither
- export_read_messages: a message whose status is not one of the four
- export_read_messages: a message whose body is over 16 KiB
- export_read_messages: a message missing a member
- export_read_messages: the valid export's lines
- export_read_messages: a message time with a lower-case z
- export_read_messages: a message time with a lower-case t
- export_read_messages: a message time with a comma before the fraction
- export_read_messages: a message time with an offset

### `export_write` — 17 cases · whole on success

- export_write: every formula prefix, quoting and line breaks, sorted rows
- export_write: a book
- export_write: a 300-character display name and permissions §8 does not have
- export_write: the rows book_rows made
- export_write with nothing to work from
- export_write: the owner as a contact
- export_write: a permission §8 does not name
- export_write: a private endpoint
- export_write: a thread whose contact is in no row
- export_write: a private key as the owner_name
- export_write: a private key as the tool
- export_write: 5000 media files
- export_write: an exported_at with a lower-case z
- export_write: a contact added with a lower-case z
- export_write: an exported_at with a comma before the fraction
- export_write: a contact added with a comma before the fraction
- export_write: instants in the one grammar, a fraction included

### `export_write_messages` — 8 cases · whole on success

- export_write_messages: a text, a file and a link
- export_write_messages: a dangling reply, a key in a body, a reply to what was left out
- export_write_messages: in batches, the file names its msg_ids
- export_write_messages: msg_ids that are not strings
- export_write_messages: two attachments
- export_write_messages: text beside a file
- export_write_messages: a message time with a lower-case z
- export_write_messages: a message time with a comma before the fraction

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

### `is_normal_https` — 28 cases · whole on success

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
- is_normal_https with args holding a lone low surrogate
- is_normal_https with args holding a surrogate pair

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

### `ledger_check` — 33 cases · whole on success

- ledger_check: a renewal where the live leaf is
- ledger_check: a move, not chosen
- ledger_check: a move, chosen
- ledger_check: back to an endpoint issued to before, not chosen
- ledger_check: back to an endpoint issued to before, chosen
- ledger_check: an empty ledger
- ledger_check: an entry whose not_before has an offset
- ledger_check: a now with an offset
- ledger_check: a now with a lower-case z
- ledger_check: no ledger at all
- ledger_check: a ledger given as null
- ledger_check: after the live leaf expired, a new endpoint
- ledger_check: after the live leaf expired, the same endpoint
- ledger_check: another root's live leaf is not this root's
- ledger_check: the newest leaf expired, an older one did not
- ledger_check: an entry whose root is empty
- ledger_check: an entry whose root is no fingerprint
- ledger_check: an entry whose endpoint is empty
- ledger_check: an entry whose not_before does not read
- ledger_check: an entry whose not_after does not read
- ledger_check: an entry with no endpoint
- ledger_check: an entry carrying the leaf
- ledger_check: an entry that is not an object
- ledger_check: a ledger that is not a list
- ledger_check with no root
- ledger_check with an empty root
- ledger_check with no endpoint
- ledger_check with an endpoint not in normal form
- ledger_check with no now
- ledger_check with a now that does not read
- ledger_check with a move that is not a boolean
- ledger_check with nothing to work from
- ledger_check over a ledger that reads

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

### `signing_request_check` — 75 cases · whole on success

- signing_request_check: a renewal from a localhost node
- signing_request_check: a move from an https host, without root_cert
- signing_request_check: a redirect to 127.0.0.2 over http
- signing_request_check: a redirect to [::1] over http
- signing_request_check: a redirect to an https default port written out
- signing_request_check: a redirect to an http default port written out
- signing_request_check: a redirect to no path at all
- signing_request_check: expiring exactly ten minutes ahead
- signing_request_check: 398 days, and a 200-character recipient
- signing_request_check: a member a request does not carry
- signing_request_check: valid_days as a number
- signing_request_check: a csr over its bound
- signing_request_check: a redirect over its bound
- signing_request_check: a recipient of 201 characters
- signing_request_check: an empty recipient
- signing_request_check: no origin
- signing_request_check: an origin of null
- signing_request_check: an origin that is not the redirect's
- signing_request_check: an origin written with its default port
- signing_request_check: a redirect over http to a public host
- signing_request_check: a redirect over http to a private address
- signing_request_check: a redirect over http to 127.1
- signing_request_check: a redirect over http to 127.000.0.1
- signing_request_check: a redirect over http to [::2]
- signing_request_check: a redirect over http to a name under localhost
- signing_request_check: a javascript: redirect
- signing_request_check: a relative redirect
- signing_request_check: a redirect with a fragment
- signing_request_check: a redirect with userinfo
- signing_request_check: a redirect with a space
- signing_request_check: a redirect with a backslash
- signing_request_check: a redirect whose host is upper case
- signing_request_check: a redirect with port 0
- signing_request_check: a redirect with a port with a leading zero
- signing_request_check: a redirect with port 65536
- signing_request_check: an expired request
- signing_request_check: a request expiring now
- signing_request_check: a request expiring more than ten minutes ahead
- signing_request_check: an expiry with an offset
- signing_request_check: an expiry that does not read
- signing_request_check: an expiry with a lower-case z
- signing_request_check: an expiry with a comma before its fraction
- signing_request_check: an expiry with a lower-case t
- signing_request_check: a redirect to upper-case IPv6 hex
- signing_request_check: a redirect whose host has an empty label
- signing_request_check: a redirect whose host begins with a dot
- signing_request_check: a redirect whose host ends with a dot
- signing_request_check: a signup
- signing_request_check: valid_days of 0
- signing_request_check: valid_days of 399
- signing_request_check: valid_days with a leading zero
- signing_request_check: valid_days of -1
- signing_request_check: a state of 31 bytes
- signing_request_check: a state outside base64url
- signing_request_check: an expect_root that is no fingerprint
- signing_request_check: a root_cert outside base64url
- signing_request_check: a root_cert that is no certificate
- signing_request_check: a root_cert that is a leaf
- signing_request_check: another identity's root_cert
- signing_request_check: a csr outside base64url
- signing_request_check: a csr carrying the root's own key
- signing_request_check: no csr
- signing_request_check: no purpose
- signing_request_check: no expect_root
- signing_request_check: no redirect
- signing_request_check: no state
- signing_request_check: no valid_days
- signing_request_check: no expires
- signing_request_check: a csr that is not a request
- signing_request_check with no request
- signing_request_check with a request that is a string
- signing_request_check with no origin
- signing_request_check with no now
- signing_request_check with root_spkis that do not read
- signing_request_check with nothing to work from

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

### `vault_seal` — 18 cases · whole on success

- vault_seal
- vault_seal of a record
- vault_seal of an earlier generation
- vault_seal of a plaintext with no generation
- vault_seal with a nonce that is not 12 bytes
- vault_seal with an empty passphrase
- vault_seal with no plaintext
- vault_seal with a KDF one pass over the ceiling
- vault_seal with a KDF below the floor
- vault_seal with a KDF whose m_kib does not fit in 32 bits
- vault_seal with a KDF with no passes
- vault_seal with a KDF with too many lanes
- vault_seal with a KDF nobody implements
- vault_seal with no passphrase
- vault_seal with a passphrase that is not a string
- vault_seal of an earlier generation under a KDF out of range
- vault_seal of a plaintext that is a string
- vault_seal with nothing to work from

### `verify` — 5 cases · whole on success

- verify a signature that is not one
- verify with an empty signature
- verify with nothing to work from
- verify a signature the other port made
- verify with args holding a lone high surrogate

### `wallet_issue` — 36 cases · whole on success

- wallet_issue
- wallet_issue from a vault that carries a ledger
- wallet_issue without a record
- wallet_issue for a root the vault does not hold
- wallet_issue of the root's own key
- wallet_issue for a second address
- wallet_issue as a move
- wallet_issue with an empty vault
- wallet_issue with no root_fingerprint
- wallet_issue with a root_fingerprint that is not a string
- wallet_issue with no csr
- wallet_issue with no now
- wallet_issue with a now that does not read
- wallet_issue with valid_days as a string
- wallet_issue with valid_days of 0
- wallet_issue with valid_days of 999
- wallet_issue with a vault that is a string
- wallet_issue with a vault of an earlier generation
- wallet_issue with a vault with a member it does not hold
- wallet_issue with a record that is a string
- wallet_issue with a record that is a list
- wallet_issue with a record of an earlier generation
- wallet_issue with a record with a member it does not hold
- wallet_issue with a record whose ledger is not a list
- wallet_issue with a ledger entry with no endpoint
- wallet_issue with a ledger entry whose not_before does not read
- wallet_issue with a ledger entry whose not_after does not read
- wallet_issue with a ledger entry whose root is not a string
- wallet_issue with a ledger entry carrying the leaf
- wallet_issue with a ledger entry that is not an object
- wallet_issue with a ledger entry whose root is empty
- wallet_issue with a ledger entry whose endpoint is empty
- wallet_issue with a root held on a card, which this function cannot sign with
- wallet_issue over a ledger that reads
- wallet_issue with nothing to work from
- wallet_issue: a request carrying a CARD-held sibling root's key
