# What is proven, and by what

**Generated — do not edit.** `node js/record.mjs` rewrites this file; `node js/record.mjs --check`
regenerates and fails on any difference, which is what gate.sh runs. Both lists come from the things
that prove them rather than from prose beside them: the MUSTs from `pact-protocol/SPEC.md` through
the same extractor `js/musts.mjs` uses, with holders from `js/musts.json`; the parity cases from
`js/parity.mjs --manifest`, which writes its manifest only after the comparison agreed — so no
case can be listed as proven that did not pass. The cases that fail today are listed apart, at the
end, each with the finding it waits on.

Specification: **2.2.4**. **88** normative sentences, **2145** cross-port parity cases over **50** guarded functions, and **3** known divergences that fail today and are listed apart, at the end.

Every answer of both ports is validated against `contract/contract.json` (**51** functions, spec 2.2.4): **4296** answers, of which **2** do not hold to the shape it declares — **2** of them in a known divergence. Of **117** declared error codes, **117** were produced by both ports in a case they answered alike; `js/parity.mjs` fails when a declared code is not.

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
| `2.2#1` | Before issuing any certificate, a wallet MUST establish that the root it is about to sign with is the root the identity already has. | `rust:a_vault_entry_that_disagrees_with_its_own_certificate_signs_nothing` — *and a named gap: a part nothing holds (js/musts.json)* |
| `2.2#2` | A wallet MUST refuse to sign unless all three hold: | `rust:a_card_whose_certificate_and_key_disagree_gets_no_leaf`, `rust:another_card_signs_nothing_for_this_identity`, `rust:a_card_that_swaps_its_key_after_the_check_signs_nothing_that_is_kept` — *and a named gap: a part nothing holds (js/musts.json)* |
| `2.2#3` | The challenge MUST be domain-separated from certificate bytes — the ASCII `PACT root proof v1` followed by a newline and at least 32 random bytes — so that proving possession can never be made to sign a certificate. | *wallet, by declaration* |
| `2.2#4` | A wallet MUST validate a chain it has assembled (§14.2) against the expected root and endpoint before returning it. | `rust:a_leaf_the_card_signed_validates_to_that_root_at_its_endpoint` — *and a named gap: a part nothing holds (js/musts.json)* |
| `2.2#5` | **A root certificate is issued once.** A wallet MUST NOT rebuild a root certificate for an identity that already has one. | `rust:a_root_the_card_signed_is_a_root` |

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
| `9.2#3` | **Unencrypted.** Every surface that writes an export MUST tell the person, before the file is written, that it is not encrypted, that anyone who gets it can read what it holds — their contact list and all their conversations and files for a full export, their contact list for a book — and that it holds no keys, so it cannot be used to speak as them. | `rust:a_host_key_a_request_an_identity_a_leaf_and_a_chain_that_validates` |
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
| `13.1#1` | base64url HPKE encapsulated key, of exactly the suite's `Npk` (RFC 9180 §7.1): 65 bytes for `PACT-SEAL-P256`, an uncompressed P-256 point, and 32 for `PACT-SEAL-X25519`. A receiver MUST refuse any other length (`envelope_invalid`) — `sig` covers the three members concatenated with nothing between them, so the suite's own length is what fixes the boundary; without it a byte moved from the end of `enc` to the front of `ct` leaves the signed bytes identical | `scenario:a byte moved from the encapsulated key into the ciphertext`, `rust:an_encapsulated_key_of_the_wrong_length_is_refused_under_each_suite`, `go:TestAnEncapsulatedKeyOfTheWrongLengthIsRefused` |
| `13.1#2` | Each of the four members is base64url (RFC 4648 §5) without padding, in its one canonical spelling, and a receiver MUST refuse (`envelope_invalid`) a member written any other way: with a character outside that alphabet — padding, whitespace and the standard alphabet's `+` and `/` among them — or with a last character whose unused bits are not zero. | `scenario:a real envelope whose protected carries a stray character`, `scenario:a real envelope whose enc is padded`, `scenario:a real envelope whose ct has a line break in it`, `scenario:a real envelope whose signature is spelled with its spare bits set` |
| `13.1#3` | The suite follows the recipient's key and nothing else: a receiver MUST refuse an envelope whose `suite` is not the one its key takes (`envelope_invalid`), so no choice is left on the wire for a sender to make badly. | `scenario:the wrong suite for the recipient's key` |
| `13.1#4` | The HPKE `info` parameter is the ASCII string `PACT-SEAL-v2`, and an envelope sealed under any other info string MUST NOT open. | `scenario:sealed with a stale info string` |
| `13.1#5` | The HPKE ephemeral MUST be fresh for every envelope — a reused one repeats the key and the nonce, and two ciphertexts under them leak the XOR of their plaintexts — and both sides MUST refuse an all-zero DH output, which a low-order X25519 point produces (RFC 9180 §7.1.4). | `scenario:HPKE ephemeral reuse leaks the XOR of two plaintexts; production sealing cannot take a seed`, `scenario:a low-order X25519 recipient point`, `rust:refuses_a_low_order_point`, `go:TestALowOrderRecipientIsRefused` |
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
| `13.3#2` | Idempotency records for seen `msg_id`s MUST be retained until `min(exp, ts + 300 s)` — the end of the window in which the envelope could be presented again and accepted. | `scenario:an envelope that asks to be remembered for a year`, `rust:an_envelope_asking_to_be_remembered_for_a_year_is_refused`, `go:TestLifetimeAndCallerSideChecks` |
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

## The 2145 cross-port parity cases

Each case feeds one argument shape to both the Rust core (through its WebAssembly bindings) and
the Go port and compares the whole answer — code, shape and `why` string. A function marked
*whole on success* has at least one case whose successful answer is compared member by member,
which is the only kind that notices a member going missing; a refusal compared whole proves both
ports refuse alike. `js/parity.mjs` fails if any guarded function lacks either.

At the run that generated this file: **2145** cases (**1108** of the run's cases are generated from the contract by `js/cases/generated.mjs`, the ones that pass are listed here), **0** disagreements besides the known ones, **50** of **50** functions compared whole on success.

### `address_guard` — 50 cases · whole on success

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
- address_guard with a zone id: https://[2001:db8::1%25eth0]/mcp
- address_guard with a zone id: https://[2001:db8::1%eth0]/mcp
- address_guard with a zone id: https://[fe80::1%eth0]/mcp
- address_guard with a zone id: https://[::1%lo]/mcp
- address_guard with a zone id: https://[2001:db8::1%x@evil.example]/mcp
- address_guard with a zone id: https://[2001:db8::1%x?y]/mcp
- address_guard with a zone id: https://[2001:db8::1%x#y]/mcp
- address_guard with a zone id: https://[2001:db8::1%X]/mcp
- address_guard with a zone id: https://[2001:db8::1%25eth0]:8443/mcp
- generated · address_guard · {}
- generated · address_guard · endpoint absent
- generated · address_guard · endpoint null
- generated · address_guard · self_endpoint ""
- generated · address_guard · self_endpoint 7
- generated · address_guard · guest "yes"
- generated · address_guard · an undeclared member
- generated · address_guard · endpoint absent, self_endpoint 7
- generated · address_guard · endpoint absent, guest "yes"

### `assemble_leaf` — 18 cases · whole on success

- assemble_leaf with a token's high-S signature
- assemble_leaf with a low-S signature
- assemble_leaf with a sig_alg that is not the TBS's
- assemble_leaf with no signature
- assemble_leaf with nothing to work from
- assemble_leaf
- generated · assemble_leaf · {}
- generated · assemble_leaf · tbs absent
- generated · assemble_leaf · tbs null
- generated · assemble_leaf · sig absent
- generated · assemble_leaf · sig null
- generated · assemble_leaf · sig_alg ""
- generated · assemble_leaf · sig_alg 7
- generated · assemble_leaf · an undeclared member
- generated · assemble_leaf · tbs absent, sig 7
- generated · assemble_leaf · tbs absent, sig_alg 7
- generated · assemble_leaf · sig absent, tbs 7
- generated · assemble_leaf · sig absent, sig_alg 7

### `assemble_root` — 15 cases · whole on success

- assemble_root of a TBS that is not one
- assemble_root with nothing to work from
- assemble_root
- generated · assemble_root · {}
- generated · assemble_root · tbs absent
- generated · assemble_root · tbs null
- generated · assemble_root · sig absent
- generated · assemble_root · sig null
- generated · assemble_root · sig_alg ""
- generated · assemble_root · sig_alg 7
- generated · assemble_root · an undeclared member
- generated · assemble_root · tbs absent, sig 7
- generated · assemble_root · tbs absent, sig_alg 7
- generated · assemble_root · sig absent, tbs 7
- generated · assemble_root · sig absent, sig_alg 7

### `book_rows` — 16 cases · whole on success

- book_rows: a contact with everything, one with the least
- book_rows: an empty book
- book_rows: a contact with a member a book does not keep
- book_rows: a contact with no endpoint
- book_rows: a name that is not a string
- book_rows: a contact that is not an object
- book_rows with nothing to work from
- book_rows with an exported_at that does not read
- generated · book_rows · {}
- generated · book_rows · contacts absent
- generated · book_rows · contacts null
- generated · book_rows · exported_at absent
- generated · book_rows · exported_at null
- generated · book_rows · an undeclared member
- generated · book_rows · contacts absent, exported_at 7
- generated · book_rows · exported_at absent, contacts "x"

### `build_leaf` — 92 cases · whole on success

- build_leaf
- build_leaf over 398 days
- build_leaf backwards in time
- build_leaf naming https://127.0.0.1/mcp
- build_leaf naming http://a.example/x
- build_leaf naming https://a.example/x/
- build_leaf with no not_before
- build_leaf with a dns_name that is empty
- build_leaf naming https://[2001:db8::1%25eth0]/mcp
- build_leaf naming https://[2001:db8::1%eth0]/mcp
- build_leaf for a host key outside the profile: rsa
- build_leaf for a host key outside the profile: P-384
- build_leaf for a host key outside the profile: X25519
- build_leaf for a host key outside the profile: Ed25519 with a NULL
- generated · build_leaf · {}
- generated · build_leaf · cn absent
- generated · build_leaf · cn null
- generated · build_leaf · root_cn absent
- generated · build_leaf · root_cn null
- generated · build_leaf · host_spki absent
- generated · build_leaf · host_spki null
- generated · build_leaf · endpoint absent
- generated · build_leaf · endpoint null
- generated · build_leaf · not_before absent
- generated · build_leaf · not_before null
- generated · build_leaf · not_after absent
- generated · build_leaf · not_after null
- generated · build_leaf · root_pkcs8 absent
- generated · build_leaf · root_pkcs8 null
- generated · build_leaf · dns_name ""
- generated · build_leaf · dns_name 7
- generated · build_leaf · serial ""
- generated · build_leaf · serial 7
- generated · build_leaf · an undeclared member
- generated · build_leaf · host_spki holding a key outside the profile
- generated · build_leaf · root_pkcs8 holding a key outside the profile
- generated · build_leaf · cn absent, root_cn 7
- generated · build_leaf · cn absent, host_spki 7
- generated · build_leaf · cn absent, endpoint 7
- generated · build_leaf · cn absent, dns_name 7
- generated · build_leaf · cn absent, not_before 7
- generated · build_leaf · cn absent, not_after 7
- generated · build_leaf · cn absent, serial 7
- generated · build_leaf · cn absent, root_pkcs8 7
- generated · build_leaf · root_cn absent, cn 7
- generated · build_leaf · root_cn absent, host_spki 7
- generated · build_leaf · root_cn absent, endpoint 7
- generated · build_leaf · root_cn absent, dns_name 7
- generated · build_leaf · root_cn absent, not_before 7
- generated · build_leaf · root_cn absent, not_after 7
- generated · build_leaf · root_cn absent, serial 7
- generated · build_leaf · root_cn absent, root_pkcs8 7
- generated · build_leaf · host_spki absent, cn 7
- generated · build_leaf · host_spki absent, root_cn 7
- generated · build_leaf · host_spki absent, endpoint 7
- generated · build_leaf · host_spki absent, dns_name 7
- generated · build_leaf · host_spki absent, not_before 7
- generated · build_leaf · host_spki absent, not_after 7
- generated · build_leaf · host_spki absent, serial 7
- generated · build_leaf · host_spki absent, root_pkcs8 7
- generated · build_leaf · endpoint absent, cn 7
- generated · build_leaf · endpoint absent, root_cn 7
- generated · build_leaf · endpoint absent, host_spki 7
- generated · build_leaf · endpoint absent, dns_name 7
- generated · build_leaf · endpoint absent, not_before 7
- generated · build_leaf · endpoint absent, not_after 7
- generated · build_leaf · endpoint absent, serial 7
- generated · build_leaf · endpoint absent, root_pkcs8 7
- generated · build_leaf · not_before absent, cn 7
- generated · build_leaf · not_before absent, root_cn 7
- generated · build_leaf · not_before absent, host_spki 7
- generated · build_leaf · not_before absent, endpoint 7
- generated · build_leaf · not_before absent, dns_name 7
- generated · build_leaf · not_before absent, not_after 7
- generated · build_leaf · not_before absent, serial 7
- generated · build_leaf · not_before absent, root_pkcs8 7
- generated · build_leaf · not_after absent, cn 7
- generated · build_leaf · not_after absent, root_cn 7
- generated · build_leaf · not_after absent, host_spki 7
- generated · build_leaf · not_after absent, endpoint 7
- generated · build_leaf · not_after absent, dns_name 7
- generated · build_leaf · not_after absent, not_before 7
- generated · build_leaf · not_after absent, serial 7
- generated · build_leaf · not_after absent, root_pkcs8 7
- generated · build_leaf · root_pkcs8 absent, cn 7
- generated · build_leaf · root_pkcs8 absent, root_cn 7
- generated · build_leaf · root_pkcs8 absent, host_spki 7
- generated · build_leaf · root_pkcs8 absent, endpoint 7
- generated · build_leaf · root_pkcs8 absent, dns_name 7
- generated · build_leaf · root_pkcs8 absent, not_before 7
- generated · build_leaf · root_pkcs8 absent, not_after 7
- generated · build_leaf · root_pkcs8 absent, serial 7

### `build_root` — 26 cases · whole on success

- build_root with no key
- build_root
- build_root with a serial that is too short
- build_root with an instant that is not one
- build_root with nothing to work from
- build_root with CN, not cn
- generated · build_root · {}
- generated · build_root · cn absent
- generated · build_root · cn null
- generated · build_root · pkcs8 absent
- generated · build_root · pkcs8 null
- generated · build_root · not_before absent
- generated · build_root · not_before null
- generated · build_root · serial ""
- generated · build_root · serial 7
- generated · build_root · an undeclared member
- generated · build_root · pkcs8 holding a key outside the profile
- generated · build_root · cn absent, pkcs8 7
- generated · build_root · cn absent, not_before 7
- generated · build_root · cn absent, serial 7
- generated · build_root · pkcs8 absent, cn 7
- generated · build_root · pkcs8 absent, not_before 7
- generated · build_root · pkcs8 absent, serial 7
- generated · build_root · not_before absent, cn 7
- generated · build_root · not_before absent, pkcs8 7
- generated · build_root · not_before absent, serial 7

### `card_decode` — 24 cases · whole on success

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
- card_decode of a card whose leaf holds a key outside the profile: rsa
- card_decode of a card whose leaf holds a key outside the profile: P-384
- card_decode of a card whose leaf holds a key outside the profile: X25519
- card_decode of a card whose leaf holds a key outside the profile: Ed25519 with a NULL
- generated · card_decode · {}
- generated · card_decode · the hostile object
- generated · card_decode · vcard absent
- generated · card_decode · vcard null
- generated · card_decode · now absent
- generated · card_decode · now null
- generated · card_decode · an undeclared member
- generated · card_decode · vcard absent, now 7
- generated · card_decode · now absent, vcard 7

### `card_encode` — 32 cases · whole on success

- card_encode
- card_encode with a name outside ASCII
- card_encode with a name that straddles the fold
- card_encode with an emoji name
- card_encode with a seal nobody has
- card_encode of a certificate that is not one
- card_encode with a certificate that is not a string
- card_encode with an extra line that is a number
- card_encode with an extra line that is null
- card_encode with nothing to work from
- card_encode: a name with CR LF
- card_encode: a name with a bare LF
- card_encode: a name with a NUL
- card_encode: a seal with CR LF
- card_encode: an extra line with CR LF
- card_encode: a name with a comma and a semicolon
- generated · card_encode · {}
- generated · card_encode · fn absent
- generated · card_encode · fn null
- generated · card_encode · cert absent
- generated · card_encode · cert null
- generated · card_encode · seal ""
- generated · card_encode · seal 7
- generated · card_encode · extra "x"
- generated · card_encode · an undeclared member
- generated · card_encode · cert holding a key outside the profile
- generated · card_encode · fn absent, cert 7
- generated · card_encode · fn absent, seal 7
- generated · card_encode · fn absent, extra "x"
- generated · card_encode · cert absent, fn 7
- generated · card_encode · cert absent, seal 7
- generated · card_encode · cert absent, extra "x"

### `compare_leaves` — 19 cases · whole on success

- compare_leaves with itself
- compare_leaves against a root
- compare_leaves of nothing
- compare_leaves with nothing to work from
- compare_leaves with pinned as null
- compare_leaves against a leaf holding a key outside the profile: rsa
- compare_leaves against a leaf holding a key outside the profile: P-384
- compare_leaves against a leaf holding a key outside the profile: X25519
- compare_leaves against a leaf holding a key outside the profile: Ed25519 with a NULL
- generated · compare_leaves · {}
- generated · compare_leaves · pinned absent
- generated · compare_leaves · pinned null
- generated · compare_leaves · presented absent
- generated · compare_leaves · presented null
- generated · compare_leaves · an undeclared member
- generated · compare_leaves · pinned holding a key outside the profile
- generated · compare_leaves · presented holding a key outside the profile
- generated · compare_leaves · pinned absent, presented 7
- generated · compare_leaves · presented absent, pinned 7

### `csr_check` — 34 cases · whole on success

- csr_check of bytes that are not a request
- csr_check of a certificate
- csr_check with no request
- the root-key refusal
- the root-key refusal with a list that will not read
- the root-key refusal with a list of numbers
- the root-key refusal with a list of one empty string
- the root-key refusal with no list
- csr_check
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
- csr_check of a request naming https://[2001:db8::1%25eth0]/mcp
- csr_check of a request naming https://[2001:db8::1%eth0]/mcp
- csr_check of a request carrying a key outside the profile: rsa
- csr_check of a request carrying a key outside the profile: P-384
- csr_check of a request carrying a key outside the profile: X25519
- csr_check of a request carrying a key outside the profile: Ed25519 with a NULL
- generated · csr_check · {}
- generated · csr_check · the hostile object
- generated · csr_check · der absent
- generated · csr_check · der null
- generated · csr_check · root_spkis "x"
- generated · csr_check · an undeclared member
- generated · csr_check · der holding a key outside the profile
- generated · csr_check · root_spkis holding a key outside the profile
- generated · csr_check · der absent, root_spkis "x"

### `csr_new` — 27 cases · whole on success

- csr_new with no key
- csr_new naming a local address
- csr_new naming nothing
- csr_new with a dns_name that is not the host
- csr_new
- csr_new with nothing to work from
- csr_new with a dns_name that is empty
- generated · csr_new · {}
- generated · csr_new · cn absent
- generated · csr_new · cn null
- generated · csr_new · host_pkcs8 absent
- generated · csr_new · host_pkcs8 null
- generated · csr_new · endpoint absent
- generated · csr_new · endpoint null
- generated · csr_new · dns_name ""
- generated · csr_new · dns_name 7
- generated · csr_new · an undeclared member
- generated · csr_new · host_pkcs8 holding a key outside the profile
- generated · csr_new · cn absent, host_pkcs8 7
- generated · csr_new · cn absent, endpoint 7
- generated · csr_new · cn absent, dns_name 7
- generated · csr_new · host_pkcs8 absent, cn 7
- generated · csr_new · host_pkcs8 absent, endpoint 7
- generated · csr_new · host_pkcs8 absent, dns_name 7
- generated · csr_new · endpoint absent, cn 7
- generated · csr_new · endpoint absent, host_pkcs8 7
- generated · csr_new · endpoint absent, dns_name 7

### `decide` — 90 cases · whole on success

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
- decide on a peer who returns a second inside the tombstone window
- decide on a peer who returns exactly at the end of the tombstone window
- decide on a stranger at an endpoint another root left a second inside the claim window
- decide on a stranger at an endpoint another root left exactly at the end of the claim window
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
- decide on a PACT-SEAL-X25519 envelope whose encapsulated key is one byte short
- decide on a PACT-SEAL-X25519 envelope whose encapsulated key is one byte long
- decide on a PACT-SEAL-P256 envelope whose encapsulated key is one byte short
- decide on a PACT-SEAL-P256 envelope whose encapsulated key is one byte long
- decide with an envelope with no sig
- decide with an envelope that is not an object
- decide with a node with no endpoint
- decide with a node that is not an object
- decide with a held key with no kid
- decide with a pin with no leaf
- decide with pins that are not a list
- decide with a seen entry that is not a string
- decide with an accept_new_hosts that is neither auto nor ask
- decide with a node and an envelope both short a member
- decide on a contact at a new endpoint, the node saying no accept_new_hosts
- decide on an envelope with a body holding a number past the largest double
- decide on an envelope with a body nested 128 deep
- decide on an envelope with a body holding the largest double
- decide on an envelope with a body nested 127 deep
- decide on an envelope whose header holds a ts past the largest double
- decide on a call sealed to the empty seed's key, held beside a P-256 key
- generated · decide · {}
- generated · decide · the hostile object
- generated · decide · now absent
- generated · decide · now null
- generated · decide · envelope absent
- generated · decide · envelope null
- generated · decide · node absent
- generated · decide · node null
- generated · decide · an undeclared member
- generated · decide · now absent, envelope "x"
- generated · decide · now absent, node "x"
- generated · decide · envelope absent, now 7
- generated · decide · envelope absent, node "x"
- generated · decide · node absent, now 7
- generated · decide · node absent, envelope "x"

### `derive_seed` — 18 cases · whole on success

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
- generated · derive_seed · {}
- generated · derive_seed · prf absent
- generated · derive_seed · prf null
- generated · derive_seed · info absent
- generated · derive_seed · info null
- generated · derive_seed · an undeclared member
- generated · derive_seed · prf absent, info 7
- generated · derive_seed · info absent, prf 7

### `export_manifest` — 15 cases · whole on success

- export_manifest: finished with the messages
- export_manifest: a book
- export_manifest with no partial
- export_manifest: messages without their hash
- export_manifest: a hash the host does not make
- export_manifest: a partial that already counts messages
- export_manifest: 5000 media files, the manifest under 64 KiB
- generated · export_manifest · {}
- generated · export_manifest · partial absent
- generated · export_manifest · partial null
- generated · export_manifest · hashes "x"
- generated · export_manifest · messages "7"
- generated · export_manifest · an undeclared member
- generated · export_manifest · partial absent, hashes "x"
- generated · export_manifest · partial absent, messages "7"

### `export_merge` — 11 cases · whole on success

- export_merge: a held pin is never replaced
- export_merge with rows whose root is no fingerprint
- export_merge: a held blocked contact keeps what the person decided
- generated · export_merge · {}
- generated · export_merge · held absent
- generated · export_merge · held null
- generated · export_merge · rows absent
- generated · export_merge · rows null
- generated · export_merge · an undeclared member
- generated · export_merge · held absent, rows "x"
- generated · export_merge · rows absent, held "x"

### `export_read` — 91 cases · whole on success

- export_read: what export_write wrote
- export_read at an instant that does not read
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
- generated · export_read · {}
- generated · export_read · the hostile object
- generated · export_read · directory absent
- generated · export_read · directory null
- generated · export_read · owner absent
- generated · export_read · owner null
- generated · export_read · now absent
- generated · export_read · now null
- generated · export_read · manifest ""
- generated · export_read · manifest 7
- generated · export_read · contacts_csv ""
- generated · export_read · contacts_csv 7
- generated · export_read · threads_csv ""
- generated · export_read · threads_csv 7
- generated · export_read · an undeclared member
- generated · export_read · directory absent, manifest 7
- generated · export_read · directory absent, contacts_csv 7
- generated · export_read · directory absent, threads_csv 7
- generated · export_read · directory absent, owner 7
- generated · export_read · directory absent, now 7
- generated · export_read · owner absent, directory "x"
- generated · export_read · owner absent, manifest 7
- generated · export_read · owner absent, contacts_csv 7
- generated · export_read · owner absent, threads_csv 7
- generated · export_read · owner absent, now 7
- generated · export_read · now absent, directory "x"
- generated · export_read · now absent, manifest 7
- generated · export_read · now absent, contacts_csv 7
- generated · export_read · now absent, threads_csv 7
- generated · export_read · now absent, owner 7

### `export_read_end` — 98 cases · whole on success

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
- export_read_end: a manifest with a count past the largest double
- export_read_end: a manifest nested 128 deep
- export_read_end: a manifest nested 127 deep
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
- generated · export_read_end · {}
- generated · export_read_end · manifest absent
- generated · export_read_end · manifest null
- generated · export_read_end · lines absent
- generated · export_read_end · lines null
- generated · export_read_end · ids absent
- generated · export_read_end · ids null
- generated · export_read_end · msg_ids absent
- generated · export_read_end · msg_ids null
- generated · export_read_end · reply_tos absent
- generated · export_read_end · reply_tos null
- generated · export_read_end · media_seen absent
- generated · export_read_end · media_seen null
- generated · export_read_end · media absent
- generated · export_read_end · media null
- generated · export_read_end · messages_sha256 ""
- generated · export_read_end · messages_sha256 7
- generated · export_read_end · an undeclared member
- generated · export_read_end · manifest absent, messages_sha256 7
- generated · export_read_end · manifest absent, lines "7"
- generated · export_read_end · manifest absent, ids "x"
- generated · export_read_end · manifest absent, msg_ids "x"
- generated · export_read_end · manifest absent, reply_tos "x"
- generated · export_read_end · manifest absent, media_seen "x"
- generated · export_read_end · manifest absent, media "x"
- generated · export_read_end · lines absent, manifest 7
- generated · export_read_end · lines absent, messages_sha256 7
- generated · export_read_end · lines absent, ids "x"
- generated · export_read_end · lines absent, msg_ids "x"
- generated · export_read_end · lines absent, reply_tos "x"
- generated · export_read_end · lines absent, media_seen "x"
- generated · export_read_end · lines absent, media "x"
- generated · export_read_end · ids absent, manifest 7
- generated · export_read_end · ids absent, messages_sha256 7
- generated · export_read_end · ids absent, lines "7"
- generated · export_read_end · ids absent, msg_ids "x"
- generated · export_read_end · ids absent, reply_tos "x"
- generated · export_read_end · ids absent, media_seen "x"
- generated · export_read_end · ids absent, media "x"
- generated · export_read_end · msg_ids absent, manifest 7
- generated · export_read_end · msg_ids absent, messages_sha256 7
- generated · export_read_end · msg_ids absent, lines "7"
- generated · export_read_end · msg_ids absent, ids "x"
- generated · export_read_end · msg_ids absent, reply_tos "x"
- generated · export_read_end · msg_ids absent, media_seen "x"
- generated · export_read_end · msg_ids absent, media "x"
- generated · export_read_end · reply_tos absent, manifest 7
- generated · export_read_end · reply_tos absent, messages_sha256 7
- generated · export_read_end · reply_tos absent, lines "7"
- generated · export_read_end · reply_tos absent, ids "x"
- generated · export_read_end · reply_tos absent, msg_ids "x"
- generated · export_read_end · reply_tos absent, media_seen "x"
- generated · export_read_end · reply_tos absent, media "x"
- generated · export_read_end · media_seen absent, manifest 7
- generated · export_read_end · media_seen absent, messages_sha256 7
- generated · export_read_end · media_seen absent, lines "7"
- generated · export_read_end · media_seen absent, ids "x"
- generated · export_read_end · media_seen absent, msg_ids "x"
- generated · export_read_end · media_seen absent, reply_tos "x"
- generated · export_read_end · media_seen absent, media "x"
- generated · export_read_end · media absent, manifest 7
- generated · export_read_end · media absent, messages_sha256 7
- generated · export_read_end · media absent, lines "7"
- generated · export_read_end · media absent, ids "x"
- generated · export_read_end · media absent, msg_ids "x"
- generated · export_read_end · media absent, reply_tos "x"
- generated · export_read_end · media absent, media_seen "x"

### `export_read_messages` — 54 cases · whole on success

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
- export_read_messages: a line with a number past the largest double
- export_read_messages: a line nested 128 deep
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
- generated · export_read_messages · {}
- generated · export_read_messages · lines absent
- generated · export_read_messages · lines null
- generated · export_read_messages · threads absent
- generated · export_read_messages · threads null
- generated · export_read_messages · contacts absent
- generated · export_read_messages · contacts null
- generated · export_read_messages · media absent
- generated · export_read_messages · media null
- generated · export_read_messages · first_line "7"
- generated · export_read_messages · an undeclared member
- generated · export_read_messages · lines absent, threads "x"
- generated · export_read_messages · lines absent, contacts "x"
- generated · export_read_messages · lines absent, media "x"
- generated · export_read_messages · lines absent, first_line "7"
- generated · export_read_messages · threads absent, lines "x"
- generated · export_read_messages · threads absent, contacts "x"
- generated · export_read_messages · threads absent, media "x"
- generated · export_read_messages · threads absent, first_line "7"
- generated · export_read_messages · contacts absent, lines "x"
- generated · export_read_messages · contacts absent, threads "x"
- generated · export_read_messages · contacts absent, media "x"
- generated · export_read_messages · contacts absent, first_line "7"
- generated · export_read_messages · media absent, lines "x"
- generated · export_read_messages · media absent, threads "x"
- generated · export_read_messages · media absent, contacts "x"
- generated · export_read_messages · media absent, first_line "7"

### `export_write` — 63 cases · whole on success

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
- export_write of a row naming https://[2001:db8::1%25eth0]/mcp
- export_write of a row naming https://[2001:db8::1%eth0]/mcp
- export_write: an exported_at with a lower-case z
- export_write: a contact added with a lower-case z
- export_write: an exported_at with a comma before the fraction
- export_write: a contact added with a comma before the fraction
- export_write: instants in the one grammar, a fraction included
- generated · export_write · {}
- generated · export_write · owner absent
- generated · export_write · owner null
- generated · export_write · owner_name absent
- generated · export_write · owner_name null
- generated · export_write · exported_at absent
- generated · export_write · exported_at null
- generated · export_write · tool absent
- generated · export_write · tool null
- generated · export_write · contacts absent
- generated · export_write · contacts null
- generated · export_write · threads "x"
- generated · export_write · media "x"
- generated · export_write · an undeclared member
- generated · export_write · owner absent, owner_name 7
- generated · export_write · owner absent, exported_at 7
- generated · export_write · owner absent, tool 7
- generated · export_write · owner absent, contacts "x"
- generated · export_write · owner absent, threads "x"
- generated · export_write · owner absent, media "x"
- generated · export_write · owner_name absent, owner 7
- generated · export_write · owner_name absent, exported_at 7
- generated · export_write · owner_name absent, tool 7
- generated · export_write · owner_name absent, contacts "x"
- generated · export_write · owner_name absent, threads "x"
- generated · export_write · owner_name absent, media "x"
- generated · export_write · exported_at absent, owner 7
- generated · export_write · exported_at absent, owner_name 7
- generated · export_write · exported_at absent, tool 7
- generated · export_write · exported_at absent, contacts "x"
- generated · export_write · exported_at absent, threads "x"
- generated · export_write · exported_at absent, media "x"
- generated · export_write · tool absent, owner 7
- generated · export_write · tool absent, owner_name 7
- generated · export_write · tool absent, exported_at 7
- generated · export_write · tool absent, contacts "x"
- generated · export_write · tool absent, threads "x"
- generated · export_write · tool absent, media "x"
- generated · export_write · contacts absent, owner 7
- generated · export_write · contacts absent, owner_name 7
- generated · export_write · contacts absent, exported_at 7
- generated · export_write · contacts absent, tool 7
- generated · export_write · contacts absent, threads "x"
- generated · export_write · contacts absent, media "x"

### `export_write_messages` — 14 cases · whole on success

- export_write_messages: a text, a file and a link
- export_write_messages: a dangling reply, a key in a body, a reply to what was left out
- export_write_messages: in batches, the file names its msg_ids
- export_write_messages: msg_ids that are not strings
- export_write_messages: two attachments
- export_write_messages: text beside a file
- export_write_messages: a message time with a lower-case z
- export_write_messages: a message time with a comma before the fraction
- generated · export_write_messages · {}
- generated · export_write_messages · messages absent
- generated · export_write_messages · messages null
- generated · export_write_messages · msg_ids "x"
- generated · export_write_messages · an undeclared member
- generated · export_write_messages · messages absent, msg_ids "x"

### `follow_renewed` — 45 cases · whole on success

- follow_renewed on a chain to another root
- follow_renewed on a chain that is not one
- follow_renewed on the same leaf
- follow_renewed to a leaf naming https://[2001:db8::1%25eth0]/mcp
- follow_renewed to a leaf naming https://[2001:db8::1%eth0]/mcp
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
- follow_renewed on an answer whose code is not a string
- follow_renewed on an answer whose data is not an object
- follow_renewed on an answer that is not an object
- follow_renewed with a pinned_root that is empty
- follow_renewed with a dialed address that is empty
- generated · follow_renewed · {}
- generated · follow_renewed · the hostile object
- generated · follow_renewed · pinned_root absent
- generated · follow_renewed · pinned_root null
- generated · follow_renewed · pinned_leaf absent
- generated · follow_renewed · pinned_leaf null
- generated · follow_renewed · dialed absent
- generated · follow_renewed · dialed null
- generated · follow_renewed · now absent
- generated · follow_renewed · now null
- generated · follow_renewed · answer ""
- generated · follow_renewed · an undeclared member
- generated · follow_renewed · pinned_leaf holding a key outside the profile
- generated · follow_renewed · pinned_root absent, pinned_leaf 7
- generated · follow_renewed · pinned_root absent, dialed 7
- generated · follow_renewed · pinned_root absent, now 7
- generated · follow_renewed · pinned_leaf absent, pinned_root 7
- generated · follow_renewed · pinned_leaf absent, dialed 7
- generated · follow_renewed · pinned_leaf absent, now 7
- generated · follow_renewed · dialed absent, pinned_root 7
- generated · follow_renewed · dialed absent, pinned_leaf 7
- generated · follow_renewed · dialed absent, now 7
- generated · follow_renewed · now absent, pinned_root 7
- generated · follow_renewed · now absent, pinned_leaf 7
- generated · follow_renewed · now absent, dialed 7

### `generate_key` — 9 cases · whole on success

- generate_key
- generate_key of a P-256 key
- generate_key with no algorithm
- generate_key with an algorithm nobody has
- generate_key with nothing to work from
- generated · generate_key · {}
- generated · generate_key · alg absent
- generated · generate_key · alg null
- generated · generate_key · an undeclared member

### `hpke_open` — 68 cases · whole on success

- hpke_open of a ciphertext that is not one
- hpke_open with nothing to work from
- hpke_open of what hpke_seal made
- hpke_open with a public key that is another Ed25519 key
- hpke_open with a public key of the other algorithm
- hpke_open with no public key
- hpke_open as a key outside the profile: rsa
- hpke_open as a key outside the profile: P-384
- hpke_open as a key outside the profile: X25519
- hpke_open as a key outside the profile: Ed25519 with a NULL
- hpke_open of a seal to the empty seed's key, by a P-256 key
- hpke_open of a seal to the empty seed's key, by another P-256 key
- hpke_open under the P-256 suite by an Ed25519 key
- hpke_open under the X25519 suite by a P-256 key
- generated · hpke_open · {}
- generated · hpke_open · suite absent
- generated · hpke_open · suite null
- generated · hpke_open · recipient_pkcs8 absent
- generated · hpke_open · recipient_pkcs8 null
- generated · hpke_open · recipient_spki absent
- generated · hpke_open · recipient_spki null
- generated · hpke_open · info absent
- generated · hpke_open · info null
- generated · hpke_open · enc absent
- generated · hpke_open · enc null
- generated · hpke_open · ct absent
- generated · hpke_open · ct null
- generated · hpke_open · aad ""
- generated · hpke_open · aad 7
- generated · hpke_open · an undeclared member
- generated · hpke_open · recipient_pkcs8 holding a key outside the profile
- generated · hpke_open · recipient_spki holding a key outside the profile
- generated · hpke_open · suite absent, recipient_pkcs8 7
- generated · hpke_open · suite absent, recipient_spki 7
- generated · hpke_open · suite absent, info 7
- generated · hpke_open · suite absent, aad 7
- generated · hpke_open · suite absent, enc 7
- generated · hpke_open · suite absent, ct 7
- generated · hpke_open · recipient_pkcs8 absent, suite 7
- generated · hpke_open · recipient_pkcs8 absent, recipient_spki 7
- generated · hpke_open · recipient_pkcs8 absent, info 7
- generated · hpke_open · recipient_pkcs8 absent, aad 7
- generated · hpke_open · recipient_pkcs8 absent, enc 7
- generated · hpke_open · recipient_pkcs8 absent, ct 7
- generated · hpke_open · recipient_spki absent, suite 7
- generated · hpke_open · recipient_spki absent, recipient_pkcs8 7
- generated · hpke_open · recipient_spki absent, info 7
- generated · hpke_open · recipient_spki absent, aad 7
- generated · hpke_open · recipient_spki absent, enc 7
- generated · hpke_open · recipient_spki absent, ct 7
- generated · hpke_open · info absent, suite 7
- generated · hpke_open · info absent, recipient_pkcs8 7
- generated · hpke_open · info absent, recipient_spki 7
- generated · hpke_open · info absent, aad 7
- generated · hpke_open · info absent, enc 7
- generated · hpke_open · info absent, ct 7
- generated · hpke_open · enc absent, suite 7
- generated · hpke_open · enc absent, recipient_pkcs8 7
- generated · hpke_open · enc absent, recipient_spki 7
- generated · hpke_open · enc absent, info 7
- generated · hpke_open · enc absent, aad 7
- generated · hpke_open · enc absent, ct 7
- generated · hpke_open · ct absent, suite 7
- generated · hpke_open · ct absent, recipient_pkcs8 7
- generated · hpke_open · ct absent, recipient_spki 7
- generated · hpke_open · ct absent, info 7
- generated · hpke_open · ct absent, aad 7
- generated · hpke_open · ct absent, enc 7

### `hpke_seal` — 50 cases · whole on success

- hpke_seal with a suite nobody has
- hpke_seal with nothing to work from
- hpke_seal
- hpke_seal under PACT-SEAL-X25519 to a key outside the profile: rsa
- hpke_seal under PACT-SEAL-P256 to a key outside the profile: rsa
- hpke_seal under PACT-SEAL-X25519 to a key outside the profile: P-384
- hpke_seal under PACT-SEAL-P256 to a key outside the profile: P-384
- hpke_seal under PACT-SEAL-X25519 to a key outside the profile: X25519
- hpke_seal under PACT-SEAL-P256 to a key outside the profile: X25519
- hpke_seal under PACT-SEAL-X25519 to a key outside the profile: Ed25519 with a NULL
- hpke_seal under PACT-SEAL-P256 to a key outside the profile: Ed25519 with a NULL
- hpke_seal under PACT-SEAL-X25519 to a P-256 key
- hpke_seal under PACT-SEAL-P256 to an Ed25519 key
- hpke_seal to an Ed25519 key of small order: the identity
- hpke_seal to an Ed25519 key of small order: y = -1
- generated · hpke_seal · {}
- generated · hpke_seal · suite absent
- generated · hpke_seal · suite null
- generated · hpke_seal · recipient_spki absent
- generated · hpke_seal · recipient_spki null
- generated · hpke_seal · info absent
- generated · hpke_seal · info null
- generated · hpke_seal · plaintext absent
- generated · hpke_seal · plaintext null
- generated · hpke_seal · aad ""
- generated · hpke_seal · aad 7
- generated · hpke_seal · ephemeral_seed ""
- generated · hpke_seal · ephemeral_seed 7
- generated · hpke_seal · an undeclared member
- generated · hpke_seal · recipient_spki holding a key outside the profile
- generated · hpke_seal · suite absent, recipient_spki 7
- generated · hpke_seal · suite absent, info 7
- generated · hpke_seal · suite absent, aad 7
- generated · hpke_seal · suite absent, plaintext 7
- generated · hpke_seal · suite absent, ephemeral_seed 7
- generated · hpke_seal · recipient_spki absent, suite 7
- generated · hpke_seal · recipient_spki absent, info 7
- generated · hpke_seal · recipient_spki absent, aad 7
- generated · hpke_seal · recipient_spki absent, plaintext 7
- generated · hpke_seal · recipient_spki absent, ephemeral_seed 7
- generated · hpke_seal · info absent, suite 7
- generated · hpke_seal · info absent, recipient_spki 7
- generated · hpke_seal · info absent, aad 7
- generated · hpke_seal · info absent, plaintext 7
- generated · hpke_seal · info absent, ephemeral_seed 7
- generated · hpke_seal · plaintext absent, suite 7
- generated · hpke_seal · plaintext absent, recipient_spki 7
- generated · hpke_seal · plaintext absent, info 7
- generated · hpke_seal · plaintext absent, aad 7
- generated · hpke_seal · plaintext absent, ephemeral_seed 7

### `ip_is_private` — 45 cases · whole on success

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
- ip_is_private with a zone id: fe80::1%eth0
- ip_is_private with a zone id: 2001:db8::1%eth0
- ip_is_private with a zone id: [fe80::1%eth0]
- ip_is_private with a zone id: ::ffff:10.0.0.1%eth0
- ip_is_private with a zone id: 2606:4700:4700::1111%25eth0
- ip_is_private with a zone id: fe80::1%eth0%x
- ip_is_private with a zone id: fe80::1%
- ip_is_private with a zone id: 10.0.0.1%eth0
- ip_is_private with a zone id: 8.8.8.8%eth0
- ip_is_private in brackets: [[::1]]
- ip_is_private in brackets: ]::1[
- ip_is_private in brackets: [[10.0.0.1]]
- ip_is_private in brackets: [::1
- ip_is_private in brackets: ::1]
- ip_is_private in brackets: [10.0.0.1]
- ip_is_private in brackets: [8.8.8.8]
- generated · ip_is_private · {}
- generated · ip_is_private · ip absent
- generated · ip_is_private · ip null
- generated · ip_is_private · an undeclared member

### `is_normal_https` — 41 cases · whole on success

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
- is_normal_https with a zone id: https://[2001:db8::1%25eth0]/mcp
- is_normal_https with a zone id: https://[2001:db8::1%eth0]/mcp
- is_normal_https with a zone id: https://[fe80::1%eth0]/mcp
- is_normal_https with a zone id: https://[::1%lo]/mcp
- is_normal_https with a zone id: https://[2001:db8::1%x@evil.example]/mcp
- is_normal_https with a zone id: https://[2001:db8::1%x?y]/mcp
- is_normal_https with a zone id: https://[2001:db8::1%x#y]/mcp
- is_normal_https with a zone id: https://[2001:db8::1%X]/mcp
- is_normal_https with a zone id: https://[2001:db8::1%25eth0]:8443/mcp
- generated · is_normal_https · {}
- generated · is_normal_https · url absent
- generated · is_normal_https · url null
- generated · is_normal_https · an undeclared member

### `issue_from_csr` — 57 cases · whole on success

- issue_from_csr with an explicit zero validity
- issue_from_csr over 398 days
- issue_from_csr with a negative validity
- issue_from_csr of a request that is not one
- issue_from_csr of a request that is a truncated SEQUENCE
- issue_from_csr refusing the root's own key
- issue_from_csr
- issue_from_csr refusing a root given as a key id
- issue_from_csr with no now
- issue_from_csr of a request naming https://[2001:db8::1%25eth0]/mcp
- issue_from_csr of a request naming https://[2001:db8::1%eth0]/mcp
- issue_from_csr of a request carrying a key outside the profile: rsa
- issue_from_csr of a request carrying a key outside the profile: P-384
- issue_from_csr of a request carrying a key outside the profile: X25519
- issue_from_csr of a request carrying a key outside the profile: Ed25519 with a NULL
- generated · issue_from_csr · {}
- generated · issue_from_csr · the hostile object
- generated · issue_from_csr · csr absent
- generated · issue_from_csr · csr null
- generated · issue_from_csr · root_cn absent
- generated · issue_from_csr · root_cn null
- generated · issue_from_csr · root_pkcs8 absent
- generated · issue_from_csr · root_pkcs8 null
- generated · issue_from_csr · now absent
- generated · issue_from_csr · now null
- generated · issue_from_csr · root_spkis "x"
- generated · issue_from_csr · previous_not_before ""
- generated · issue_from_csr · previous_not_before 7
- generated · issue_from_csr · valid_days "7"
- generated · issue_from_csr · an undeclared member
- generated · issue_from_csr · csr holding a key outside the profile
- generated · issue_from_csr · root_spkis holding a key outside the profile
- generated · issue_from_csr · root_pkcs8 holding a key outside the profile
- generated · issue_from_csr · csr absent, root_cn 7
- generated · issue_from_csr · csr absent, root_spkis "x"
- generated · issue_from_csr · csr absent, now 7
- generated · issue_from_csr · csr absent, previous_not_before 7
- generated · issue_from_csr · csr absent, valid_days "7"
- generated · issue_from_csr · csr absent, root_pkcs8 7
- generated · issue_from_csr · root_cn absent, csr 7
- generated · issue_from_csr · root_cn absent, root_spkis "x"
- generated · issue_from_csr · root_cn absent, now 7
- generated · issue_from_csr · root_cn absent, previous_not_before 7
- generated · issue_from_csr · root_cn absent, valid_days "7"
- generated · issue_from_csr · root_cn absent, root_pkcs8 7
- generated · issue_from_csr · root_pkcs8 absent, csr 7
- generated · issue_from_csr · root_pkcs8 absent, root_cn 7
- generated · issue_from_csr · root_pkcs8 absent, root_spkis "x"
- generated · issue_from_csr · root_pkcs8 absent, now 7
- generated · issue_from_csr · root_pkcs8 absent, previous_not_before 7
- generated · issue_from_csr · root_pkcs8 absent, valid_days "7"
- generated · issue_from_csr · now absent, csr 7
- generated · issue_from_csr · now absent, root_cn 7
- generated · issue_from_csr · now absent, root_spkis "x"
- generated · issue_from_csr · now absent, previous_not_before 7
- generated · issue_from_csr · now absent, valid_days "7"
- generated · issue_from_csr · now absent, root_pkcs8 7

### `issue_tbs_from_csr` — 46 cases · whole on success

- issue_tbs_from_csr of a request that is a truncated SEQUENCE
- issue_tbs_from_csr
- issue_tbs_from_csr of a request naming https://[2001:db8::1%25eth0]/mcp
- issue_tbs_from_csr of a request naming https://[2001:db8::1%eth0]/mcp
- generated · issue_tbs_from_csr · {}
- generated · issue_tbs_from_csr · the hostile object
- generated · issue_tbs_from_csr · csr absent
- generated · issue_tbs_from_csr · csr null
- generated · issue_tbs_from_csr · root_cn absent
- generated · issue_tbs_from_csr · root_cn null
- generated · issue_tbs_from_csr · root_spki absent
- generated · issue_tbs_from_csr · root_spki null
- generated · issue_tbs_from_csr · now absent
- generated · issue_tbs_from_csr · now null
- generated · issue_tbs_from_csr · root_spkis "x"
- generated · issue_tbs_from_csr · previous_not_before ""
- generated · issue_tbs_from_csr · previous_not_before 7
- generated · issue_tbs_from_csr · valid_days "7"
- generated · issue_tbs_from_csr · an undeclared member
- generated · issue_tbs_from_csr · csr holding a key outside the profile
- generated · issue_tbs_from_csr · root_spkis holding a key outside the profile
- generated · issue_tbs_from_csr · root_spki holding a key outside the profile
- generated · issue_tbs_from_csr · csr absent, root_cn 7
- generated · issue_tbs_from_csr · csr absent, root_spkis "x"
- generated · issue_tbs_from_csr · csr absent, now 7
- generated · issue_tbs_from_csr · csr absent, previous_not_before 7
- generated · issue_tbs_from_csr · csr absent, valid_days "7"
- generated · issue_tbs_from_csr · csr absent, root_spki 7
- generated · issue_tbs_from_csr · root_cn absent, csr 7
- generated · issue_tbs_from_csr · root_cn absent, root_spkis "x"
- generated · issue_tbs_from_csr · root_cn absent, now 7
- generated · issue_tbs_from_csr · root_cn absent, previous_not_before 7
- generated · issue_tbs_from_csr · root_cn absent, valid_days "7"
- generated · issue_tbs_from_csr · root_cn absent, root_spki 7
- generated · issue_tbs_from_csr · root_spki absent, csr 7
- generated · issue_tbs_from_csr · root_spki absent, root_cn 7
- generated · issue_tbs_from_csr · root_spki absent, root_spkis "x"
- generated · issue_tbs_from_csr · root_spki absent, now 7
- generated · issue_tbs_from_csr · root_spki absent, previous_not_before 7
- generated · issue_tbs_from_csr · root_spki absent, valid_days "7"
- generated · issue_tbs_from_csr · now absent, csr 7
- generated · issue_tbs_from_csr · now absent, root_cn 7
- generated · issue_tbs_from_csr · now absent, root_spkis "x"
- generated · issue_tbs_from_csr · now absent, previous_not_before 7
- generated · issue_tbs_from_csr · now absent, valid_days "7"
- generated · issue_tbs_from_csr · now absent, root_spki 7

### `key_from_seed` — 14 cases · whole on success

- key_from_seed with a short seed
- key_from_seed with an unknown algorithm
- key_from_seed with a seed that is not a string
- key_from_seed with nothing to work from
- key_from_seed
- key_from_seed of a P-256 key
- generated · key_from_seed · {}
- generated · key_from_seed · alg absent
- generated · key_from_seed · alg null
- generated · key_from_seed · seed absent
- generated · key_from_seed · seed null
- generated · key_from_seed · an undeclared member
- generated · key_from_seed · alg absent, seed 7
- generated · key_from_seed · seed absent, alg 7

### `key_info` — 30 cases · whole on success

- args that are not an object
- args that are a list
- args that are null
- args that are a number
- args that are true
- args that are an empty list
- key_info of an spki that is not one
- key_info with no argument
- key_info of bytes that are not base64url ("!!!")
- key_info of bytes that are not base64url ("")
- key_info of bytes that are not base64url ("AA=")
- key_info of bytes that are not base64url ("a b c")
- key_info of bytes that are not base64url ("~~~~")
- key_info of a number
- key_info of an spki nested 126 deep, 127 with the arguments
- key_info of an spki nested 127 deep, 128 with the arguments
- key_info of an RSA key
- key_info with nothing to work from
- key_info with spki as null
- key_info
- key_info of a P-256 key
- key_info of a key outside the profile: rsa
- key_info of a key outside the profile: P-384
- key_info of a key outside the profile: X25519
- key_info of a key outside the profile: Ed25519 with a NULL
- generated · key_info · {}
- generated · key_info · spki absent
- generated · key_info · spki null
- generated · key_info · an undeclared member
- generated · key_info · spki holding a key outside the profile

### `leaf_tbs` — 86 cases · whole on success

- leaf_tbs
- leaf_tbs with no issuer
- leaf_tbs naming https://[2001:db8::1%25eth0]/mcp
- leaf_tbs naming https://[2001:db8::1%eth0]/mcp
- leaf_tbs under a root key outside the profile: rsa
- leaf_tbs under a root key outside the profile: P-384
- leaf_tbs under a root key outside the profile: X25519
- leaf_tbs under a root key outside the profile: Ed25519 with a NULL
- generated · leaf_tbs · {}
- generated · leaf_tbs · cn absent
- generated · leaf_tbs · cn null
- generated · leaf_tbs · root_cn absent
- generated · leaf_tbs · root_cn null
- generated · leaf_tbs · host_spki absent
- generated · leaf_tbs · host_spki null
- generated · leaf_tbs · endpoint absent
- generated · leaf_tbs · endpoint null
- generated · leaf_tbs · not_before absent
- generated · leaf_tbs · not_before null
- generated · leaf_tbs · not_after absent
- generated · leaf_tbs · not_after null
- generated · leaf_tbs · root_spki absent
- generated · leaf_tbs · root_spki null
- generated · leaf_tbs · dns_name ""
- generated · leaf_tbs · dns_name 7
- generated · leaf_tbs · serial ""
- generated · leaf_tbs · serial 7
- generated · leaf_tbs · an undeclared member
- generated · leaf_tbs · host_spki holding a key outside the profile
- generated · leaf_tbs · root_spki holding a key outside the profile
- generated · leaf_tbs · cn absent, root_cn 7
- generated · leaf_tbs · cn absent, host_spki 7
- generated · leaf_tbs · cn absent, endpoint 7
- generated · leaf_tbs · cn absent, dns_name 7
- generated · leaf_tbs · cn absent, not_before 7
- generated · leaf_tbs · cn absent, not_after 7
- generated · leaf_tbs · cn absent, serial 7
- generated · leaf_tbs · cn absent, root_spki 7
- generated · leaf_tbs · root_cn absent, cn 7
- generated · leaf_tbs · root_cn absent, host_spki 7
- generated · leaf_tbs · root_cn absent, endpoint 7
- generated · leaf_tbs · root_cn absent, dns_name 7
- generated · leaf_tbs · root_cn absent, not_before 7
- generated · leaf_tbs · root_cn absent, not_after 7
- generated · leaf_tbs · root_cn absent, serial 7
- generated · leaf_tbs · root_cn absent, root_spki 7
- generated · leaf_tbs · host_spki absent, cn 7
- generated · leaf_tbs · host_spki absent, root_cn 7
- generated · leaf_tbs · host_spki absent, endpoint 7
- generated · leaf_tbs · host_spki absent, dns_name 7
- generated · leaf_tbs · host_spki absent, not_before 7
- generated · leaf_tbs · host_spki absent, not_after 7
- generated · leaf_tbs · host_spki absent, serial 7
- generated · leaf_tbs · host_spki absent, root_spki 7
- generated · leaf_tbs · endpoint absent, cn 7
- generated · leaf_tbs · endpoint absent, root_cn 7
- generated · leaf_tbs · endpoint absent, host_spki 7
- generated · leaf_tbs · endpoint absent, dns_name 7
- generated · leaf_tbs · endpoint absent, not_before 7
- generated · leaf_tbs · endpoint absent, not_after 7
- generated · leaf_tbs · endpoint absent, serial 7
- generated · leaf_tbs · endpoint absent, root_spki 7
- generated · leaf_tbs · not_before absent, cn 7
- generated · leaf_tbs · not_before absent, root_cn 7
- generated · leaf_tbs · not_before absent, host_spki 7
- generated · leaf_tbs · not_before absent, endpoint 7
- generated · leaf_tbs · not_before absent, dns_name 7
- generated · leaf_tbs · not_before absent, not_after 7
- generated · leaf_tbs · not_before absent, serial 7
- generated · leaf_tbs · not_before absent, root_spki 7
- generated · leaf_tbs · not_after absent, cn 7
- generated · leaf_tbs · not_after absent, root_cn 7
- generated · leaf_tbs · not_after absent, host_spki 7
- generated · leaf_tbs · not_after absent, endpoint 7
- generated · leaf_tbs · not_after absent, dns_name 7
- generated · leaf_tbs · not_after absent, not_before 7
- generated · leaf_tbs · not_after absent, serial 7
- generated · leaf_tbs · not_after absent, root_spki 7
- generated · leaf_tbs · root_spki absent, cn 7
- generated · leaf_tbs · root_spki absent, root_cn 7
- generated · leaf_tbs · root_spki absent, host_spki 7
- generated · leaf_tbs · root_spki absent, endpoint 7
- generated · leaf_tbs · root_spki absent, dns_name 7
- generated · leaf_tbs · root_spki absent, not_before 7
- generated · leaf_tbs · root_spki absent, not_after 7
- generated · leaf_tbs · root_spki absent, serial 7

### `ledger_check` — 58 cases · whole on success

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
- ledger_check for https://[2001:db8::1%25eth0]/mcp
- ledger_check for https://[2001:db8::1%eth0]/mcp
- generated · ledger_check · {}
- generated · ledger_check · the hostile object
- generated · ledger_check · root absent
- generated · ledger_check · root null
- generated · ledger_check · endpoint absent
- generated · ledger_check · endpoint null
- generated · ledger_check · now absent
- generated · ledger_check · now null
- generated · ledger_check · ledger "x"
- generated · ledger_check · move "yes"
- generated · ledger_check · an undeclared member
- generated · ledger_check · root absent, ledger "x"
- generated · ledger_check · root absent, endpoint 7
- generated · ledger_check · root absent, now 7
- generated · ledger_check · root absent, move "yes"
- generated · ledger_check · endpoint absent, ledger "x"
- generated · ledger_check · endpoint absent, root 7
- generated · ledger_check · endpoint absent, now 7
- generated · ledger_check · endpoint absent, move "yes"
- generated · ledger_check · now absent, ledger "x"
- generated · ledger_check · now absent, root 7
- generated · ledger_check · now absent, endpoint 7
- generated · ledger_check · now absent, move "yes"

### `limits_decide` — 76 cases · whole on success

- limits_decide: a contact in, fresh
- limits_decide: a contact in, empty
- limits_decide: a contact out, fresh
- limits_decide: a contact out, empty
- limits_decide: a guest with an address, fresh
- limits_decide: a guest with an address, empty
- limits_decide: a guest with no address, fresh
- limits_decide: a guest with no address, empty
- limits_decide: a small form, no root, fresh
- limits_decide: a small form, no root, empty
- limits_decide: a small form, an empty root, fresh
- limits_decide: a small form, an empty root, empty
- limits_decide: the guest total, fresh
- limits_decide: the guest total, empty
- limits_decide: a stranger out, fresh
- limits_decide: a stranger out, empty
- limits_decide: an integration, fresh
- limits_decide: an integration, empty
- limits_decide: the identity aggregate, empty
- limits_decide: the outbound aggregate, empty
- limits_decide: both buckets empty, the first of equals
- limits_decide: a contact cap of 0 is still one call a second
- limits_decide: a contact cap past the capacity
- limits_decide: a row over its burst
- limits_decide: a clock that went back
- limits_decide: a partly refilled bucket
- limits_decide: rows for other buckets are left alone
- limits_decide: requests under the cap
- limits_decide: requests at the cap
- limits_decide with no rules
- limits_decide with rules that cannot be enforced
- limits_decide with no charge
- limits_decide with a charge that is a string
- limits_decide with a charge with no kind
- limits_decide with a charge of an unknown kind
- limits_decide with a charge with a member its kind does not hold
- limits_decide with a contact charge with no root
- limits_decide with a contact charge with an empty root
- limits_decide with a contact cap with a fraction
- limits_decide with a negative contact cap
- limits_decide with a guest charge whose root is a number
- limits_decide with a guest charge with no source
- limits_decide with a guest charge with no addressed
- limits_decide with an integration charge with no contact
- limits_decide with a pending count that is a string
- limits_decide with no now
- limits_decide with a negative now
- limits_decide with a now with a fraction
- limits_decide with a now past 2^53
- limits_decide with a state that is a list
- limits_decide with a row that is a number
- limits_decide with a row with a member it does not hold
- limits_decide with a row whose tokens are a string
- limits_decide with a row with no updated_at
- limits_decide with a row whose updated_at has a fraction
- limits_decide with a now of -0
- limits_decide with nothing to work from
- generated · limits_decide · {}
- generated · limits_decide · the hostile object
- generated · limits_decide · rules absent
- generated · limits_decide · rules null
- generated · limits_decide · charge absent
- generated · limits_decide · charge null
- generated · limits_decide · now absent
- generated · limits_decide · now null
- generated · limits_decide · state "x"
- generated · limits_decide · an undeclared member
- generated · limits_decide · rules absent, charge "x"
- generated · limits_decide · rules absent, now "7"
- generated · limits_decide · rules absent, state "x"
- generated · limits_decide · charge absent, rules "x"
- generated · limits_decide · charge absent, now "7"
- generated · limits_decide · charge absent, state "x"
- generated · limits_decide · now absent, rules "x"
- generated · limits_decide · now absent, charge "x"
- generated · limits_decide · now absent, state "x"

### `limits_rules_check` — 22 cases · whole on success

- limits_rules_check: a document that can be enforced
- limits_rules_check: not an object
- limits_rules_check: a member it does not hold
- limits_rules_check: a member missing
- limits_rules_check: a member that is a string
- limits_rules_check: a contact rate of 0
- limits_rules_check: a burst under one call
- limits_rules_check: a capacity under one call
- limits_rules_check: a guest budget of 0
- limits_rules_check: a negative source budget
- limits_rules_check: a stranger budget of 0
- limits_rules_check: an integration budget of 0
- limits_rules_check: a guest total of 0
- limits_rules_check: a pending cap of 0
- limits_rules_check: a pending cap with a fraction
- limits_rules_check: a contact bucket slower than the hour
- limits_rules_check with no rules
- limits_rules_check with null rules
- generated · limits_rules_check · {}
- generated · limits_rules_check · rules absent
- generated · limits_rules_check · rules null
- generated · limits_rules_check · an undeclared member

### `no_such_function` — 1 case · not a dispatched function

- a function nobody defines

### `open_result` — 88 cases · whole on success

- open_result of a request envelope
- open_result with nothing to work from
- open_result of what seal_result made
- open_result with a public key that is not this key's: the kid says so first
- open_result with the kid's public key and another private key: it does not open
- open_result with no public key
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
- open_result on a PACT-SEAL-X25519 answer whose encapsulated key is one byte short
- open_result on a PACT-SEAL-X25519 answer whose encapsulated key is one byte long
- open_result on a PACT-SEAL-P256 answer whose encapsulated key is one byte short
- open_result on a PACT-SEAL-P256 answer whose encapsulated key is one byte long
- open_result with an envelope with no ct
- open_result with an envelope that is not an object
- open_result with a pin with no root
- open_result with a pin whose root is not a string
- open_result with a pin that is not an object
- open_result with pins that are null
- open_result in the chain form with an expected_root that is empty
- open_result on an answer whose result holds a number past the largest double
- open_result on an answer whose result holds the largest double
- generated · open_result · {}
- generated · open_result · the hostile object
- generated · open_result · envelope absent
- generated · open_result · envelope null
- generated · open_result · my_pkcs8 absent
- generated · open_result · my_pkcs8 null
- generated · open_result · my_spki absent
- generated · open_result · my_spki null
- generated · open_result · msg_id absent
- generated · open_result · msg_id null
- generated · open_result · now absent
- generated · open_result · now null
- generated · open_result · pins "x"
- generated · open_result · expected_root ""
- generated · open_result · expected_root 7
- generated · open_result · expected_endpoint ""
- generated · open_result · expected_endpoint 7
- generated · open_result · an undeclared member
- generated · open_result · my_pkcs8 holding a key outside the profile
- generated · open_result · my_spki holding a key outside the profile
- generated · open_result · envelope absent, my_pkcs8 7
- generated · open_result · envelope absent, my_spki 7
- generated · open_result · envelope absent, msg_id 7
- generated · open_result · envelope absent, now 7
- generated · open_result · envelope absent, pins "x"
- generated · open_result · envelope absent, expected_root 7
- generated · open_result · envelope absent, expected_endpoint 7
- generated · open_result · my_pkcs8 absent, envelope "x"
- generated · open_result · my_pkcs8 absent, my_spki 7
- generated · open_result · my_pkcs8 absent, msg_id 7
- generated · open_result · my_pkcs8 absent, now 7
- generated · open_result · my_pkcs8 absent, pins "x"
- generated · open_result · my_pkcs8 absent, expected_root 7
- generated · open_result · my_pkcs8 absent, expected_endpoint 7
- generated · open_result · my_spki absent, envelope "x"
- generated · open_result · my_spki absent, my_pkcs8 7
- generated · open_result · my_spki absent, msg_id 7
- generated · open_result · my_spki absent, now 7
- generated · open_result · my_spki absent, pins "x"
- generated · open_result · my_spki absent, expected_root 7
- generated · open_result · my_spki absent, expected_endpoint 7
- generated · open_result · msg_id absent, envelope "x"
- generated · open_result · msg_id absent, my_pkcs8 7
- generated · open_result · msg_id absent, my_spki 7
- generated · open_result · msg_id absent, now 7
- generated · open_result · msg_id absent, pins "x"
- generated · open_result · msg_id absent, expected_root 7
- generated · open_result · msg_id absent, expected_endpoint 7
- generated · open_result · now absent, envelope "x"
- generated · open_result · now absent, my_pkcs8 7
- generated · open_result · now absent, my_spki 7
- generated · open_result · now absent, msg_id 7
- generated · open_result · now absent, pins "x"
- generated · open_result · now absent, expected_root 7
- generated · open_result · now absent, expected_endpoint 7

### `parse_certificate` — 28 cases · whole on success

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
- parse_certificate of a leaf holding a key outside the profile: rsa
- parse_certificate of a leaf holding a key outside the profile: P-384
- parse_certificate of a leaf holding a key outside the profile: X25519
- parse_certificate of a leaf holding a key outside the profile: Ed25519 with a NULL
- generated · parse_certificate · {}
- generated · parse_certificate · the hostile object
- generated · parse_certificate · der absent
- generated · parse_certificate · der null
- generated · parse_certificate · an undeclared member
- generated · parse_certificate · der holding a key outside the profile

### `prf_salt` — 3 cases · whole on success

- prf_salt
- generated · prf_salt · {}
- generated · prf_salt · an undeclared member

### `profile_error` — 21 cases · whole on success

- profile_error of a leaf read as a root
- profile_error of a root read as a leaf
- profile_error with a kind nobody has
- profile_error of that leaf
- profile_error with nothing to work from
- profile_error of a leaf read as a leaf
- profile_error of a root read as a root
- profile_error of a leaf holding a key outside the profile: rsa
- profile_error of a leaf holding a key outside the profile: P-384
- profile_error of a leaf holding a key outside the profile: X25519
- profile_error of a leaf holding a key outside the profile: Ed25519 with a NULL
- generated · profile_error · {}
- generated · profile_error · the hostile object
- generated · profile_error · der absent
- generated · profile_error · der null
- generated · profile_error · kind absent
- generated · profile_error · kind null
- generated · profile_error · an undeclared member
- generated · profile_error · der holding a key outside the profile
- generated · profile_error · der absent, kind 7
- generated · profile_error · kind absent, der 7

### `public_key` — 12 cases · whole on success

- public_key of a key that is not one
- public_key with no argument
- public_key of an RSA key
- public_key with nothing to work from
- public_key
- public_key of a P-256 key
- public_key from an Ed25519 PKCS #8 whose algorithm carries a NULL
- generated · public_key · {}
- generated · public_key · pkcs8 absent
- generated · public_key · pkcs8 null
- generated · public_key · an undeclared member
- generated · public_key · pkcs8 holding a key outside the profile

### `root_tbs` — 27 cases · whole on success

- root_tbs
- root_tbs with no key
- root_tbs with a serial that is too long
- root_tbs of a key outside the profile: rsa
- root_tbs of a key outside the profile: P-384
- root_tbs of a key outside the profile: X25519
- root_tbs of a key outside the profile: Ed25519 with a NULL
- generated · root_tbs · {}
- generated · root_tbs · cn absent
- generated · root_tbs · cn null
- generated · root_tbs · spki absent
- generated · root_tbs · spki null
- generated · root_tbs · not_before absent
- generated · root_tbs · not_before null
- generated · root_tbs · serial ""
- generated · root_tbs · serial 7
- generated · root_tbs · an undeclared member
- generated · root_tbs · spki holding a key outside the profile
- generated · root_tbs · cn absent, spki 7
- generated · root_tbs · cn absent, not_before 7
- generated · root_tbs · cn absent, serial 7
- generated · root_tbs · spki absent, cn 7
- generated · root_tbs · spki absent, not_before 7
- generated · root_tbs · spki absent, serial 7
- generated · root_tbs · not_before absent, cn 7
- generated · root_tbs · not_before absent, spki 7
- generated · root_tbs · not_before absent, serial 7

### `seal_request` — 81 cases · whole on success

- seal_request with no recipient
- seal_request with a form nobody has
- seal_request with a method nobody has
- seal_request with an empty msg_id
- seal_request whose exp is a month past its ts
- seal_request
- seal_request with no msg_id at all
- seal_request with an ephemeral_seed, which neither port takes
- seal_request with no params
- seal_request with exp 0
- seal_request with ts 0
- seal_request with an empty method and an empty cty
- seal_request with ts -0
- seal_request with exp -0
- seal_request with neither msg_id nor sender_chain
- seal_request with nothing to work from
- seal_request in the chain form with no sender_chain
- seal_request whose sender_chain is not base64url
- seal_request whose sender_chain is not a list
- seal_request to a leaf holding an Ed25519 key of small order: the identity
- seal_request to a leaf holding an Ed25519 key of small order: y = -1
- generated · seal_request · {}
- generated · seal_request · recipient_leaf absent
- generated · seal_request · recipient_leaf null
- generated · seal_request · sender_pkcs8 absent
- generated · seal_request · sender_pkcs8 null
- generated · seal_request · msg_id absent
- generated · seal_request · msg_id null
- generated · seal_request · ts absent
- generated · seal_request · ts null
- generated · seal_request · form ""
- generated · seal_request · form 7
- generated · seal_request · sender_chain "x"
- generated · seal_request · exp "7"
- generated · seal_request · ephemeral_seed ""
- generated · seal_request · ephemeral_seed 7
- generated · seal_request · method ""
- generated · seal_request · method 7
- generated · seal_request · params ""
- generated · seal_request · cty ""
- generated · seal_request · cty 7
- generated · seal_request · an undeclared member
- generated · seal_request · recipient_leaf holding a key outside the profile
- generated · seal_request · sender_pkcs8 holding a key outside the profile
- generated · seal_request · sender_chain holding a key outside the profile
- generated · seal_request · recipient_leaf absent, sender_pkcs8 7
- generated · seal_request · recipient_leaf absent, form 7
- generated · seal_request · recipient_leaf absent, sender_chain "x"
- generated · seal_request · recipient_leaf absent, msg_id 7
- generated · seal_request · recipient_leaf absent, ts "7"
- generated · seal_request · recipient_leaf absent, exp "7"
- generated · seal_request · recipient_leaf absent, ephemeral_seed 7
- generated · seal_request · recipient_leaf absent, method 7
- generated · seal_request · recipient_leaf absent, cty 7
- generated · seal_request · sender_pkcs8 absent, recipient_leaf 7
- generated · seal_request · sender_pkcs8 absent, form 7
- generated · seal_request · sender_pkcs8 absent, sender_chain "x"
- generated · seal_request · sender_pkcs8 absent, msg_id 7
- generated · seal_request · sender_pkcs8 absent, ts "7"
- generated · seal_request · sender_pkcs8 absent, exp "7"
- generated · seal_request · sender_pkcs8 absent, ephemeral_seed 7
- generated · seal_request · sender_pkcs8 absent, method 7
- generated · seal_request · sender_pkcs8 absent, cty 7
- generated · seal_request · msg_id absent, recipient_leaf 7
- generated · seal_request · msg_id absent, sender_pkcs8 7
- generated · seal_request · msg_id absent, form 7
- generated · seal_request · msg_id absent, sender_chain "x"
- generated · seal_request · msg_id absent, ts "7"
- generated · seal_request · msg_id absent, exp "7"
- generated · seal_request · msg_id absent, ephemeral_seed 7
- generated · seal_request · msg_id absent, method 7
- generated · seal_request · msg_id absent, cty 7
- generated · seal_request · ts absent, recipient_leaf 7
- generated · seal_request · ts absent, sender_pkcs8 7
- generated · seal_request · ts absent, form 7
- generated · seal_request · ts absent, sender_chain "x"
- generated · seal_request · ts absent, msg_id 7
- generated · seal_request · ts absent, exp "7"
- generated · seal_request · ts absent, ephemeral_seed 7
- generated · seal_request · ts absent, method 7
- generated · seal_request · ts absent, cty 7

### `seal_result` — 60 cases · whole on success

- seal_result
- seal_result with no recipient
- seal_result with neither a result nor an error
- seal_result with ts 0 and exp 0
- seal_result with a chain of one and neither a result nor an error
- seal_result with a chain and neither a result nor an error
- seal_result with nothing to work from
- seal_result of a real result
- seal_result whose sender_chain is not base64url
- seal_result to an Ed25519 key of small order: the identity
- seal_result to an Ed25519 key of small order: y = -1
- generated · seal_result · {}
- generated · seal_result · recipient_spki absent
- generated · seal_result · recipient_spki null
- generated · seal_result · sender_pkcs8 absent
- generated · seal_result · sender_pkcs8 null
- generated · seal_result · msg_id absent
- generated · seal_result · msg_id null
- generated · seal_result · ts absent
- generated · seal_result · ts null
- generated · seal_result · form ""
- generated · seal_result · form 7
- generated · seal_result · sender_chain "x"
- generated · seal_result · exp "7"
- generated · seal_result · ephemeral_seed ""
- generated · seal_result · ephemeral_seed 7
- generated · seal_result · result ""
- generated · seal_result · error ""
- generated · seal_result · an undeclared member
- generated · seal_result · recipient_spki holding a key outside the profile
- generated · seal_result · sender_pkcs8 holding a key outside the profile
- generated · seal_result · sender_chain holding a key outside the profile
- generated · seal_result · recipient_spki absent, sender_pkcs8 7
- generated · seal_result · recipient_spki absent, form 7
- generated · seal_result · recipient_spki absent, sender_chain "x"
- generated · seal_result · recipient_spki absent, msg_id 7
- generated · seal_result · recipient_spki absent, ts "7"
- generated · seal_result · recipient_spki absent, exp "7"
- generated · seal_result · recipient_spki absent, ephemeral_seed 7
- generated · seal_result · sender_pkcs8 absent, recipient_spki 7
- generated · seal_result · sender_pkcs8 absent, form 7
- generated · seal_result · sender_pkcs8 absent, sender_chain "x"
- generated · seal_result · sender_pkcs8 absent, msg_id 7
- generated · seal_result · sender_pkcs8 absent, ts "7"
- generated · seal_result · sender_pkcs8 absent, exp "7"
- generated · seal_result · sender_pkcs8 absent, ephemeral_seed 7
- generated · seal_result · msg_id absent, recipient_spki 7
- generated · seal_result · msg_id absent, sender_pkcs8 7
- generated · seal_result · msg_id absent, form 7
- generated · seal_result · msg_id absent, sender_chain "x"
- generated · seal_result · msg_id absent, ts "7"
- generated · seal_result · msg_id absent, exp "7"
- generated · seal_result · msg_id absent, ephemeral_seed 7
- generated · seal_result · ts absent, recipient_spki 7
- generated · seal_result · ts absent, sender_pkcs8 7
- generated · seal_result · ts absent, form 7
- generated · seal_result · ts absent, sender_chain "x"
- generated · seal_result · ts absent, msg_id 7
- generated · seal_result · ts absent, exp "7"
- generated · seal_result · ts absent, ephemeral_seed 7

### `sign` — 15 cases · whole on success

- sign with a public key
- sign with no data
- sign with nothing to work from
- sign
- sign with a P-256 key
- sign with an Ed25519 PKCS #8 whose algorithm carries a NULL
- generated · sign · {}
- generated · sign · pkcs8 absent
- generated · sign · pkcs8 null
- generated · sign · data absent
- generated · sign · data null
- generated · sign · an undeclared member
- generated · sign · pkcs8 holding a key outside the profile
- generated · sign · pkcs8 absent, data 7
- generated · sign · data absent, pkcs8 7

### `signing_request_check` — 95 cases · whole on success

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
- generated · signing_request_check · {}
- generated · signing_request_check · the hostile object
- generated · signing_request_check · request absent
- generated · signing_request_check · request null
- generated · signing_request_check · origin absent
- generated · signing_request_check · origin null
- generated · signing_request_check · now absent
- generated · signing_request_check · now null
- generated · signing_request_check · root_spkis "x"
- generated · signing_request_check · an undeclared member
- generated · signing_request_check · root_spkis holding a key outside the profile
- generated · signing_request_check · request absent, origin 7
- generated · signing_request_check · request absent, now 7
- generated · signing_request_check · request absent, root_spkis "x"
- generated · signing_request_check · origin absent, request "x"
- generated · signing_request_check · origin absent, now 7
- generated · signing_request_check · origin absent, root_spkis "x"
- generated · signing_request_check · now absent, request "x"
- generated · signing_request_check · now absent, origin 7
- generated · signing_request_check · now absent, root_spkis "x"

### `suite_for` — 14 cases · whole on success

- suite_for an spki that is not one
- suite_for an Ed25519 key
- suite_for a P-256 key
- suite_for an RSA key
- suite_for with nothing to work from
- suite_for a key outside the profile: rsa
- suite_for a key outside the profile: P-384
- suite_for a key outside the profile: X25519
- suite_for a key outside the profile: Ed25519 with a NULL
- generated · suite_for · {}
- generated · suite_for · spki absent
- generated · suite_for · spki null
- generated · suite_for · an undeclared member
- generated · suite_for · spki holding a key outside the profile

### `validate_chain` — 62 cases · whole on success

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
- validate_chain with an expected_root that is empty
- validate_chain with an expected_endpoint that is empty
- validate_chain of a leaf naming https://[2001:db8::1%25eth0]/mcp
- validate_chain of a leaf naming https://[2001:db8::1%eth0]/mcp
- validate_chain of a leaf holding a key outside the profile: rsa
- validate_chain of a leaf holding a key outside the profile: P-384
- validate_chain of a leaf holding a key outside the profile: X25519
- validate_chain of a leaf holding a key outside the profile: Ed25519 with a NULL
- generated · validate_chain · {}
- generated · validate_chain · the hostile object
- generated · validate_chain · chain absent
- generated · validate_chain · chain null
- generated · validate_chain · now absent
- generated · validate_chain · now null
- generated · validate_chain · expected_root ""
- generated · validate_chain · expected_root 7
- generated · validate_chain · expected_endpoint ""
- generated · validate_chain · expected_endpoint 7
- generated · validate_chain · an undeclared member
- generated · validate_chain · chain holding a key outside the profile
- generated · validate_chain · chain absent, now 7
- generated · validate_chain · chain absent, expected_root 7
- generated · validate_chain · chain absent, expected_endpoint 7
- generated · validate_chain · now absent, chain "x"
- generated · validate_chain · now absent, expected_root 7
- generated · validate_chain · now absent, expected_endpoint 7

### `vault_open` — 24 cases · whole on success

- vault_open of what vault_seal made
- vault_open of what vault_seal made, with t spelled 1.0
- vault_open of what vault_seal made, with m_kib spelled 8192.0
- vault_open of what vault_seal made, with p spelled 1e0
- vault_open of what vault_seal made, with m_kib 8192.5
- vault_open with a passphrase that is wrong
- vault_open of a document that is not a vault
- vault_open of no document at all
- vault_open of what vault_seal made with the most passes the contract allows
- vault_open of what vault_seal made with the most lanes the contract allows
- vault_open of a document with a KDF one pass over the ceiling
- vault_open of a document with a KDF below the floor
- vault_open of a document with a KDF whose m_kib does not fit in 32 bits
- vault_open of a document with a KDF with no passes
- vault_open of a document with a KDF with too many lanes
- vault_open of a document with a KDF nobody implements
- vault_open with nothing to work from
- generated · vault_open · {}
- generated · vault_open · passphrase absent
- generated · vault_open · passphrase null
- generated · vault_open · vault absent
- generated · vault_open · vault null
- generated · vault_open · an undeclared member
- generated · vault_open · vault absent, passphrase 7

### `vault_seal` — 39 cases · whole on success

- vault_seal
- vault_seal of a record
- vault_seal of an earlier generation
- vault_seal of a plaintext with no generation
- vault_seal with a nonce that is not 12 bytes
- vault_seal with an empty passphrase
- vault_seal with no plaintext
- vault_seal with the most passes the contract allows
- vault_seal with the most lanes the contract allows
- vault_seal with one lane more than the contract allows
- vault_seal with one KiB less than the contract allows
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
- vault_seal with an empty passphrase and no plaintext
- generated · vault_seal · {}
- generated · vault_seal · passphrase absent
- generated · vault_seal · passphrase null
- generated · vault_seal · plaintext absent
- generated · vault_seal · plaintext null
- generated · vault_seal · salt 7
- generated · vault_seal · nonce ""
- generated · vault_seal · nonce 7
- generated · vault_seal · an undeclared member
- generated · vault_seal · passphrase absent, kdf "x"
- generated · vault_seal · passphrase absent, salt 7
- generated · vault_seal · passphrase absent, nonce 7
- generated · vault_seal · plaintext absent, passphrase 7
- generated · vault_seal · plaintext absent, kdf "x"
- generated · vault_seal · plaintext absent, salt 7
- generated · vault_seal · plaintext absent, nonce 7

### `verify` — 25 cases · whole on success

- verify a signature that is not one
- verify with an empty signature
- verify with an RSA key
- verify with nothing to work from
- verify a signature the other port made
- verify with args holding a lone high surrogate
- verify with a key outside the profile: rsa
- verify with a key outside the profile: P-384
- verify with a key outside the profile: X25519
- verify with a key outside the profile: Ed25519 with a NULL
- generated · verify · {}
- generated · verify · spki absent
- generated · verify · spki null
- generated · verify · data absent
- generated · verify · data null
- generated · verify · sig absent
- generated · verify · sig null
- generated · verify · an undeclared member
- generated · verify · spki holding a key outside the profile
- generated · verify · spki absent, data 7
- generated · verify · spki absent, sig 7
- generated · verify · data absent, spki 7
- generated · verify · data absent, sig 7
- generated · verify · sig absent, spki 7
- generated · verify · sig absent, data 7

### `version` — 11 cases · not a dispatched function

- version with a member it does not declare
- version with a number past the largest double
- version with a negative number past the largest double
- version with the first number that rounds past the largest double
- version with the largest double
- version with a number too small to be anything but 0
- version with a number past the largest double, in a string
- version with containers nested 128 deep
- version with containers nested 127 deep
- version with a number past the largest double before containers nested 129 deep
- version with containers nested 129 deep before a number past the largest double

### `wallet_issue` — 85 cases · whole on success

- wallet_issue
- wallet_issue from a vault that carries a ledger
- wallet_issue without a record
- wallet_issue for a root the vault does not hold
- wallet_issue of the root's own key
- wallet_issue of a request that is a truncated SEQUENCE
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
- wallet_issue with valid_days spelled -0
- wallet_issue with valid_days spelled 365.0
- wallet_issue over a ledger that reads
- wallet_issue with nothing to work from
- wallet_issue: a request carrying a CARD-held sibling root's key
- generated · wallet_issue · {}
- generated · wallet_issue · the hostile object
- generated · wallet_issue · vault_plaintext absent
- generated · wallet_issue · vault_plaintext null
- generated · wallet_issue · record_plaintext absent
- generated · wallet_issue · record_plaintext null
- generated · wallet_issue · root_fingerprint absent
- generated · wallet_issue · root_fingerprint null
- generated · wallet_issue · csr absent
- generated · wallet_issue · csr null
- generated · wallet_issue · now absent
- generated · wallet_issue · now null
- generated · wallet_issue · valid_days "7"
- generated · wallet_issue · move "yes"
- generated · wallet_issue · an undeclared member
- generated · wallet_issue · csr holding a key outside the profile
- generated · wallet_issue · vault_plaintext absent, record_plaintext "x"
- generated · wallet_issue · vault_plaintext absent, root_fingerprint 7
- generated · wallet_issue · vault_plaintext absent, csr 7
- generated · wallet_issue · vault_plaintext absent, now 7
- generated · wallet_issue · vault_plaintext absent, valid_days "7"
- generated · wallet_issue · vault_plaintext absent, move "yes"
- generated · wallet_issue · record_plaintext absent, vault_plaintext "x"
- generated · wallet_issue · record_plaintext absent, root_fingerprint 7
- generated · wallet_issue · record_plaintext absent, csr 7
- generated · wallet_issue · record_plaintext absent, now 7
- generated · wallet_issue · record_plaintext absent, valid_days "7"
- generated · wallet_issue · record_plaintext absent, move "yes"
- generated · wallet_issue · root_fingerprint absent, vault_plaintext "x"
- generated · wallet_issue · root_fingerprint absent, record_plaintext "x"
- generated · wallet_issue · root_fingerprint absent, csr 7
- generated · wallet_issue · root_fingerprint absent, now 7
- generated · wallet_issue · root_fingerprint absent, valid_days "7"
- generated · wallet_issue · root_fingerprint absent, move "yes"
- generated · wallet_issue · csr absent, vault_plaintext "x"
- generated · wallet_issue · csr absent, record_plaintext "x"
- generated · wallet_issue · csr absent, root_fingerprint 7
- generated · wallet_issue · csr absent, now 7
- generated · wallet_issue · csr absent, valid_days "7"
- generated · wallet_issue · csr absent, move "yes"
- generated · wallet_issue · now absent, vault_plaintext "x"
- generated · wallet_issue · now absent, record_plaintext "x"
- generated · wallet_issue · now absent, root_fingerprint 7
- generated · wallet_issue · now absent, csr 7
- generated · wallet_issue · now absent, valid_days "7"
- generated · wallet_issue · now absent, move "yes"

## The 3 known divergences

Cases that FAIL today, each excused by `js/cases/known-divergences.json` only while it fails exactly
as its entry says, and each waiting on the audit finding named beside it (the port-parity audit of
2026-09-29). None of them is proven; they are here so that the list is read, not assumed.

- a function nobody defines, with args that are a list — R34 (wasm off the contract, differ)
- generated · vault_seal · kdf "x" — R28, C4 (wasm off the contract, wasm not as expected, go not as expected)
- generated · vault_seal · salt "" — R29, C6 (differ)
