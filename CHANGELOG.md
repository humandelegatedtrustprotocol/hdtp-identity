# Changelog

One version for everything in this repository: the Rust crates (`hdtp-identity`,
`hdtp-identity-wasm`, `hdtp-limits`, the `hdtp` CLI), the Go module `github.com/humandelegatedtrustprotocol/hdtp-identity/go` and the
Wasm package. A release is tagged `vX.Y.Z` and `go/vX.Y.Z` on one commit (`make release`), and its
GitHub release carries the Wasm package, the CLI binaries, `manifest.json` and `SHA256SUMS`.
Versions follow semver; before 1.0.0 a minor version may change the contract (`CONTRACT.md`).

Entries go under `## Unreleased` as they land; `make release` dates them.

## Unreleased

## 0.9.0 — 2026-10-11

- **What a host changes (a change of the contract, hence 0.9.0).** `export_read_messages` requires
  `left_out_threads`, the ids `export_read` answered under that name, and `export_read_end` requires
  `kept_msg_ids` and `media_kept`; each absent or null is `<name> is required`. An
  importer writes no thread in `left_out_threads` and no message in `left_out`, writes each
  `reply_to` in `reply_to_null` as null, and writes no file in `media_left_out`. `decide` answers two
  refusals it did not: `too_large` and `bad_request` for a contact's `thread_id` at `send_message`,
  `send_media` and `book_slot`, with no `seen` effect. Each is described below.

- **A `thread_id` has two forms, and `decide` refuses any other (SEP-0006, SPEC §7 of the draft).**
  A `thread_id` is 1 to 64 ASCII letters and digits, or a UUID in RFC 9562's textual form in lower
  case. At `send_message`, `send_media` and `book_slot`, a contact's call whose
  `arguments.thread_id` is over 64 bytes is answered `too_large` (`thread_id over 64 bytes`), checked
  first; one of neither form, the empty string included, `bad_request` (`thread_id of neither form`);
  and one that is not a string `bad_request` (`thread_id is not a string`). Absent or null is no
  `thread_id`. The check runs at the contact tier, after a `pending_out` pin's answer, in both forms;
  the refusal names `root`, `endpoint`, `leaf`, `form` and `msg_id`, as `pending_approval` does, so a
  host can seal it back, and carries no `seen` effect, so nothing is recorded; the pin's own moves
  stand. This changes what a host built on this library accepts: a call from a 1.0 sender whose
  `thread_id` is of neither form is refused. `is_thread_id` (Rust) and `IsThreadID` (Go) are the one
  test of the two forms, and `thread_id_refusal` (Rust) and `ThreadIDRefusal` (Go) the one refusal,
  for a host door that takes a call outside an envelope, as `decide_chain`'s does. `js/intrude.mjs` runs the seed's 22 new `thread` scenarios by their names on
  both ports (180 of 180 agree with the seed of hdtp-spec #62).

- **The writer re-issues an id as `r` and the first 62 hex digits of its sha256 (63 characters), no
  longer `r-` and 62 (64).** The new form is of the two forms of a `thread_id`, so a re-issued thread
  id reads back as a thread. The rule is otherwise 0.8.1's: a thread id, a message's `thread`, a
  `reply_to` and an incoming `msg_id` that read as a private key, and any of them, an outgoing
  `msg_id` included, already `r` and 62 lowercase hex digits, are re-issued, with every reference
  alike; an outgoing `msg_id` that reads as a key is refused. An `r-` id a 0.8.1 writer issued is
  now written as it is, and is a thread id of neither form. The writer no longer refuses a thread whose id is
  empty (`threads[<i>], column id: empty`): like every id it does not re-issue, it is written as the
  host holds it, and the reader leaves it out.

- **The reader leaves out a thread whose id is of neither form, and never refuses the file for it
  (SPEC §9.2, Import, step 3).** Such a thread, the empty id included (which was refused, `column id:
  empty`), is held to every other rule of the file and counted, and `export_read` answers it in
  `left_out_threads` (`id`, `contact`, `reason`) instead of `threads`. `export_read_messages` takes
  the left-out ids as `left_out_threads` (required) and answers a message of such a thread, checked
  as every message is, in `left_out`, and the files the other messages name in `media_kept`.
  `export_read_end` takes `kept_msg_ids` and `media_kept` (both required), still checks every
  message, and answers `reply_to_null` (each `reply_to` that names no kept message, which a host
  writes as null) and `media_left_out` (each file only left-out messages name, which it does not
  write). Go's `ReadExportZip` and the `hdtp` CLI apply both: `ExportContents.LeftOutThreads` and
  `Contents.left_out_threads` name the threads, and `hdtp contacts import` prints each one. The
  export corpus gains `valid-export-with-a-left-out-thread.zip` and
  `valid-export-with-a-0.8.1-reissued-thread-id.zip` (62 cases, 7 accepted). The memory tests of
  `export_read_end` count the new list in the arguments they measure against.

- SEP-0006's MUSTs are in the specification's draft; `js/musts.json` and PROOFS.md read 1.0.0 and do
  not register them yet.

## 0.8.1 — 2026-10-11

- **This library's writer no longer lets a contact stop the owner's export with text that reads as
  a private key, and leaves no conversation, message or file out for it.** The writer refused the
  whole export when any cell or message member held such text, so a contact could block it by
  choosing a thread id, a `msg_id`, a topic or a display name like `MAoCAQAwAwYBAAQA`, which decodes
  to a PKCS #8 key. Such text is now never refused and never written. A contact's `display_name`, a
  removed thread's `contact_display_name` and a thread's `topic` are written empty, and an incoming
  file's `filename` or `mime` is written `file` or `application/octet-stream`, the file kept: what
  was blanked or replaced is not in the file. A thread id, a `msg_id` (unless the message went out)
  and a `reply_to` that read as a key are written as `r-` and the first 62 hex digits of the id's
  sha256, as is an id already of that form, so no two ids are written as one; the same id is written
  the same way in every call, so `threads.csv`, each message's `thread` and every reply hold together
  and the conversation reads back whole. A thread id and a topic are rewritten whichever side wrote
  them, since the format cannot tell (SPEC §7). The re-issued ids are recorded nowhere, so after an
  import a contact who continues a re-issued thread, or sends a re-issued `msg_id` again, reaches the
  importing host as a new thread or a new message (hosts dedupe by `msg_id` and adopt the peer's
  thread id), and a file re-imported beside the conversation it came from adds a thread row, empty of
  the original's messages, next to the original. What the owner's side wrote is still refused: the
  owner's `name` and `contact_name` for a contact, `owner_name`, `tool`, a message's `id`, and an
  outgoing message's `msg_id`, `filename` and `mime`. The reader is unchanged and refuses key
  material wherever it is (SPEC §9.2).

- **The memory tests run no dynamic code.** `js/wasm-memory.mjs` gives each case a fresh Wasm instance
  in a worker thread of its own, which loads the node package unchanged, where it evaluated the
  package's source with `new Function`; `js/export-memory.test.mjs` now requires each fresh instance
  to grow, by at least its argument where it reads one, so a case run on a reused instance fails.

- **`decide` refuses a `sig` that is not base64url in its one spelling before the envelope is
  opened, in either form.** Both ports read `sig` leniently: one that did not read became a
  signature that failed, which the chain form refused (`envelope_invalid`) and the small form
  answered `chain_required`, so one envelope had two answers by its form alone. `sig` is now read
  after the `kid`, the suite and the `enc` length and before the open, and one that does not read
  (padding, the standard alphabet, spare bits set) is `envelope_invalid`, `sig is not base64url`,
  in both forms (SPEC §13.1). An empty `sig` reads, as the one spelling of zero bytes, and fails as
  a signature (§13.3 step 7): `chain_required` in the small form, `signature is not the chain's
  leaf key` in the chain form. Go's `Envelope` cannot tell an absent or null `sig` from an empty
  one, so a host checks presence before it calls `Decide`. CONTRACT §5 says so; the seed's
  `receive()` refuses the same `sig` at the same point (hdtp-spec #61), and `js/intrude.mjs` runs
  its small-form respelling scenario on both ports.

- **The export growth tests measure CPU time, not the wall clock.** The Go test reads the process's
  CPU time (`getrusage`) with the collector run before and kept off during each measurement; the
  Rust test reads the CPU clock of its own thread (`CLOCK_THREAD_CPUTIME_ID`). Both are unix-only
  now, and `libc` is a unix dev-dependency of the core.

- **No path from the writer's machine in tracked text or a commit message.** `gate.sh` refuses a
  tracked text line carrying a home-directory path (under `/Users` or `/home`), naming file and
  line, and `githooks/commit-msg` refuses one in a commit message; the gate holds the two copies of
  the pattern to each other.

- **No sign-off.** CONTRIBUTING no longer asks for a `Signed-off-by` line, and the pull-request
  template drops its checkbox: there is no sign-off and no CLA, and section 5 of the Apache License
  2.0 covers a contribution.

- **The darwin-arm64 `hdtp` binary carries no path from the machine that built it.** 0.8.0's held
  230 paths of a dependency's source file under the builder's home directory (its cargo
  home); `scripts/build-cli.sh` now builds it with the remaps `js/build.sh` gives the Wasm, so they
  read `/cargo/registry/src/...`. `make release` refuses an asset that holds the home directory of
  the machine cutting it.


## 0.8.0 — 2026-10-10

- **An export carries a former contact's conversation (SEP-0004).** A removed thread is a row of
  `threads.csv` whose `contact` is not a root of `contacts.csv`. It carries the names the contact is
  known by in two new columns, `contact_name` and `contact_display_name`, which are empty on every
  other thread. `threads.csv` takes the longer header only when a removed thread exists, so a file
  without one is the file this library wrote before, and the manifest does not change. A removed
  thread's root is a fingerprint and not the owner's. Its names are at most 200 characters (the
  display name cut, as a contact's is) and the same on every removed thread of that root.
  `export_read` answers the two names on a removed thread and on no other; `export_write` takes
  them on a removed thread and refuses them on any other. A message's `contact` may be a removed
  thread's: its refusal now reads `names no contact in contacts.csv and no removed thread` for every
  file, where it read `names no contact in contacts.csv`. A threads.csv header that is neither of the
  two is refused naming both. The corpus gains `valid-export-with-removed-thread.zip`,
  `valid-export-with-a-nameless-removed-thread.zip` and fourteen refusals (60 cases);
  `valid-export.zip` and `valid-book.zip` are byte for byte what they were. The reader keeps a removed
  thread's names by the row, never as copies: a file whose every thread is removed with a root of its
  own allocates 7.5–7.7× its threads.csv in the Go port and peaks at 3.3–3.4× in the core
  (11.3–11.6× and 6.1× before), and the largest such file grows a Wasm instance by 76.4 MB; the memory
  tests hold all three at N and 4N rows and at the largest file. `hdtp vectors corpus --owner` carries
  the owner's alias with the owner, so the owner-alias case names the new owner's alias.
- **A member's control characters have a ceiling, and a writer drops them where a contact writes.**
  A JSON answer writes U+0001 as six bytes (`\u0001`; every character below U+0020 but tab, line
  feed, carriage return, U+0008 and U+000C so), so a legal threads.csv of removed threads named with
  200 U+0001 each grew a Wasm instance by 413.9 MB, the core by 15.8× and the Go port by 30× its CSV. `export_read` now counts them in
  `contacts.csv` and `threads.csv` before parsing and refuses a member with more than 65,536
  (`ExportLimits.control_characters`, a ceiling of this library's as a host's own, SPEC §9.2): such a
  file is refused at 2.4× its argument in the Go port, 2.0–2.4× its CSV in the core and 1.4–1.6× its
  argument in Wasm; 64,000 removed threads holding 65,536 of them read at 7.6×, 3.4× and 4.85×. The
  answer's room now counts the two bytes of each tab, line feed and carriage return too: the largest threads.csv whose
  every topic is 1000 line feeds, which this writer writes, read at 7.91× in the Go port (9.15×
  before, its buffer doubling), 2.98× in the core and 82.4 MB in Wasm (118.0 MB); one whose every
  thread is removed under one root with names of 200 characters at 5.67×, 2.41× and 67.6 MB.
  `export_write` drops them from every name (`name`, `display_name`, `contact_name`,
  `contact_display_name`) and a thread's `topic`, before a name's length is checked. An `id` is
  written as given: a thread id is chosen by whoever sends first (SPEC §7), so a host that takes one
  holding them can still write a file this reader refuses; that is bounded where the id enters, not
  here.
- **A fingerprint has one spelling.** `sha256:` and 43 base64url characters whose last is one of
  `AEIMQUYcgkosw048`: the two spare bits are zero (RFC 4648 §3.5). Any other last character spells the
  same 32 bytes again, a second name for one root: a live contact's root so spelled would have read as
  a removed thread, the owner's as a removed thread that is not the owner, and two contacts.csv rows
  as two roots. Both ports refuse it everywhere a fingerprint is read (SEP-0004, SPEC §2), the
  `expect_root` a chain is verified against included, through the one shared check; the corpus holds
  the three aliases.
- **The seed's six stale-sender scenarios run on both ports.** `js/intrude.mjs` carries the
  scenarios hdtp-spec's `vectors/intrude.mjs` gained for the stolen leaf key in the small form of
  §13.2 and for the sender a renewal has not reached (§2): the superseded key the host still holds
  opens what a contact seals to it, until the leaf's `notAfter`, and so does whoever holds that
  key; once the renewal reaches the contact, what it seals next is closed to it, and a replay of
  the superseded chain does not roll the pin back. Verdicts agree with the seed on both ports.
- **The repository is written for a public reader.** `NOTICE`, `SECURITY.md`, `CONTRIBUTING.md`,
  `GOVERNANCE.md`, `MAINTAINERS.md`, `CODE_OF_CONDUCT.md`, `CITATION.cff` and `.github/` (two issue
  forms, the pull-request template, `CODEOWNERS`; no workflow), modelled on hdtp-spec's; the README
  in the public form (`go get …/go@v0.7.3`, Cargo by git tag, the Wasm from the release asset), with
  every number read from the tree (seven version copies, the pinned `.wasm` at 863,199 bytes, Node 22,
  the pin's `linux/arm64` builder); `gate.sh`, the hooks, `js/reproduce.sh` and the `Makefile` no
  longer call hdtp-spec private, and `make verify-release` no longer rewrites the remote to SSH;
  the limits vectors' batondeck citations carry their measured dates, as a private repository's.

## 0.7.3 — 2026-10-07

- **SPEC §9 9.#4 follows SEP-0003.** `js/musts.json` holds the amended rule (hash `f835c346eb45`):
  a left address is kept for 24 hours for the account that held it, which may be one the person
  shares at the host. The `hdtp` wallet's move notice says so.

## 0.7.2 — 2026-10-07

- **`hdtp id issue` counts the days the leaf has.** A leaf ended with its root printed the days
  asked beside the shorter span; the consent line now reads `(31 days; 365 asked)`.
- **`hdtp id issue` says each thing once, on the consent screen where the person decides**: that
  the leaf ends with its root, that the host is new, that the identity moves. The core's warnings of
  the same facts are no longer printed again after the signature.
- **PROOFS.md says which elsewhere rows name an artefact and which a role.** Of the 30 MUSTs held
  outside this repository, 16 name the artefact that holds them and 14 the implementation role, by
  declaration, as hdtp-spec's §12 (The record) now allows; the header had said every one named an
  artefact.
- **SPEC §4 4.#1 names the tests that hold it**: hdtp-gateway's `TestP1ExitTwoNodesPairAndMessage`
  (the landing's chain validates and its leaf is the card's certificate) and `TestVerifyOfferRefusals`
  (the redeemer refuses a chain that is not the card's), in place of `TestLandingNoOracle404`, which
  holds the not-found sentence and no MUST. Its gap is named: no test fails when the node's redeemer
  ignores the chain's validation, since its other checks refuse every case.

## 0.7.1 — 2026-10-06

- **SPEC §9 9.#4 follows SEP-0002.** `js/musts.json` holds the amended rule (hash `9c1f6a96da61`):
  an address left, deleted or moved, is kept for the person for 24 hours, then freed.
- **The `hdtp` wallet's move notice states that rule** in the web wallet's words; it no longer says
  the address stays reserved until the old leaf expires.

- **The gate holds hdtp-spec's JSON Schema to this contract.** `gate.sh`, and so the pre-push hook
  and `make release`, runs hdtp-spec's `schema/gen.mjs --check` with `HDTP_IDENTITY_DIR` set to this
  tree: the spec's committed `schema/*/schema.json` must be what this `contract/contract.json`
  generates. 0.7.0 shipped a contract change that schema did not carry, found only when the
  whitepaper's publish ran the spec's own `schema:check`. On a difference the gate fails and names
  the fix: regenerate the schema in hdtp-spec first, as a spec PR.

## 0.7.0 — 2026-10-05

- **A card whose folding a paste damaged reads (hdtp-spec SEP-0001, draft §3 *Reading a card*).**
  `card_decode` (Go: `DecodeCard`), in both ports and the seed: after RFC 6350 unfolding,
  `X-HDTP-CERT` takes every following line that does not start a property
  (`[group.]NAME[;params]:`), blank lines included, and loses every space, tab, CR and LF before it
  is read. A card pasted through a chat — continuations without their leading space, blank lines
  between them — was refused `certificate does not parse` (seen on staging, 2026-10-05). A line that
  starts a property is never taken into the certificate. A certificate with a space or a tab inside
  it now reads (it was `not base64url`); a vertical tab, a no-break space and every other character
  outside base64url are refused as before. A cut certificate is still refused by the DER parse; a
  changed character either fails to parse or reads as a certificate its root did not sign, which
  reading cannot find (a card carries no root) — the position of a card altered in transit, as before
  (`tests/card_paste.rs`, `go/card_paste_test.go`, `js/cases/cards.mjs`).

## 0.6.0 — 2026-10-04

- **A root may carry an end date (SPEC 1.0.0 as amended 2026-10-04, §14.1, §14.2, §2.2).** Every
  root still has none by default (`99991231235959Z`) and is never rotated; `build_root` and
  `root_tbs` take an optional `not_after` (Go: `RootOpts.NotAfter`, `RootTBS`'s `notAfter`), refuse
  one before `not_before`, and the profile admits any root `notAfter` from its `notBefore` on.
  `validate_chain`'s rule 4 refuses `root has expired` (first) and `leaf outlives the root` (last),
  by one predicate in each port (`x509::root_expired`, `RootExpired`), inclusive as RFC 5280 reads
  validity. Appendix B's five new chain cases are read with their reasons.
- **Every wallet refuses an expired root before it signs, as `root_expired`**, a new code in the
  library's vocabulary, never on the wire: `issue_from_csr`, `issue_tbs_from_csr` (before a `tbs`
  exists), `wallet_issue` (before its proof of possession), and the CLI's `id issue` (before the
  leaf is shown, the passphrase asked again or a card touched). A leaf that would outlive its root
  ends with it, and `warnings` says so (the two issuers gained `warnings`).
- **`issue_from_csr` and `issue_tbs_from_csr` take `root_cert`** in place of `root_cn` and
  `root_spki` (Go: `IssueOpts.Root` in place of `RootCN` and `RootPub`): the name, key and end date
  are read from the root's certificate, which must be a root of the profile and self-signed;
  `root_pkcs8` must be its key. `build_leaf` and `leaf_tbs` stay raw builders for tests and vectors,
  and judge no date against a root.
- **`hdtp id create --ends <RFC 3339>`**, with `--piv` too: the identity's end date, refused before
  anything is asked when it is not in the future.
- **Cards fold at 75 octets** (RFC 6350 §3.2, as CONTRACT §4 says), never splitting a UTF-8
  sequence, in both ports and the seed; they counted UTF-16 code units, so a name beyond ASCII
  folded where no octet-counting reader would.

## 0.5.0 — 2026-10-03

- **HDTP 1.0.** The library implements HDTP 1.0.0, hdtp-spec's `docs/specification/1.0/`, and
  `version` answers spec `1.0.0` in both ports. The specification's text is read through
  hdtp-spec's `site/spec-source.mjs` (the index page and the pages it links); the Rust and Go tests
  and `hdtp vectors check` read the same pages, and `--spec` takes a version directory or one
  document carrying Appendix B.
- **Every name is HDTP's.** The crates are `hdtp-identity`, `hdtp-identity-wasm`, `hdtp-limits` and
  `hdtp` (the CLI); the Go module is `github.com/humandelegatedtrustprotocol/hdtp-identity/go`,
  package `hdtpidentity`; the release assets are `hdtp-<version>-<os>`,
  `hdtp-identity-wasm-web-<version>.tgz` and `hdtp-identity-exportcorpus-<version>.tgz`; the
  environment variables are `HDTP_*`.
- **The wire labels and every version restart at 1.** HPKE `info` `HDTP-SEAL-v1`; suites
  `HDTP-SEAL-P256` and `HDTP-SEAL-X25519`; the challenges `HDTP root proof v1` and
  `HDTP card-attach proof v1`; the derivation `info` strings `hdtp/root/1`, `hdtp/store-key/1`,
  `hdtp/store-id/1` over the PRF input `SHA-256("hdtp/vault/1")`; media types
  `application/hdtp-call+json` and `application/hdtp-result+json`; the card's `X-HDTP-VERSION:1`,
  `X-HDTP-CERT` and `X-HDTP-SEAL`; an envelope header's `v` is 1; an export's `hdtp_export` is 1;
  the vault is `hdtp-vault/1` and its plaintext's `v` is 1. Anything else is refused as before, and
  nothing converts. The Go constant for the info string is `Info` (Rust `envelope::INFO`). One
  refusal a caller reads changed its article with the name: `not an hdtp-vault/1 document`.
- **The vectors and the corpus are new bytes**: Appendix B from the seeds `hdtp-1.0-vectors/{label}`,
  the export corpus from `hdtp-identity/exportcorpus/{label}`, and the live battery's version
  scenario is `unknown-v2`.
- **The name guard replaces the guard of retired behaviours' names.** `js/check-names.mjs` and `js/hdtp-names.txt`, byte for
  byte hdtp-spec's `scripts/` copies, fail the gate on the name the list forbids in any tracked
  path or text, and on the names of the behaviours HDTP does not have; `js/check-no-1x.mjs` and its list are gone.
