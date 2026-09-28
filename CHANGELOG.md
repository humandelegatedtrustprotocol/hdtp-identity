# Changelog

One version for everything in this repository: the Rust crates (`pact-identity`,
`pact-identity-wasm`, the `pact` CLI), the Go module `github.com/pact-cloud/pact-identity/go` and the
Wasm package. A release is tagged `vX.Y.Z` and `go/vX.Y.Z` on one commit (`make release`), and its
GitHub release carries the Wasm package, the CLI binaries, `manifest.json` and `SHA256SUMS`.
Versions follow semver; before 1.0.0 a minor version may change the contract (`CONTRACT.md`).

Entries go under `## Unreleased` as they land; `make release` dates them.

## Unreleased

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
