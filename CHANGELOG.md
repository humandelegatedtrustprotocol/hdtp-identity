# Changelog

One version for everything in this repository: the Rust crates (`pact-identity`,
`pact-identity-wasm`, the `pact` CLI), the Go module `github.com/pact-cloud/pact-identity/go` and the
Wasm package. A release is tagged `vX.Y.Z` and `go/vX.Y.Z` on one commit (`make release`), and its
GitHub release carries the Wasm package, the CLI binaries, `manifest.json` and `SHA256SUMS`.
Versions follow semver; before 1.0.0 a minor version may change the contract (`CONTRACT.md`).

Entries go under `## Unreleased` as they land; `make release` dates them.

## Unreleased

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
  functions, and `ContactRowOf` / `VaultContactOf` between the wallet's book and a row.
- `go/exportcorpus`: a valid export, a valid book, and one hostile file per check of §9.2, each
  naming its refusal (`cases.json`), generated by `go run ./exportcorpus/gen` and held to the
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
  CLI's `contacts export` and the Go port's `ContactRowOf` use.
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
