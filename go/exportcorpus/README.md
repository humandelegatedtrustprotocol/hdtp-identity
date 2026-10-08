# exportcorpus

The fixture corpus of the export (SPEC section 9.2; `CONTRACT.md` section 6.2): a valid export, a valid
book, and hostile files for the checks of the specification's validation. `cases.json` names the
owner root and the clock the corpus stands at, and lists 44 cases: 3 carry `accept` (what the file
holds: `valid-export.zip`, `valid-book.zip` and `local-names-differ.zip`, which is accepted, not
refused), 40 carry a `refusal` (the refusal it must produce, at a `stage`: the core's or the
host's), and 1, `understated-size.zip`, carries neither. The corpus is the data the readers are tested
on; it has no behaviour of its own beyond building itself.

Who reads it: the Go port's tests, the Rust core's tests, `js/parity.mjs` (`js/cases/export.mjs`),
and the CLI, which embeds it (`crates/hdtp/build.rs`) so that `hdtp vectors corpus --owner <root>`
can write it again for another owner. Hosts import the Go package
`github.com/humandelegatedtrustprotocol/hdtp-identity/go/exportcorpus`, or take the release asset
`hdtp-identity-exportcorpus-X.Y.Z.tgz`, which holds `cases.json` and every `.zip` here and nothing
else (`scripts/release.sh` selects them by name; this README is not packed).

## What it holds

- `cases.json` and the `*.zip` files it names (44 `.zip` files in this tree), embedded as `FS`
  (`embed.go`, `//go:embed cases.json *.zip`).
- `Build() (map[string][]byte, error)` (`build.go`) makes the whole corpus deterministically, the
  same bytes on every run: every member is stored (a compressor's output may change with the
  toolchain) except one deflated member in each size-bound file, and every time and serial is fixed.
  The valid export and the book are what the library's own writer makes.
- `Index`, `Case`, `Accept` (the shape of `cases.json`) and `OwnerCN`.
- `gen/` is `go run ./exportcorpus/gen` from `go/`: it writes what `Build` makes into the directory
  above it (or the directory named by its first argument), removing `.zip` files `Build` no longer
  makes.

## What it refuses, and how

The refusals are the corpus's data: each hostile case names the refusal the reader must produce in
the contract's words. Every refusal of the export is `bad_request`, and its `why` begins with where:
the member, then the row or line, then the column or member of a message (`src/export/mod.rs`'s
header).

## Invariants

- The committed files are what `Build` makes, byte for byte, and nothing else is in the embedded
  set: `TestTheCommittedCorpusIsWhatBuildMakes` (`corpus_test.go`).
- The CLI's re-issue for a random owner reads in the Go port as `cases.json` says
  (`gate.sh`, "The corpus the CLI writes for a fresh owner ...").
- The release's corpus tarball is exactly `cases.json` and the zips at the tag
  (`scripts/verify-release.sh`, `scripts/verify-assets.mjs`).

## Held by

`corpus_test.go` here; `go/export_corpus_test.go`, `go/export_zip_test.go`; the Rust test
`read_export_answers_the_whole_corpus`; `js/parity.mjs`.

## What it does not do

The committed corpus names one fixed owner. A host whose identities cannot hold that root refuses
each hostile file at the owner check, before the check the file targets, and that result is
unreached, not proven; `hdtp vectors corpus` exists to write the corpus for the host's own root.
The corpus holds no reader: reading is `ReadExportZip` in the parent package and `export_read*` in
the contract.
