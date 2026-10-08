# gen

`go run ./exportcorpus/gen` from `go/` writes the export corpus into `go/exportcorpus` (or into the
directory named by its first argument): the files are what `exportcorpus.Build` makes, and a `.zip`
there that `Build` no longer makes is removed. Exits 1 with `gen: <why>` on stderr on failure.
`TestTheCommittedCorpusIsWhatBuildMakes` in the parent holds the committed files to `Build`. See
the [parent README](../README.md).
