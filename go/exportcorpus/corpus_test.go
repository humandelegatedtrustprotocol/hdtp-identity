package exportcorpus

import (
	"bytes"
	"io/fs"
	"testing"
)

// The committed corpus is what Build makes, byte for byte, and nothing else is in it: the files and
// the generator cannot drift apart.
func TestTheCommittedCorpusIsWhatBuildMakes(t *testing.T) {
	want, err := Build()
	if err != nil {
		t.Fatal(err)
	}
	have, err := fs.Glob(FS, "*")
	if err != nil {
		t.Fatal(err)
	}
	if len(have) != len(want) {
		t.Errorf("%d files committed, %d built: run `go run ./exportcorpus/gen` in go/", len(have), len(want))
	}
	for name, data := range want {
		got, err := FS.ReadFile(name)
		if err != nil || !bytes.Equal(got, data) {
			t.Errorf("%s: the committed file is not what Build makes: run `go run ./exportcorpus/gen` in go/", name)
		}
	}
}
