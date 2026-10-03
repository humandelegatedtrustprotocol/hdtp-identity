package hdtpidentity_test

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"io"
	"io/fs"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	hdtp "github.com/humandelegatedtrustprotocol/hdtp-identity/go"
	"github.com/humandelegatedtrustprotocol/hdtp-identity/go/exportcorpus"
)

// Every file of the corpus through ReadExportZip: each hostile one refused with the refusal it
// names, and both controls accepted with what they hold. The corpus is the same one the Rust host's
// test and js/parity.mjs read.
func TestReadExportZipAnswersTheWholeCorpus(t *testing.T) {
	answersCorpus(t, exportcorpus.FS)
}

// The corpus the hdtp CLI writes for another owner (`hdtp vectors corpus --owner <root> --out <dir>`),
// read by this port: every hostile file refused with the refusal ITS cases.json names — not at the
// owner check — and every control accepted whole. The CLI is the one writer, and this is the port it
// did not write in. HDTP_REISSUED_CORPUS names the directory. gate.sh writes one for a fresh owner,
// sets it, and fails unless this test PASSED; a plain `go test` has no corpus to read and skips it.
func TestReadExportZipAnswersTheCorpusWrittenForAnotherOwner(t *testing.T) {
	dir := os.Getenv("HDTP_REISSUED_CORPUS")
	if dir == "" {
		t.Skip("HDTP_REISSUED_CORPUS names no corpus written by `hdtp vectors corpus`; gate.sh writes one and sets it")
	}
	written, fixed := readCorpusIndex(t, os.DirFS(dir)), readCorpusIndex(t, exportcorpus.FS)
	if written.Owner == fixed.Owner {
		t.Fatalf("the corpus in %s names the committed owner %s: it is not one written for another", dir, fixed.Owner)
	}
	if len(written.Cases) != len(fixed.Cases) {
		t.Fatalf("the corpus in %s has %d cases, the committed one %d", dir, len(written.Cases), len(fixed.Cases))
	}
	answersCorpus(t, os.DirFS(dir))
	// The control: the committed valid export, read as the new owner, is another identity's.
	data, _ := exportcorpus.FS.ReadFile("valid-export.zip")
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	now, _ := time.Parse(time.RFC3339, written.Now)
	if _, err := hdtp.ReadExportZip(zr, written.Owner, now, 1<<30); err == nil || !strings.HasPrefix(err.Error(), "manifest.json: owner: the file is ") {
		t.Errorf("the committed valid export read as %s: %v", written.Owner, err)
	}
}

func readCorpusIndex(t *testing.T, fsys fs.FS) exportcorpus.Index {
	t.Helper()
	raw, err := fs.ReadFile(fsys, "cases.json")
	if err != nil {
		t.Fatal(err)
	}
	var index exportcorpus.Index
	if err := json.Unmarshal(raw, &index); err != nil {
		t.Fatal(err)
	}
	return index
}

// answersCorpus reads every file of a corpus through ReadExportZip and holds each to its case.
func answersCorpus(t *testing.T, fsys fs.FS) {
	t.Helper()
	index := readCorpusIndex(t, fsys)
	now, _ := time.Parse(time.RFC3339, index.Now)
	accepted := 0
	for _, c := range index.Cases {
		data, err := fs.ReadFile(fsys, c.File)
		if err != nil {
			t.Fatal(err)
		}
		zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			t.Errorf("%s: %v", c.File, err)
			continue
		}
		got, err := hdtp.ReadExportZip(zr, index.Owner, now, 1<<30)
		switch {
		case c.Accept != nil:
			if err != nil {
				t.Errorf("%s: refused: %v", c.File, err)
				continue
			}
			accepted++
			pinned := 0
			for _, r := range got.Contacts {
				if r.Leaf != nil {
					pinned++
				}
				for _, l := range c.Accept.Leafless {
					if r.Root == l && r.Leaf != nil {
						t.Errorf("%s: %s's leaf pins, and must not", c.File, l)
					}
				}
			}
			if len(got.Contacts) != c.Accept.Contacts || len(got.Threads) != c.Accept.Threads || len(got.Messages) != c.Accept.Messages ||
				len(got.Media) != c.Accept.Media || pinned != c.Accept.Pinned {
				t.Errorf("%s: %d contacts (%d pinned), %d threads, %d messages, %d media; want %+v", c.File, len(got.Contacts), pinned,
					len(got.Threads), len(got.Messages), len(got.Media), *c.Accept)
			}
		case err == nil:
			t.Errorf("%s: accepted, and must be refused: %s%s", c.File, c.Refusal, c.RefusalPrefix)
		case c.Refusal != "" && err.Error() != c.Refusal:
			t.Errorf("%s:\n  got  %s\n  want %s", c.File, err, c.Refusal)
		case c.RefusalPrefix != "" && !strings.HasPrefix(err.Error(), c.RefusalPrefix):
			t.Errorf("%s:\n  got  %s\n  want %s…", c.File, err, c.RefusalPrefix)
		}
	}
	// Every file cases.json marks as accepted, and at least one: a reader that refuses everything
	// must fail here.
	want := 0
	for _, c := range index.Cases {
		if c.Accept != nil {
			want++
		}
	}
	if want == 0 || accepted != want {
		t.Errorf("%d files accepted; cases.json accepts %d, and a reader that refuses everything must fail here", accepted, want)
	}
}

// WriteExportZip over the corpus's two controls: each is read with ReadExportZip and written again
// from what was read, and the file written is the file read — every member byte for byte but where a
// reader changes a row (a leaf that pins nothing comes back null, so contacts.csv and the manifest
// that hashes it differ in the export and nowhere in the book) — and it reads back to the same rows.
func TestWriteExportZipWritesTheCorpusControlsBack(t *testing.T) {
	raw, _ := exportcorpus.FS.ReadFile("cases.json")
	var index exportcorpus.Index
	if err := json.Unmarshal(raw, &index); err != nil {
		t.Fatal(err)
	}
	now, _ := time.Parse(time.RFC3339, index.Now)
	members := func(zr *zip.Reader) map[string][]byte {
		out := map[string][]byte{}
		for _, f := range zr.File {
			r, err := f.Open()
			if err != nil {
				t.Fatal(err)
			}
			b, _ := io.ReadAll(r)
			r.Close()
			out[f.Name] = b
		}
		return out
	}
	controls := 0
	for _, c := range index.Cases {
		if c.Accept == nil {
			continue
		}
		controls++
		file := c.File
		data, _ := exportcorpus.FS.ReadFile(file)
		zr, _ := zip.NewReader(bytes.NewReader(data), int64(len(data)))
		first, err := hdtp.ReadExportZip(zr, index.Owner, now, 1<<30)
		if err != nil {
			t.Fatalf("%s: %v", file, err)
		}
		was := members(zr)
		var m struct {
			OwnerName  string `json:"owner_name"`
			Tool       string `json:"tool"`
			ExportedAt string `json:"exported_at"`
		}
		if err := json.Unmarshal(was["manifest.json"], &m); err != nil {
			t.Fatal(err)
		}
		at, _ := time.Parse(time.RFC3339, m.ExportedAt)
		var out bytes.Buffer
		in := hdtp.ExportInput{Owner: index.Owner, OwnerName: m.OwnerName, Tool: m.Tool, ExportedAt: at,
			Contacts: first.Contacts, Threads: first.Threads, Messages: first.Messages, Media: first.Media}
		_, err = hdtp.WriteExportZip(&out, in, func(hash string) (io.ReadCloser, error) { return zr.Open("media/" + hash) })
		if err != nil {
			t.Fatalf("%s: %v", file, err)
		}
		again, _ := zip.NewReader(bytes.NewReader(out.Bytes()), int64(out.Len()))
		now2 := members(again)
		if len(now2) != len(was) {
			t.Errorf("%s: %d members written, %d read", file, len(now2), len(was))
		}
		leafless := len(c.Accept.Leafless) > 0
		for name, b := range was {
			changed := leafless && (name == "contacts.csv" || name == "manifest.json")
			if !changed && !bytes.Equal(now2[name], b) {
				t.Errorf("%s: %s is not written back as it was read", file, name)
			}
		}
		second, err := hdtp.ReadExportZip(again, index.Owner, now, 1<<30)
		if err != nil {
			t.Fatalf("%s: what was written does not read: %v", file, err)
		}
		if !reflect.DeepEqual(first, second) {
			t.Errorf("%s: what was written reads back differently", file)
		}
	}
	if controls < 2 {
		t.Errorf("%d controls in the corpus, want the export and the book at least", controls)
	}
}
