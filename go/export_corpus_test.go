package pactidentity_test

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	pact "github.com/pact-cloud/pact-identity/go"
	"github.com/pact-cloud/pact-identity/go/exportcorpus"
)

// Every file of the corpus through ReadExportZip: each hostile one refused with the refusal it
// names, and both controls accepted with what they hold. The corpus is the same one the Rust host's
// test and js/parity.mjs read.
func TestReadExportZipAnswersTheWholeCorpus(t *testing.T) {
	raw, err := exportcorpus.FS.ReadFile("cases.json")
	if err != nil {
		t.Fatal(err)
	}
	var index exportcorpus.Index
	if err := json.Unmarshal(raw, &index); err != nil {
		t.Fatal(err)
	}
	now, _ := time.Parse(time.RFC3339, index.Now)
	accepted := 0
	for _, c := range index.Cases {
		data, err := exportcorpus.FS.ReadFile(c.File)
		if err != nil {
			t.Fatal(err)
		}
		zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			t.Errorf("%s: %v", c.File, err)
			continue
		}
		got, err := pact.ReadExportZip(zr, index.Owner, now, 1<<30)
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
	if accepted != 2 {
		t.Errorf("%d controls accepted; the corpus has two, and a reader that refuses everything must fail here", accepted)
	}
}
