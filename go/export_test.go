package pactidentity

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestCSVReadsRFC4180StrictlyAndRefusesWhatItWouldHaveToRepair(t *testing.T) {
	rows, bad := csvRead("a,b\r\n\"x,\"\"y\"\"\r\nz\",\r\n")
	if bad != nil || !reflect.DeepEqual(rows, [][]string{{"a", "b"}, {"x,\"y\"\r\nz", ""}}) {
		t.Fatalf("%q %v", rows, bad)
	}
	if rows, bad := csvRead("a,b\nc,d"); bad != nil || len(rows) != 2 {
		t.Errorf("LF records: %q %v", rows, bad)
	}
	for in, want := range map[string]csvRefusal{
		"a,b\r\n\r\nc,d\r\n": {2, "a blank row"},
		"a,b\rc,d\n":         {1, "a carriage return that ends no line"},
		"a,b\"c\r\n":         {1, "a quote inside an unquoted field"},
		"\"a\"b,c\r\n":       {1, "a character follows a closing quote"},
		"a\r\n\"b":           {2, "a quoted field is never closed"},
	} {
		if _, bad := csvRead(in); bad == nil || *bad != want {
			t.Errorf("%q: want %v, got %v", in, want, bad)
		}
	}
}

func TestCSVWritesWhatItReadsBackAndGuardsEveryFormulaPrefix(t *testing.T) {
	cells := []string{"=1+1", "+1", "-1", "@SUM", "'Tis", "\tx", "\rx", "plain", "a,b", "say \"hi\"", "two\nlines"}
	var guarded []string
	for _, c := range cells {
		guarded = append(guarded, csvGuard(c))
	}
	var out strings.Builder
	csvWriteRecord(&out, guarded)
	rows, bad := csvRead(out.String())
	if bad != nil {
		t.Fatal(bad)
	}
	var back []string
	for _, c := range rows[0] {
		back = append(back, csvUnguard(c))
	}
	if !reflect.DeepEqual(back, cells) {
		t.Errorf("%q", back)
	}
	if csvGuard("MIIB") != "MIIB" {
		t.Error("a certificate is guarded")
	}
}

const (
	exportOwner = "sha256:" + "A0000000000000000000000000000000000000000AA"
	exportPeer  = "sha256:" + "B0000000000000000000000000000000000000000BB"
)

func exportFixture(t *testing.T) (ExportInput, map[string][]byte) {
	t.Helper()
	file := []byte("%PDF- a small file")
	sum := sha256.Sum256(file)
	h := hex.EncodeToString(sum[:])
	reply := "m-1"
	return ExportInput{
		Owner: exportOwner, OwnerName: "Alina", Tool: "go test", ExportedAt: time.Date(2026, 9, 27, 10, 0, 0, 0, time.UTC),
		Contacts: []ContactRow{{Root: exportPeer, Endpoint: "https://agent.bharat.example/mcp", Name: "=Bharat", DisplayName: "'Tis Bharat",
			Status: "active", WasActive: true, Permissions: []string{"message.text", "message.media"}, TheirPermissions: []string{}, Added: "2026-09-01T00:00:00Z"}},
		Threads: []ThreadRow{{ID: "t-1", Contact: exportPeer, Topic: "plans", CreatedAt: "2026-09-02T00:00:00Z", LastAt: "2026-09-03T00:00:00Z"}},
		Messages: []MessageRow{
			{ID: "1", Thread: "t-1", Contact: exportPeer, MsgID: "m-1", Direction: "in", Sender: "human", Time: "2026-09-02T00:00:00Z",
				Body: "", Status: "delivered", Attachments: []Attachment{{File: h, Filename: "a.pdf", MIME: "application/pdf", Size: int64(len(file))}}},
			{ID: "2", Thread: "t-1", Contact: exportPeer, MsgID: "m-2", Direction: "out", Sender: "agent", Time: "2026-09-03T00:00:00Z",
				Body: "https://example.org/a-link", ReplyTo: &reply, Status: "queued", Attachments: []Attachment{}},
		},
		Media: []ExportMedia{{Hash: h, Size: int64(len(file))}},
	}, map[string][]byte{h: file}
}

func writeFixture(t *testing.T, in ExportInput, files map[string][]byte) *zip.Reader {
	t.Helper()
	var b bytes.Buffer
	err := WriteExportZip(&b, in, func(h string) (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(files[h])), nil })
	if err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(bytes.NewReader(b.Bytes()), int64(b.Len()))
	if err != nil {
		t.Fatal(err)
	}
	return zr
}

func TestAnExportWrittenIsReadBackWhole(t *testing.T) {
	in, files := exportFixture(t)
	zr := writeFixture(t, in, files)
	got, err := ReadExportZip(zr, exportOwner, in.ExportedAt, 1<<30)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Contacts) != 1 || got.Contacts[0].Name != "=Bharat" || got.Contacts[0].DisplayName != "'Tis Bharat" || got.Contacts[0].Leaf != nil {
		t.Errorf("contacts: %+v", got.Contacts)
	}
	if !reflect.DeepEqual(got.Threads, in.Threads) || !reflect.DeepEqual(got.Media, in.Media) {
		t.Errorf("threads %+v media %+v", got.Threads, got.Media)
	}
	if !reflect.DeepEqual(got.Messages, in.Messages) {
		t.Errorf("messages: %+v", got.Messages)
	}
	// The same input writes the same bytes.
	var one, two bytes.Buffer
	for _, b := range []*bytes.Buffer{&one, &two} {
		if err := WriteExportZip(b, in, func(h string) (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(files[h])), nil }); err != nil {
			t.Fatal(err)
		}
	}
	if !bytes.Equal(one.Bytes(), two.Bytes()) {
		t.Error("two writes of one export differ")
	}
	// Another identity's import refuses the file by its manifest.
	if _, err := ReadExportZip(zr, exportPeer, in.ExportedAt, 1<<30); err == nil || !strings.HasPrefix(err.Error(), "manifest.json: owner: the file is ") {
		t.Errorf("another owner: %v", err)
	}
	// And a ceiling below the file is named.
	if _, err := ReadExportZip(zr, exportOwner, in.ExportedAt, 100); err == nil || err.Error() != "the file is over the 100-byte ceiling this host sets" {
		t.Errorf("ceiling: %v", err)
	}
}

func TestAMessageCarriesAtMostOneFile(t *testing.T) {
	in, files := exportFixture(t)
	in.Messages[0].Attachments = append(in.Messages[0].Attachments, in.Messages[0].Attachments[0])
	var b bytes.Buffer
	err := WriteExportZip(&b, in, func(h string) (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(files[h])), nil })
	if err == nil || err.Error() != "messages[0], member attachments: more than one attachment: a message carries at most one file" {
		t.Errorf("the writer: %v", err)
	}
	line := `{"attachments":[{"file":"` + in.Media[0].Hash + `","filename":"a","mime":"b","size":1},{"file":"` + in.Media[0].Hash + `","filename":"a","mime":"b","size":1}],"body":"","contact":"` + exportPeer + `","direction":"in","id":"1","msg_id":"m","reply_to":null,"sender":"human","status":"read","thread":"t-1","time":"2026-09-02T00:00:00Z"}`
	_, _, err = exportReadMessages([]string{line}, 7, messageNames{threads: []string{"t-1"}, contacts: []string{exportPeer}, media: []string{in.Media[0].Hash}})
	if err == nil || err.Error() != "messages.jsonl: line 7, member attachments: more than one attachment: a message carries at most one file" {
		t.Errorf("the reader: %v", err)
	}
}

// A wallet's book through the export and back: the row a VaultContact becomes is one export_write
// writes and export_read reads, and the contact that comes back is the one that went in (the leaf
// kept only because it validates).
func TestAVaultContactTravelsAsARowAndComesBack(t *testing.T) {
	owner, _ := KeyFromSeed(AlgEd25519, Seed("book/owner"))
	friend, _ := KeyFromSeed(AlgEd25519, Seed("book/friend"))
	at := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	cert, _ := BuildRoot(RootOpts{CN: "Friend", Key: friend, NotBefore: at, Serial: []byte{1, 2, 3, 4, 5, 6, 7, 8}})
	host, _ := KeyFromSeed(AlgEd25519, Seed("book/host"))
	leaf, _ := BuildLeaf(LeafOpts{CN: "Friend", RootCN: "Friend", RootKey: friend, HostPub: host.Public, Endpoint: "https://friend.example/mcp",
		NotBefore: at, NotAfter: at.AddDate(1, 0, 0), Serial: []byte{8, 7, 6, 5, 4, 3, 2, 1}})
	kept := VaultContact{Root: Fingerprint(friend.Public.SPKI), Endpoint: "https://friend.example/mcp", Name: "Friend", Leaf: B64url(leaf), RootCert: B64url(cert)}
	var buf bytes.Buffer
	in := ExportInput{Owner: Fingerprint(owner.Public.SPKI), OwnerName: "Owner", Tool: "test", ExportedAt: at.Add(24 * time.Hour),
		Contacts: []ContactRow{ContactRowOf(kept, at.Add(24*time.Hour))}}
	if err := WriteExportZip(&buf, in, nil); err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatal(err)
	}
	got, err := ReadExportZip(zr, in.Owner, at.Add(48*time.Hour), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	back := VaultContactOf(got.Contacts[0])
	kept.Added = timeOut(at.Add(24 * time.Hour))
	if back != kept {
		t.Errorf("%+v\n  came back as\n%+v", kept, back)
	}
}
