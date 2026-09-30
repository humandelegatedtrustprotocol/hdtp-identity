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
	"unicode/utf8"
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
	_, err := WriteExportZip(&b, in, func(h string) (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(files[h])), nil })
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
		if _, err := WriteExportZip(b, in, func(h string) (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(files[h])), nil }); err != nil {
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
	_, err := WriteExportZip(&b, in, func(h string) (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(files[h])), nil })
	if err == nil || err.Error() != "messages[0], member attachments: more than one attachment: a message carries at most one file" {
		t.Errorf("the writer: %v", err)
	}
	line := `{"attachments":[{"file":"` + in.Media[0].Hash + `","filename":"a","mime":"b","size":1},{"file":"` + in.Media[0].Hash + `","filename":"a","mime":"b","size":1}],"body":"","contact":"` + exportPeer + `","direction":"in","id":"1","msg_id":"m","reply_to":null,"sender":"human","status":"read","thread":"t-1","time":"2026-09-02T00:00:00Z"}`
	_, _, err = exportReadMessages([]string{line}, 7, messageNames{threads: setOf([]string{"t-1"}), contacts: setOf([]string{exportPeer}), media: setOf([]string{in.Media[0].Hash})})
	if err == nil || err.Error() != "messages.jsonl: line 7, member attachments: more than one attachment: a message carries at most one file" {
		t.Errorf("the reader: %v", err)
	}
}

// SPEC §9.2: an exporter never leaves a file out. A file that cannot be read, and a message whose
// file is not among those handed in, each refuse the export; a control with the file writes.
func TestWriteExportZipRefusesRatherThanOmitsAFile(t *testing.T) {
	in, files := exportFixture(t)
	open := func(h string) (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(files[h])), nil }
	var b bytes.Buffer
	if _, err := WriteExportZip(&b, in, open); err != nil {
		t.Fatalf("the control: %v", err)
	}
	lost := func(string) (io.ReadCloser, error) { return nil, io.ErrUnexpectedEOF }
	if _, err := WriteExportZip(&bytes.Buffer{}, in, lost); err == nil {
		t.Error("a file that cannot be read was left out rather than refusing the export")
	}
	without := in
	without.Media = nil
	_, err := WriteExportZip(&bytes.Buffer{}, without, open)
	if err == nil || !strings.Contains(err.Error(), "it is not among the files to export") {
		t.Errorf("a message's file left out of the export: %v", err)
	}
}

// SPEC §9.2, import step 2: an imported leaf never replaces a pin the host validated itself, and a
// row the host holds without a leaf takes the row's (export_read kept it only because it validated).
func TestExportMergeNeverReplacesAHeldPin(t *testing.T) {
	a, b, c := "sha256:"+strings.Repeat("A", 43), "sha256:"+strings.Repeat("B", 43), "sha256:"+strings.Repeat("C", 43)
	row := func(root, endpoint string, leaf any) map[string]any {
		return map[string]any{"root": root, "endpoint": endpoint, "leaf": leaf, "root_cert": nil}
	}
	held := []any{row(a, "https://a.example/mcp", "MIIheld"), row(b, "https://b.example/mcp", nil)}
	rows := []any{row(a, "https://moved.example/mcp", "MIIrow"), row(b, "https://b.example/mcp", "MIIrow"), row(c, "https://c.example/mcp", nil)}
	write, keep, conflicts, err := exportMerge(held, rows)
	if err != nil {
		t.Fatal(err)
	}
	if len(write) != 2 || write[0].(map[string]any)["root"] != b || write[1].(map[string]any)["root"] != c {
		t.Errorf("written: %v", write)
	}
	if len(keep) != 1 || keep[0] != a {
		t.Errorf("kept: %v", keep)
	}
	if len(conflicts) != 2 {
		t.Errorf("the held pin's endpoint and leaf are two conflicts: %v", conflicts)
	}
}

// SPEC §9.2, what a contact controls: none of it stops the owner's export, and what WriteExportZip
// writes reads back whole. A reply to a message the file does not carry is written null; a
// permission the contact claims and §8 does not have, or one repeated, is dropped; a name the contact
// gives themselves over 200 characters is cut to 200, on a character; a message whose body holds what
// reads as a key is left out with the file it carried, and listed.
func TestWhatAContactControlsNeverStopsAnExportAndItReadsBack(t *testing.T) {
	in, files := exportFixture(t)
	long := strings.Repeat("é", 150) + strings.Repeat("x", 150)
	in.Contacts[0].DisplayName = long
	in.Contacts[0].TheirPermissions = []string{"message.media", "root.everything", "message.media", "integration.cal"}
	elsewhere := "m-elsewhere"
	in.Messages[1].ReplyTo = &elsewhere
	key, _ := KeyFromSeed(AlgEd25519, Seed("export/contact-key"))
	pkcs8, _ := key.PKCS8()
	in.Messages[0].Body = B64url(pkcs8) // the message that carries the one file, now with a key in its body
	var b bytes.Buffer
	leftOut, err := WriteExportZip(&b, in, func(h string) (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(files[h])), nil })
	if err != nil {
		t.Fatalf("the export was refused: %v", err)
	}
	if len(leftOut) != 1 || leftOut[0].ID != "1" || leftOut[0].Reason != exportBodyHoldsAKey {
		t.Errorf("left out: %+v", leftOut)
	}
	zr, err := zip.NewReader(bytes.NewReader(b.Bytes()), int64(b.Len()))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range zr.File {
		if strings.HasPrefix(f.Name, "media/") {
			t.Errorf("%s: the file of a message left out went into the export", f.Name)
		}
	}
	got, err := ReadExportZip(zr, exportOwner, in.ExportedAt, 1<<30)
	if err != nil {
		t.Fatalf("what was written does not read: %v", err)
	}
	c := got.Contacts[0]
	if utf8.RuneCountInString(c.DisplayName) != ExportNameMax || !strings.HasPrefix(long, c.DisplayName) {
		t.Errorf("display_name: %d characters", utf8.RuneCountInString(c.DisplayName))
	}
	if !reflect.DeepEqual(c.TheirPermissions, []string{"integration.cal", "message.media"}) {
		t.Errorf("their_permissions: %v", c.TheirPermissions)
	}
	if len(got.Messages) != 1 || got.Messages[0].ReplyTo != nil {
		t.Errorf("messages: %+v", got.Messages)
	}
}

// A contact held without a leaf, blocked and granted one thing, keeps what the person decided when a
// file brings its leaf: it stays blocked and granted what it was, and each difference is a conflict.
func TestExportMergeKeepsWhatThePersonDecidedAboutAHeldContact(t *testing.T) {
	root := "sha256:" + strings.Repeat("B", 43)
	held := []any{map[string]any{"root": root, "endpoint": "https://b.example/mcp", "leaf": nil, "root_cert": nil, "status": "blocked", "permissions": []any{"message.text"}}}
	rows := []any{map[string]any{"root": root, "endpoint": "https://b.example/mcp", "leaf": "MIIrow", "root_cert": "MIIroot", "status": "active", "permissions": []any{"message.media", "message.text"}}}
	write, _, conflicts, err := exportMerge(held, rows)
	if err != nil || len(write) != 1 {
		t.Fatal(err, write)
	}
	w := write[0].(map[string]any)
	if w["status"] != "blocked" || !reflect.DeepEqual(w["permissions"], []any{"message.text"}) || w["leaf"] != "MIIrow" {
		t.Errorf("written: %v", w)
	}
	if len(conflicts) != 2 || conflicts[0].(map[string]any)["field"] != "status" || conflicts[1].(map[string]any)["field"] != "permissions" {
		t.Errorf("conflicts: %v", conflicts)
	}
	same := []any{map[string]any{"root": root, "endpoint": "https://b.example/mcp", "leaf": "MIIrow", "status": "blocked", "permissions": []any{"message.text"}}}
	if _, _, c, _ := exportMerge(held, same); len(c) != 0 {
		t.Errorf("no difference, and conflicts: %v", c)
	}
}

// csvRead is every record, at once: for these tests, which read a file back whole. The port streams its
// records (csvEach); this sat beside it with no caller outside a test (X12).
func csvRead(text string) ([][]string, *csvRefusal) {
	var records [][]string
	bad := csvEach(text, func(_ int, fields []string) bool {
		records = append(records, append([]string(nil), fields...))
		return true
	})
	if bad != nil {
		return nil, bad
	}
	return records, nil
}
