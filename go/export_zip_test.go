package hdtpidentity

import (
	"archive/zip"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

// untouched is a writer a refused export must never reach: SPEC §9.2's checks run before the first
// byte, so a refusal leaves the host's file empty rather than half-written.
type untouched struct{ t *testing.T }

func (u untouched) Write(p []byte) (int, error) {
	u.t.Errorf("a refused export wrote %d bytes before it was refused", len(p))
	return len(p), nil
}

// WriteExportZip refuses, before the first byte, every input its own ReadExportZip would refuse, in
// the reader's words: a file no message names, a message to a thread or a contact the export does
// not hold, the same message id twice.
func TestWriteExportZipRefusesWhatItsReaderRefusesBeforeTheFirstByte(t *testing.T) {
	open := func(files map[string][]byte) func(string) (io.ReadCloser, error) {
		return func(h string) (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(files[h])), nil }
	}
	orphan := []byte("a file nobody sent")
	orphanHash := sha256Hex(orphan)
	for _, tc := range []struct {
		what   string
		change func(in *ExportInput, files map[string][]byte)
		want   string
	}{
		{"a file no message names", func(in *ExportInput, files map[string][]byte) {
			files[orphanHash] = orphan
			in.Media = append(in.Media, ExportMedia{Hash: orphanHash, Size: int64(len(orphan))})
		}, "media/" + orphanHash + ": nothing names it"},
		{"a message to a thread the export does not hold", func(in *ExportInput, _ map[string][]byte) {
			in.Messages[1].Thread = "t-elsewhere"
		}, "messages.jsonl: line 2, member thread: names no thread in threads.csv"},
		{"a message to a contact the export does not hold", func(in *ExportInput, _ map[string][]byte) {
			in.Messages[1].Contact = "sha256:" + strings.Repeat("C", 43)
		}, "messages.jsonl: line 2, member contact: names no root in contacts.csv or removed.csv"},
		{"the same message id twice", func(in *ExportInput, _ map[string][]byte) {
			in.Messages[1].ID = in.Messages[0].ID
		}, `messages.jsonl: id "1" appears twice`},
		{"a file whose bytes are not the ones declared", func(in *ExportInput, files map[string][]byte) {
			h := in.Media[0].Hash
			files[h] = append([]byte{}, files[h]...)
			files[h][0] ^= 1
		}, "media/" + fixtureHash(t) + ": the bytes are not the 18-byte file declared"},
		{"a key in the manifest's owner_name", func(in *ExportInput, _ map[string][]byte) {
			key, _ := KeyFromSeed(AlgEd25519, Seed("export/owner-name-key"))
			der, _ := key.PKCS8()
			in.OwnerName = B64url(der)
		}, "owner_name holds a private key"},
	} {
		in, files := exportFixture(t)
		// A body of some 14 KB that deflate cannot shrink below archive/zip's 4 KiB buffer, so a writer
		// that failed after messages.jsonl, among the files, would show here as bytes written.
		in.Messages[1].Body = incompressible(14000)
		tc.change(&in, files)
		_, err := WriteExportZip(untouched{t}, in, open(files))
		if err == nil || err.Error() != tc.want {
			t.Errorf("%s:\n  got  %v\n  want %s", tc.what, err, tc.want)
		}
	}
	// The control: the fixture as it is writes, and reads back.
	in, files := exportFixture(t)
	var b bytes.Buffer
	if _, err := WriteExportZip(&b, in, open(files)); err != nil {
		t.Fatalf("the control was refused: %v", err)
	}
	zr, _ := zip.NewReader(bytes.NewReader(b.Bytes()), int64(b.Len()))
	if _, err := ReadExportZip(zr, exportOwner, in.ExportedAt, 1<<30); err != nil {
		t.Fatalf("the control does not read back: %v", err)
	}
}

// incompressible is n characters of hex from a hash chain: text deflate leaves at about half its size.
func incompressible(n int) string {
	var b strings.Builder
	h := sha256Hex([]byte("pad"))
	for b.Len() < n {
		b.WriteString(h)
		h = sha256Hex([]byte(h))
	}
	return b.String()[:n]
}

func fixtureHash(t *testing.T) string {
	in, _ := exportFixture(t)
	return in.Media[0].Hash
}

// A file whose bytes are a private key (SPEC §9.2, key material): the writer leaves out every
// message that carries it, with the file, and lists each; a reply to it is then a reply to a message
// not carried, written null. The reader refuses a file that carries one anyway.
func TestAFileThatIsAKeyLeavesWithItsMessageAndIsRefusedOnRead(t *testing.T) {
	in, files := exportFixture(t)
	key, _ := KeyFromSeed(AlgP256, Seed("export/key-file"))
	der, _ := key.PKCS8()
	h := sha256Hex(der)
	in.Media = []ExportMedia{{Hash: h, Size: int64(len(der))}}
	in.Messages[0].Attachments[0].File, in.Messages[0].Attachments[0].Size = h, int64(len(der))
	files = map[string][]byte{h: der}
	var b bytes.Buffer
	leftOut, err := WriteExportZip(&b, in, func(x string) (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(files[x])), nil })
	if err != nil {
		t.Fatalf("the export was refused: %v", err)
	}
	want := "its file media/" + h + " holds what reads as a private key, which an export never carries"
	if len(leftOut) != 1 || leftOut[0].ID != "1" || leftOut[0].Reason != want {
		t.Errorf("left out: %+v", leftOut)
	}
	zr, _ := zip.NewReader(bytes.NewReader(b.Bytes()), int64(b.Len()))
	for _, f := range zr.File {
		if strings.HasPrefix(f.Name, "media/") {
			t.Errorf("%s: a file that is a key went into the export", f.Name)
		}
	}
	got, err := ReadExportZip(zr, exportOwner, in.ExportedAt, 1<<30)
	if err != nil {
		t.Fatalf("what was written does not read: %v", err)
	}
	if len(got.Messages) != 1 || got.Messages[0].ReplyTo != nil {
		t.Errorf("the reply to the message left out: %+v", got.Messages)
	}

	// A file written by hand, carrying the key as a media file a message names: refused on read.
	hostile := keyFileExport(t, der, h)
	zr, _ = zip.NewReader(bytes.NewReader(hostile), int64(len(hostile)))
	if _, err := ReadExportZip(zr, exportOwner, in.ExportedAt, 1<<30); err == nil || err.Error() != "media/"+h+": holds a private key" {
		t.Errorf("a key as a media file: %v", err)
	}
}

// keyFileExport is an export built member by member, as a writer that does not hold SPEC §9.2's key
// rule would build it: one message carrying `file` as its media.
func keyFileExport(t *testing.T, file []byte, h string) []byte {
	t.Helper()
	in, _ := exportFixture(t)
	var contacts, threads any
	_ = convert(in.Contacts, &contacts)
	_ = convert(in.Threads, &threads)
	msg := in.Messages[0]
	msg.Attachments[0].File, msg.Attachments[0].Size = h, int64(len(file))
	var one any
	_ = convert([]MessageRow{msg}, &one)
	lines, _, err := exportWriteMessages(one.([]any), nil)
	if err != nil {
		t.Fatal(err)
	}
	written, err := exportWrite(in.Owner, in.OwnerName, in.ExportedAt, in.Tool, contacts.([]any), nil, threads.([]any), []any{map[string]any{"hash": h, "size": len(file)}})
	if err != nil {
		t.Fatal(err)
	}
	jsonl := lines[0] + "\n"
	sha := sha256Hex([]byte(jsonl))
	partial, _ := json.Marshal(written.partial)
	manifest, err := finishManifest(partial, &sha, 1)
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	for _, m := range []struct {
		name string
		body []byte
	}{{"contacts.csv", []byte(written.contactsCSV)}, {"threads.csv", []byte(*written.threadsCSV)}, {"messages.jsonl", []byte(jsonl)},
		{"media/", nil}, {"media/" + h, file}, {"manifest.json", []byte(manifest)}} {
		fw, _ := zw.CreateHeader(&zip.FileHeader{Name: m.name, Method: zip.Store, Modified: time.Unix(0, 0)})
		_, _ = fw.Write(m.body)
	}
	_ = zw.Close()
	return b.Bytes()
}

// SPEC §9.2: media are bound by their names and counted, and not listed in the manifest's
// `files`, so an export's media are not capped by the manifest's 64 KiB. 5000 files, each carried by
// a message, write and read back whole.
func TestAnExportOf5000MediaWritesAndReadsBack(t *testing.T) {
	in, _ := exportFixture(t)
	files := map[string][]byte{}
	in.Media, in.Messages = nil, nil
	for i := 0; i < 5000; i++ {
		body := []byte(fmt.Sprintf("file %d", i))
		h := sha256Hex(body)
		files[h] = body
		in.Media = append(in.Media, ExportMedia{Hash: h, Size: int64(len(body))})
		in.Messages = append(in.Messages, MessageRow{ID: fmt.Sprintf("m%d", i), Thread: "t-1", Contact: exportPeer, MsgID: fmt.Sprintf("x%d", i),
			Direction: "in", Sender: "human", Time: "2026-09-02T00:00:00Z", Status: "read",
			Attachments: []Attachment{{File: h, Filename: "f", MIME: "text/plain", Size: int64(len(body))}}})
	}
	var b bytes.Buffer
	if _, err := WriteExportZip(&b, in, func(h string) (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(files[h])), nil }); err != nil {
		t.Fatalf("5000 media: %v", err)
	}
	zr, _ := zip.NewReader(bytes.NewReader(b.Bytes()), int64(b.Len()))
	got, err := ReadExportZip(zr, exportOwner, in.ExportedAt, 1<<30)
	if err != nil {
		t.Fatalf("5000 media do not read back: %v", err)
	}
	if len(got.Media) != 5000 || len(got.Messages) != 5000 {
		t.Errorf("%d media, %d messages", len(got.Media), len(got.Messages))
	}
}

// A media file is key material when its bytes are a PKCS #8 or SEC1 key in DER, or text holding one
// in PEM or base64 (SPEC 9.2#15), read leniently: js/key-material.json, the one list of cases,
// which the core's a_media_file_is_key_material_in_der_or_pem and the parity cases read too.
func TestAMediaFileIsKeyMaterialInDEROrPEM(t *testing.T) {
	raw, err := os.ReadFile("../js/key-material.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Cases []struct {
			What  string  `json:"what"`
			Hex   *string `json:"hex"`
			Text  *string `json:"text"`
			Holds bool    `json:"holds"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Cases) < 20 {
		t.Fatalf("js/key-material.json holds %d cases", len(doc.Cases))
	}
	for _, c := range doc.Cases {
		var b []byte
		switch {
		case c.Hex != nil && c.Text == nil:
			if b, err = hex.DecodeString(*c.Hex); err != nil {
				t.Fatal(err)
			}
		case c.Text != nil && c.Hex == nil:
			b = []byte(*c.Text)
		default:
			t.Fatalf("a case is hex or text: %s", c.What)
		}
		if mediaHoldsPrivateKey(b) != c.Holds {
			t.Errorf("%s: holds a private key %v, want %v", c.What, !c.Holds, c.Holds)
		}
	}
}

// An owner of "" is an owner, compared like any other, as the core compares it (its `Option`; CONTRACT
// §0: empty is not absent). It meant "no owner" to this port's manifest check, so a host that passed
// an empty root read another identity's file whole where the core refuses it (the port-parity hunt
// of 2026-09-30). The file's own owner is the control that must read.
func TestReadExportZipComparesAnEmptyOwner(t *testing.T) {
	in, files := exportFixture(t)
	zr := writeFixture(t, in, files)
	if _, err := ReadExportZip(zr, exportOwner, in.ExportedAt, 1<<30); err != nil {
		t.Fatalf("the file's own owner (the control): %v", err)
	}
	want := "manifest.json: owner: the file is " + exportOwner + "'s, not this identity's ()"
	if _, err := ReadExportZip(zr, "", in.ExportedAt, 1<<30); err == nil || err.Error() != want {
		t.Fatalf("an owner of \"\": %v, want %q", err, want)
	}
}
