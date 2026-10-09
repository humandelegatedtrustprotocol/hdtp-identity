package hdtpidentity

// Go conveniences over the export contract functions (CONTRACT §6.2's prose names them; they are
// not contract functions and parity does not reach them, so this port's tests hold them to the
// corpus): ReadExportZip is the whole host flow of SPEC §9.2's validation over an archive/zip
// reader, and WriteExportZip writes an export through export_write, export_write_messages and
// export_manifest. A node reads and writes its exports through these rather than again.

import (
	"archive/zip"
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
	"unicode/utf8"
)

// ContactRow is one row of contacts.csv, as export_read answers it.
type ContactRow struct {
	Root             string   `json:"root"`
	Endpoint         string   `json:"endpoint"`
	Name             string   `json:"name"`
	DisplayName      string   `json:"display_name"`
	Status           string   `json:"status"`
	WasActive        bool     `json:"was_active"`
	Permissions      []string `json:"permissions"`
	TheirPermissions []string `json:"their_permissions"`
	Leaf             *string  `json:"leaf"`
	RootCert         *string  `json:"root_cert"`
	Added            string   `json:"added"`
}

// ThreadRow is one row of threads.csv. ContactName and ContactDisplayName are a removed thread's: the
// names its former contact is known by (SPEC §9.2); on any other thread they are empty.
type ThreadRow struct {
	ID                 string `json:"id"`
	Contact            string `json:"contact"`
	Topic              string `json:"topic"`
	CreatedAt          string `json:"created_at"`
	LastAt             string `json:"last_at"`
	ContactName        string `json:"contact_name,omitempty"`
	ContactDisplayName string `json:"contact_display_name,omitempty"`
	// removed is the reader's: the row is a removed thread, which its answer names.
	removed bool
}

// Attachment is the one file a message may carry.
type Attachment struct {
	File     string `json:"file"`
	Filename string `json:"filename"`
	MIME     string `json:"mime"`
	Size     int64  `json:"size"`
}

// MessageRow is one line of messages.jsonl.
type MessageRow struct {
	ID          string       `json:"id"`
	Thread      string       `json:"thread"`
	Contact     string       `json:"contact"`
	MsgID       string       `json:"msg_id"`
	Direction   string       `json:"direction"`
	Sender      string       `json:"sender"`
	Time        string       `json:"time"`
	Body        string       `json:"body"`
	ReplyTo     *string      `json:"reply_to"`
	Status      string       `json:"status"`
	Attachments []Attachment `json:"attachments"`
}

// ExportMedia names one media file: its sha256 (lowercase hex) and its size.
type ExportMedia struct {
	Hash string `json:"hash"`
	Size int64  `json:"size"`
}

// ExportContents is what a validated export holds.
type ExportContents struct {
	Contacts []ContactRow
	Threads  []ThreadRow
	Messages []MessageRow
	Media    []ExportMedia
}

// ExportInput is what WriteExportZip writes.
type ExportInput struct {
	Owner, OwnerName, Tool string
	ExportedAt             time.Time
	Contacts               []ContactRow
	Threads                []ThreadRow
	Messages               []MessageRow
	Media                  []ExportMedia
}

// convert moves a value between the typed rows and the contract's JSON shape.
func convert(from, to any) error {
	b, err := json.Marshal(from)
	if err != nil {
		return err
	}
	if p, isAny := to.(*any); isAny {
		v, err := decodeJSON(b)
		if err != nil {
			return err
		}
		*p = v
		return nil
	}
	return json.Unmarshal(b, to)
}

const exportBatch = 500

// zipMode is the Unix mode the host hands the core: the external attributes' high half when there
// is one, a directory for an MS-DOS entry with its directory bit, and nothing otherwise — the
// S_IFMT bits the Rust zip crate's unix_mode() gives.
func zipMode(f *zip.File) uint32 {
	if m := f.ExternalAttrs >> 16; m != 0 {
		return m
	}
	if f.CreatorVersion>>8 == 0 && f.ExternalAttrs&0x10 != 0 {
		return 0o040775
	}
	return 0
}

// exportHost carries what the host counts across members.
type exportHost struct {
	ceiling int64
	total   int64
}

func (h *exportHost) over() error {
	return fmt.Errorf("the file is over the %d-byte ceiling this host sets", h.ceiling)
}

// readCapped reads one member whole, refusing it past limit bytes of what it decompresses.
func (h *exportHost) readCapped(f *zip.File, limit int64) ([]byte, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, errors.New(f.Name + ": does not decompress")
	}
	defer rc.Close()
	b, err := io.ReadAll(io.LimitReader(rc, limit+1))
	h.total += int64(len(b))
	if h.total > h.ceiling {
		return nil, h.over()
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%s: over %d bytes", f.Name, limit)
	}
	if err != nil {
		return nil, errors.New(f.Name + ": does not decompress")
	}
	return b, nil
}

// hostFailures maps the core's "this member is required" to the member the host could not read.
var hostFailures = map[string]string{
	"manifest is required":                              "manifest.json",
	"contacts_csv is required":                          "contacts.csv",
	"threads_csv is required: the file has threads.csv": "threads.csv",
}

// ReadExportZip validates a whole export as SPEC §9.2 requires, before anything is written, and
// answers what it holds. ceiling is the whole-file limit this host sets, by bytes decompressed.
func ReadExportZip(zr *zip.Reader, owner string, now time.Time, ceiling int64) (*ExportContents, error) {
	h := &exportHost{ceiling: ceiling}
	var directory []ExportEntry
	first := map[string]*zip.File{}
	for _, f := range zr.File {
		directory = append(directory, ExportEntry{Name: f.Name, Size: f.UncompressedSize64, Encrypted: f.Flags&1 != 0, Mode: zipMode(f)})
		if _, seen := first[f.Name]; !seen {
			first[f.Name] = f
		}
	}
	// The text members, in a fixed order. One that fails to read is handed to the core as absent and
	// its error kept: the core's directory and manifest refusals come first, whatever the host saw.
	texts := map[string]*string{}
	failed := map[string]error{}
	for _, m := range []struct {
		name  string
		limit int64
	}{{"manifest.json", ExportManifestMax}, {"contacts.csv", ExportContactsMax}, {"threads.csv", ExportThreadsMax}} {
		f, has := first[m.name]
		if !has {
			continue
		}
		b, err := h.readCapped(f, m.limit)
		if err != nil && h.total > h.ceiling {
			return nil, err
		}
		if err == nil && !utf8.Valid(b) {
			err = errors.New(m.name + ": not UTF-8 text")
		}
		if err != nil {
			failed[m.name] = err
			continue
		}
		s := string(b)
		texts[m.name] = &s
	}
	r, err := exportRead(directory, texts["manifest.json"], texts["contacts.csv"], texts["threads.csv"], owner, now)
	if err != nil {
		if member, known := hostFailures[err.Error()]; known && failed[member] != nil {
			return nil, failed[member]
		}
		return nil, err
	}
	out := &ExportContents{Media: r.media}
	if err := convert(r.contacts, &out.Contacts); err != nil {
		return nil, err
	}
	out.Threads = r.threads
	names := messageNames{threads: strSet{}, contacts: strSet{}, media: strSet{}}
	for _, c := range out.Contacts {
		names.contacts.add(c.Root)
	}
	// A message names a contact, or the contact of a removed thread.
	for _, t := range out.Threads {
		names.threads.add(t.ID)
		names.contacts.add(t.Contact)
	}
	for _, m := range out.Media {
		names.media.add(m.Hash)
	}

	end := exportEnd{ids: []string{}, msgIDs: []string{}, replyTos: []string{}, mediaSeen: []string{}}
	// Every media file of the directory must be named by a message (SPEC §9.2).
	for _, m := range out.Media {
		end.media = append(end.media, m.Hash)
	}
	if f, has := first["messages.jsonl"]; has {
		sha, lines, err := h.streamMessages(f, names, &end, out)
		if err != nil {
			return nil, err
		}
		end.messagesSHA256, end.lines = &sha, lines
	}
	for _, f := range zr.File {
		if isExportMedia(f.Name) {
			if err := h.checkMedia(f); err != nil {
				return nil, err
			}
		}
	}
	if err := exportReadEnd(*texts["manifest.json"], end); err != nil {
		return nil, err
	}
	return out, nil
}

func (h *exportHost) streamMessages(f *zip.File, names messageNames, end *exportEnd, out *ExportContents) (string, uint64, error) {
	rc, err := f.Open()
	if err != nil {
		return "", 0, errors.New("messages.jsonl: does not decompress")
	}
	defer rc.Close()
	sum := sha256.New()
	br := bufio.NewReader(io.TeeReader(rc, sum))
	mediaSeen := setOf(end.mediaSeen)
	var batch []string
	var n uint64
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		msgs, seen, err := exportReadMessages(batch, n-uint64(len(batch))+1, names)
		if err != nil {
			return err
		}
		for _, m := range msgs {
			o := m.(map[string]any)
			end.ids = append(end.ids, o["id"].(string))
			end.msgIDs = append(end.msgIDs, o["msg_id"].(string))
			if r, isText := o["reply_to"].(string); isText {
				end.replyTos = append(end.replyTos, r)
			}
			var row MessageRow
			if err := convert(o, &row); err != nil {
				return err
			}
			out.Messages = append(out.Messages, row)
		}
		for _, s := range seen {
			if !mediaSeen.has(s) {
				mediaSeen.add(s)
				end.mediaSeen = append(end.mediaSeen, s)
			}
		}
		batch = batch[:0]
		return nil
	}
	for {
		line, ended, err := readLine(br, ExportLineMax)
		if ended || len(line) > 0 {
			n++
			h.total += int64(len(line))
			if ended {
				h.total++
			}
			if h.total > h.ceiling {
				return "", 0, h.over()
			}
			if len(line) > ExportLineMax {
				return "", 0, fmt.Errorf("messages.jsonl: line %d: over %d bytes", n, ExportLineMax)
			}
			if !utf8.Valid(line) {
				return "", 0, fmt.Errorf("messages.jsonl: line %d: not UTF-8 text", n)
			}
			batch = append(batch, string(line))
			if len(batch) == exportBatch {
				if err := flush(); err != nil {
					return "", 0, err
				}
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", 0, errors.New("messages.jsonl: does not decompress")
		}
	}
	if err := flush(); err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(sum.Sum(nil)), n, nil
}

// readLine reads one line up to '\n' (not kept; ended says one was found), keeping at most limit+1
// bytes of a longer line. At the end of the member it answers io.EOF with what was left.
func readLine(br *bufio.Reader, limit int) ([]byte, bool, error) {
	var line []byte
	for {
		chunk, err := br.ReadSlice('\n')
		switch err {
		case nil:
			chunk = chunk[:len(chunk)-1]
		case bufio.ErrBufferFull:
		default:
		}
		if len(line) <= limit {
			line = append(line, chunk...)
			if len(line) > limit+1 {
				line = line[:limit+1]
			}
		}
		switch err {
		case nil:
			return line, true, nil
		case bufio.ErrBufferFull:
			continue
		default:
			return line, false, err
		}
	}
}

func (h *exportHost) checkMedia(f *zip.File) error {
	rc, err := f.Open()
	if err != nil {
		return errors.New(f.Name + ": does not decompress")
	}
	defer rc.Close()
	// The bytes are held (5 MiB at the most) to be searched for key material after they are hashed.
	body, err := io.ReadAll(io.LimitReader(rc, ExportMediaMax+1))
	n := int64(len(body))
	h.total += n
	if h.total > h.ceiling {
		return h.over()
	}
	if n > ExportMediaMax {
		return fmt.Errorf("%s: over %d bytes", f.Name, ExportMediaMax)
	}
	if err != nil {
		return errors.New(f.Name + ": does not decompress")
	}
	if sha256Hex(body) != f.Name[6:] {
		return errors.New(f.Name + ": its sha256 is not its name")
	}
	if mediaHoldsPrivateKey(body) {
		return errors.New(f.Name + ": holds a private key")
	}
	return nil
}

// mediaHoldsPrivateKey is SPEC §9.2's key-material rule over a file's bytes: the bytes themselves a
// PKCS #8 or SEC1 key (DER), or, when they are text, the rule every cell and member is read by
// (PEM armour, or a word that decodes as base64 to such a key).
func mediaHoldsPrivateKey(b []byte) bool {
	return isPrivateKeyDER(b) || utf8.Valid(b) && holdsPrivateKey(string(b))
}

// WriteExportZip writes an export: contacts.csv, threads.csv when there are threads, messages.jsonl
// when there are messages, media/ and each media file stored as it comes from media, and
// manifest.json last.
//
// Nothing reaches w until the whole file has passed the reader's rules (SPEC §9.2), so a refused
// export writes no byte. Before the first byte it reads every media file once (5 MiB at the most at a
// time) to check its size, its sha256 and whether it is key material, writes the rows and lines, and
// holds them — and the finished manifest — to what ReadExportZip checks: every message's thread,
// contact and file, ids and msg_ids unique, every reply_to carried, every file named. The media are
// then read a second time as they are copied, and checked again; media opens each file twice, which
// is what lets an export of any size be refused whole without holding it (an export can be
// gigabytes of files). Only a file whose bytes change between the two reads can fail mid-stream.
//
// What a contact controls never stops the export (SPEC §9.2): a message whose body holds what reads
// as a private key is left out, with the file it carried; a message carrying a file whose bytes are a
// private key is left out, with that file; a reply to a message not carried is written null. Every
// message left out is returned for the host to report to the person.
func WriteExportZip(w io.Writer, in ExportInput, media func(hash string) (io.ReadCloser, error)) ([]ExportLeftOut, error) {
	// The files, read once and checked, before anything is decided: the size and hash declared, and
	// whether the bytes are a key.
	keyFiles := strSet{}
	handed := make(map[string]ExportMedia, len(in.Media))
	for _, m := range in.Media {
		handed[m.Hash] = m
		body, err := readMedia(media, m)
		if err != nil {
			return nil, err
		}
		if mediaHoldsPrivateKey(body) {
			keyFiles.add(m.Hash)
		}
	}
	// A message carrying a file that is a key is left out with it, before the lines are written, so a
	// reply to it is a reply to a message the file does not carry.
	var leftOut []ExportLeftOut
	var kept []MessageRow
	for _, msg := range in.Messages {
		carriesKey := ""
		for _, a := range msg.Attachments {
			if keyFiles.has(a.File) {
				carriesKey = a.File
			}
		}
		if carriesKey != "" {
			leftOut = append(leftOut, ExportLeftOut{ID: msg.ID, Reason: "its file media/" + carriesKey + " holds what reads as a private key, which an export never carries"})
			continue
		}
		kept = append(kept, msg)
	}
	var contacts, threads, messages any
	for _, c := range []struct{ from, to any }{{in.Contacts, &contacts}, {in.Threads, &threads}, {kept, &messages}} {
		if err := convert(c.from, c.to); err != nil {
			return nil, err
		}
	}
	asList := func(v any) []any {
		l, _ := v.([]any)
		return l
	}
	lines, bodyLeftOut, err := exportWriteMessages(asList(messages), nil)
	if err != nil {
		return nil, err
	}
	leftOut = append(leftOut, bodyLeftOut...)
	// The files the kept messages carry. A file only left-out messages carried goes with them; a
	// kept message's file must be among those handed in (SPEC §9.2: an exporter never leaves one out).
	gone := strSet{}
	for _, l := range leftOut {
		gone.add(l.ID)
	}
	keptFiles, goneFiles := strSet{}, strSet{}
	for _, msg := range in.Messages {
		for _, a := range msg.Attachments {
			if gone.has(msg.ID) {
				goneFiles.add(a.File)
				continue
			}
			if _, has := handed[a.File]; !has {
				return nil, fmt.Errorf("media/%s: message %s carries it, and it is not among the files to export", a.File, msg.ID)
			}
			keptFiles.add(a.File)
		}
	}
	var files []ExportMedia
	for _, m := range in.Media {
		if goneFiles.has(m.Hash) && !keptFiles.has(m.Hash) {
			continue
		}
		files = append(files, m)
	}
	var mediaList any
	if err := convert(files, &mediaList); err != nil {
		return nil, err
	}
	at := time.Unix(in.ExportedAt.Unix(), 0).UTC()
	written, err := exportWrite(in.Owner, in.OwnerName, at, in.Tool, asList(contacts), asList(threads), asList(mediaList))
	if err != nil {
		return nil, err
	}
	var jsonl bytes.Buffer
	for _, l := range lines {
		jsonl.WriteString(l)
		jsonl.WriteByte('\n')
	}
	var sha *string
	if len(lines) > 0 {
		s := sha256Hex(jsonl.Bytes())
		sha = &s
	}
	partial, err := json.Marshal(written.partial)
	if err != nil {
		return nil, err
	}
	manifest, err := finishManifest(partial, sha, uint64(len(lines)))
	if err != nil {
		return nil, err
	}
	// The reader's rules over what is about to be written, in the reader's words: every message's
	// thread, contact and file, then the rules across the whole member.
	names := messageNames{threads: strSet{}, contacts: strSet{}, media: strSet{}}
	for _, c := range in.Contacts {
		names.contacts.add(c.Root)
	}
	for _, t := range in.Threads {
		names.threads.add(t.ID)
		names.contacts.add(t.Contact)
	}
	for _, m := range files {
		names.media.add(m.Hash)
	}
	read, seen, err := exportReadMessages(lines, 1, names)
	if err != nil {
		return nil, err
	}
	end := exportEnd{messagesSHA256: sha, lines: uint64(len(lines)), ids: []string{}, msgIDs: []string{}, replyTos: []string{}, mediaSeen: seen}
	for _, m := range files {
		end.media = append(end.media, m.Hash)
	}
	for _, v := range read {
		o, _ := v.(map[string]any)
		id, _ := o["id"].(string)
		msgID, _ := o["msg_id"].(string)
		end.ids = append(end.ids, id)
		end.msgIDs = append(end.msgIDs, msgID)
		if r, isText := o["reply_to"].(string); isText {
			end.replyTos = append(end.replyTos, r)
		}
	}
	if err := exportReadEnd(manifest, end); err != nil {
		return nil, err
	}

	// Only now does a byte reach w.
	zw := zip.NewWriter(w)
	put := func(name string, method uint16, body io.Reader) error {
		fw, err := zw.CreateHeader(&zip.FileHeader{Name: name, Method: method, Modified: at})
		if err != nil {
			return err
		}
		_, err = io.Copy(fw, body)
		return err
	}
	if err := put("contacts.csv", zip.Deflate, bytes.NewReader([]byte(written.contactsCSV))); err != nil {
		return nil, err
	}
	if written.threadsCSV != nil {
		if err := put("threads.csv", zip.Deflate, bytes.NewReader([]byte(*written.threadsCSV))); err != nil {
			return nil, err
		}
	}
	if len(lines) > 0 {
		if err := put("messages.jsonl", zip.Deflate, &jsonl); err != nil {
			return nil, err
		}
	}
	if len(files) > 0 {
		if _, err := zw.CreateHeader(&zip.FileHeader{Name: "media/", Method: zip.Store, Modified: at}); err != nil {
			return nil, err
		}
	}
	for _, m := range files {
		// Read again, and checked again: the bytes written are the bytes that were checked.
		body, err := readMedia(media, m)
		if err != nil {
			return nil, err
		}
		if err := put("media/"+m.Hash, zip.Store, bytes.NewReader(body)); err != nil {
			return nil, err
		}
	}
	if err := put("manifest.json", zip.Deflate, bytes.NewReader([]byte(manifest))); err != nil {
		return nil, err
	}
	return leftOut, zw.Close()
}

// readMedia is one file from the host, whole, held to what was declared of it: at most 5 MiB, the
// size and the sha256 declared.
func readMedia(media func(hash string) (io.ReadCloser, error), m ExportMedia) ([]byte, error) {
	rc, err := media(m.Hash)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	body, err := io.ReadAll(io.LimitReader(rc, ExportMediaMax+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) != m.Size || sha256Hex(body) != m.Hash {
		return nil, fmt.Errorf("media/%s: the bytes are not the %d-byte file declared", m.Hash, m.Size)
	}
	return body, nil
}
