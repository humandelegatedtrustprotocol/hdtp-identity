package pactidentity

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
	"hash"
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

// ThreadRow is one row of threads.csv.
type ThreadRow struct {
	ID        string `json:"id"`
	Contact   string `json:"contact"`
	Topic     string `json:"topic"`
	CreatedAt string `json:"created_at"`
	LastAt    string `json:"last_at"`
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
	if err := convert(r.threads, &out.Threads); err != nil {
		return nil, err
	}
	names := messageNames{threads: []string{}, contacts: []string{}, media: []string{}}
	for _, c := range out.Contacts {
		names.contacts = append(names.contacts, c.Root)
	}
	for _, t := range out.Threads {
		names.threads = append(names.threads, t.ID)
	}
	for _, m := range out.Media {
		names.media = append(names.media, m.Hash)
	}

	end := exportEnd{ids: []string{}, msgIDs: []string{}, replyTos: []string{}, mediaSeen: []string{}}
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
			if !contains(end.mediaSeen, s) {
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
	sum := sha256.New()
	n, err := io.Copy(sum, io.LimitReader(rc, ExportMediaMax+1))
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
	if hex.EncodeToString(sum.Sum(nil)) != f.Name[6:] {
		return errors.New(f.Name + ": its sha256 is not its name")
	}
	return nil
}

// WriteExportZip writes an export: contacts.csv, threads.csv when there are threads, messages.jsonl
// when there are messages, media/ and each media file stored as it comes from media, and
// manifest.json last. Each media file's sha256 and size are checked against what was declared.
func WriteExportZip(w io.Writer, in ExportInput, media func(hash string) (io.ReadCloser, error)) error {
	var contacts, threads, mediaList, messages any
	for _, c := range []struct{ from, to any }{{in.Contacts, &contacts}, {in.Threads, &threads}, {in.Media, &mediaList}, {in.Messages, &messages}} {
		if err := convert(c.from, c.to); err != nil {
			return err
		}
	}
	asList := func(v any) []any {
		l, _ := v.([]any)
		return l
	}
	at := time.Unix(in.ExportedAt.Unix(), 0).UTC()
	written, err := exportWrite(in.Owner, in.OwnerName, at, in.Tool, asList(contacts), asList(threads), asList(mediaList))
	if err != nil {
		return err
	}
	lines, err := exportWriteMessages(asList(messages))
	if err != nil {
		return err
	}
	zw := zip.NewWriter(w)
	put := func(name string, method uint16, body io.Reader, check hash.Hash) (int64, error) {
		fw, err := zw.CreateHeader(&zip.FileHeader{Name: name, Method: method, Modified: at})
		if err != nil {
			return 0, err
		}
		if check != nil {
			body = io.TeeReader(body, check)
		}
		return io.Copy(fw, body)
	}
	if _, err := put("contacts.csv", zip.Deflate, bytes.NewReader([]byte(written.contactsCSV)), nil); err != nil {
		return err
	}
	if written.threadsCSV != nil {
		if _, err := put("threads.csv", zip.Deflate, bytes.NewReader([]byte(*written.threadsCSV)), nil); err != nil {
			return err
		}
	}
	var sha *string
	if len(lines) > 0 {
		var b bytes.Buffer
		for _, l := range lines {
			b.WriteString(l)
			b.WriteByte('\n')
		}
		s := sha256Hex(b.Bytes())
		sha = &s
		if _, err := put("messages.jsonl", zip.Deflate, &b, nil); err != nil {
			return err
		}
	}
	// SPEC §9.2: an exporter never leaves out a file a message it exports carries. A message whose
	// attachment is not among the files handed in is a reason to refuse the export, not to write it.
	for _, msg := range in.Messages {
		for _, a := range msg.Attachments {
			held := false
			for _, m := range in.Media {
				held = held || m.Hash == a.File
			}
			if !held {
				return fmt.Errorf("media/%s: message %s carries it, and it is not among the files to export", a.File, msg.ID)
			}
		}
	}
	if len(in.Media) > 0 {
		if _, err := zw.CreateHeader(&zip.FileHeader{Name: "media/", Method: zip.Store, Modified: at}); err != nil {
			return err
		}
	}
	for _, m := range in.Media {
		rc, err := media(m.Hash)
		if err != nil {
			return err
		}
		sum := sha256.New()
		n, err := put("media/"+m.Hash, zip.Store, rc, sum)
		rc.Close()
		if err != nil {
			return err
		}
		if n != m.Size || hex.EncodeToString(sum.Sum(nil)) != m.Hash {
			return fmt.Errorf("media/%s: the bytes are not the %d-byte file declared", m.Hash, m.Size)
		}
	}
	partial, err := json.Marshal(written.partial)
	if err != nil {
		return err
	}
	manifest, err := finishManifest(partial, sha, uint64(len(lines)))
	if err != nil {
		return err
	}
	if _, err := put("manifest.json", zip.Deflate, bytes.NewReader([]byte(manifest)), nil); err != nil {
		return err
	}
	return zw.Close()
}
