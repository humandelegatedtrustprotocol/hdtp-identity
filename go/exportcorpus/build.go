package exportcorpus

// Build makes the whole corpus, deterministically: the same bytes on every run, so a test can hold
// the committed files to it. Every member is stored — a compressor's output may change with the
// toolchain, and a stored member's bytes are its own — except the one member of each bound's file,
// deflated so the repository holds kilobytes, not megabytes (the drift test would name a toolchain
// whose deflate changed); every time and serial is fixed. The valid export and the book are what the
// library's own writer makes (export_write, export_write_messages, export_manifest); each hostile
// file is the valid export with ONE thing wrong, and cases.json names the refusal it must produce.

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"io/fs"
	"strings"
	"time"

	hdtp "github.com/humandelegatedtrustprotocol/hdtp-identity/go"
)

// Owner's seed, the importing identity's; Now is the instant the corpus is read at.
const (
	OwnerCN = "Alina Rao"
	Now     = "2026-09-27T12:00:00Z"
)

var (
	born     = time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	dies     = time.Date(2027, 9, 1, 0, 0, 0, 0, time.UTC)
	modified = time.Date(2026, 9, 27, 10, 0, 0, 0, time.UTC)
)

// Case is one file of the corpus and what a reader must answer.
type Case struct {
	File string `json:"file"`
	// Why the file is here, in a person's words.
	About string `json:"about"`
	// "core": the refusal is the core's, and parity reproduces it from the file's members; "host":
	// only a host reading the container can see it (bytes actually decompressed, UTF-8, the media's
	// own hash), so the two hosts' tests hold it.
	Stage string `json:"stage,omitempty"`
	// The refusal, exactly; or, where two containers word a broken entry differently, its start.
	Refusal       string `json:"refusal,omitempty"`
	RefusalPrefix string `json:"refusal_prefix,omitempty"`
	// A file that must be accepted, and what it holds.
	Accept *Accept `json:"accept,omitempty"`
}

// Accept is what a valid file holds, and which rows' leaves pin nothing.
type Accept struct {
	Contacts int `json:"contacts"`
	// Removed counts the removed threads (a former contact's conversation); written only for a file
	// that has them.
	Removed  int `json:"removed,omitempty"`
	Threads  int `json:"threads"`
	Messages int `json:"messages"`
	Media    int `json:"media"`
	// Pinned counts the rows whose leaf is answered; Leafless names those whose leaf is not.
	Pinned   int      `json:"pinned"`
	Leafless []string `json:"leafless"`
}

// Index is cases.json.
type Index struct {
	Owner string `json:"owner"`
	Now   string `json:"now"`
	Cases []Case `json:"cases"`
}

type entry struct {
	name      string
	data      []byte
	encrypted bool
	mode      fs.FileMode // 0: a regular file, 0644
	// size, when set, is the uncompressed size the headers state instead of the true one.
	size *uint64
	// deflate compresses the member: the files of a bound's size, which stored would put megabytes
	// into the repository. Everything else is stored, its bytes its own.
	deflate bool
}

func seed(label string) []byte {
	s := sha256.Sum256([]byte("hdtp-identity/exportcorpus/" + label))
	return s[:]
}

func serial(label string) []byte { return seed("serial/" + label)[:8] }

func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func sum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func call(name string, args any) (map[string]any, error) {
	in, err := json.Marshal(args)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(hdtp.Call(name, in), &out); err != nil {
		return nil, err
	}
	if why, refused := out["why"].(string); refused && out["error"] != nil {
		return nil, fmt.Errorf("%s: %s", name, why)
	}
	return out, nil
}

func zipOf(entries []entry) ([]byte, error) {
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for _, e := range entries {
		if e.deflate {
			fh := &zip.FileHeader{Name: e.name, Method: zip.Deflate, Modified: modified}
			fh.SetMode(0o644)
			fw, err := w.CreateHeader(fh)
			if err != nil {
				return nil, err
			}
			if _, err := fw.Write(e.data); err != nil {
				return nil, err
			}
			continue
		}
		size := uint64(len(e.data))
		if e.size != nil {
			size = *e.size
		}
		fh := &zip.FileHeader{Name: e.name, Method: zip.Store, Modified: modified, CRC32: crc32.ChecksumIEEE(e.data),
			CompressedSize64: uint64(len(e.data)), UncompressedSize64: size}
		switch {
		case e.mode != 0:
			fh.SetMode(e.mode)
		case strings.HasSuffix(e.name, "/"):
			fh.SetMode(fs.ModeDir | 0o755)
		default:
			fh.SetMode(0o644)
		}
		if e.encrypted {
			fh.Flags |= 1
		}
		fw, err := w.CreateRaw(fh)
		if err != nil {
			return nil, err
		}
		if _, err := fw.Write(e.data); err != nil {
			return nil, err
		}
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// localNamesDiffer rewrites the name in every local file header of a zip to `../` over its first
// three bytes, leaving each length, CRC and offset, and the whole central directory, as they were.
func localNamesDiffer(z []byte) []byte {
	out := append([]byte{}, z...)
	for i := 0; i+30 <= len(out); {
		if !bytes.Equal(out[i:i+4], []byte{0x50, 0x4b, 0x03, 0x04}) {
			break
		}
		nameLen := int(out[i+26]) | int(out[i+27])<<8
		extraLen := int(out[i+28]) | int(out[i+29])<<8
		compressed := int(out[i+18]) | int(out[i+19])<<8 | int(out[i+20])<<16 | int(out[i+21])<<24
		if nameLen >= 3 {
			copy(out[i+30:], "../")
		}
		i += 30 + nameLen + extraLen + compressed
	}
	return out
}

// export is the valid file's members, which the variants below copy and change one thing in.
type export struct {
	owner    string
	manifest map[string]any
	members  []entry // in the order they are written, the manifest last
}

func (x export) clone() export {
	m := map[string]any{}
	raw, _ := json.Marshal(x.manifest)
	_ = json.Unmarshal(raw, &m)
	members := make([]entry, len(x.members))
	copy(members, x.members)
	return export{owner: x.owner, manifest: m, members: members}
}

func (x *export) set(name string, data []byte) {
	for i := range x.members {
		if x.members[i].name == name {
			x.members[i].data = data
			return
		}
	}
	x.members = append(x.members, entry{name: name, data: data})
}

func (x *export) get(name string) []byte {
	for _, e := range x.members {
		if e.name == name {
			return e.data
		}
	}
	return nil
}

func (x *export) drop(name string) {
	var kept []entry
	for _, e := range x.members {
		if e.name != name {
			kept = append(kept, e)
		}
	}
	x.members = kept
}

func (x export) files() map[string]any { return x.manifest["files"].(map[string]any) }

func (x export) counts() map[string]any { return x.manifest["counts"].(map[string]any) }

// relist sets manifest.files to the true hash of every text member: a media member is bound by its
// name and counted, never listed.
func (x *export) relist() {
	files := map[string]any{}
	for _, e := range x.members {
		if !strings.HasPrefix(e.name, "media/") {
			files[e.name] = sum(e.data)
		}
	}
	x.manifest["files"] = files
}

func (x export) zip() ([]byte, error) {
	manifest := hdtp.Canonical(x.manifest)
	return zipOf(append(append([]entry{}, x.members...), entry{name: "manifest.json", data: manifest}))
}

type identity struct {
	key  *hdtp.PrivateKey
	fp   string
	cert string
}

func root(label, cn string) (identity, error) {
	k, err := hdtp.KeyFromSeed(hdtp.AlgEd25519, seed(label))
	if err != nil {
		return identity{}, err
	}
	der, err := hdtp.BuildRoot(hdtp.RootOpts{CN: cn, Key: k, NotBefore: born, Serial: serial(label)})
	if err != nil {
		return identity{}, err
	}
	return identity{key: k, fp: hdtp.Fingerprint(k.Public().SPKI), cert: b64u(der)}, nil
}

func leaf(of identity, cn, host, endpoint string) (string, error) {
	h, err := hdtp.KeyFromSeed(hdtp.AlgEd25519, seed("host/"+host))
	if err != nil {
		return "", err
	}
	der, err := hdtp.BuildLeaf(hdtp.LeafOpts{CN: cn, RootCN: cn, RootKey: of.key, HostPub: h.Public(), Endpoint: endpoint,
		NotBefore: born, NotAfter: dies, Serial: serial("leaf/" + host)})
	return b64u(der), err
}

// valid builds the valid export, the book, and the valid export with a former contact's
// conversation added (a removed thread), through the library's own writer.
func valid() (export, []byte, []string, export, error) {
	var fail export
	owner, err := root("owner", OwnerCN)
	if err != nil {
		return fail, nil, nil, fail, err
	}
	bharat, err := root("bharat", "Bharat")
	if err != nil {
		return fail, nil, nil, fail, err
	}
	chen, err := root("chen", "Chen")
	if err != nil {
		return fail, nil, nil, fail, err
	}
	dana, err := root("dana", "Dana")
	if err != nil {
		return fail, nil, nil, fail, err
	}
	eve, err := root("eve", "Eve")
	if err != nil {
		return fail, nil, nil, fail, err
	}
	bharatLeaf, err := leaf(bharat, "Bharat", "bharat", "https://agent.bharat.example/mcp")
	if err != nil {
		return fail, nil, nil, fail, err
	}
	// Chen's leaf names another address than Chen's row: it validates nowhere the row points, so
	// it pins nothing and the reader answers it null.
	chenLeaf, err := leaf(chen, "Chen", "chen", "https://old.chen.example/mcp")
	if err != nil {
		return fail, nil, nil, fail, err
	}
	media := []byte("%PDF-1.7\nthe bytes of a.pdf\n")
	h := sum(media)
	contacts := []map[string]any{
		{"root": bharat.fp, "endpoint": "https://agent.bharat.example/mcp", "name": "Bharat", "display_name": "Bharat S.", "status": "active",
			"was_active": true, "permissions": []string{"message.text", "message.media"}, "their_permissions": []string{"message.text"},
			"leaf": bharatLeaf, "root_cert": bharat.cert, "added": "2026-09-02T09:00:00Z"},
		{"root": chen.fp, "endpoint": "https://chen.example/mcp", "name": "=HYPERLINK(\"https://x.example\")", "display_name": "'Tis Chen",
			"status": "active", "was_active": true, "permissions": []string{"message.text"}, "their_permissions": []string{},
			"leaf": chenLeaf, "root_cert": chen.cert, "added": "2026-09-03T09:00:00Z"},
		{"root": dana.fp, "endpoint": "https://dana.example/agent/mcp", "name": "\tDana, tabbed", "display_name": "\rDana",
			"status": "blocked", "was_active": true, "permissions": []string{"integration.calendar-x", "message.text"}, "their_permissions": []string{},
			"leaf": nil, "root_cert": nil, "added": "2026-09-04T09:00:00Z"},
		{"root": eve.fp, "endpoint": "https://eve.example/mcp", "name": "@SUM(A1:A9)", "display_name": "+61 -2 \"Eve\"",
			"status": "pending_out", "was_active": false, "permissions": []string{}, "their_permissions": []string{"message.media"},
			"leaf": nil, "root_cert": nil, "added": "2026-09-05T09:00:00Z"},
	}
	threads := []map[string]any{
		{"id": "t1", "contact": bharat.fp, "topic": "-minus: a topic that begins with a sign", "created_at": "2026-09-10T10:00:00Z", "last_at": "2026-09-11T10:00:00Z"},
		{"id": "t2", "contact": dana.fp, "topic": "plain, with a comma, \"quotes\"\r\nand a second line", "created_at": "2026-09-12T10:00:00Z", "last_at": "2026-09-12T10:05:00Z"},
	}
	messages := []map[string]any{
		{"id": "m1", "thread": "t1", "contact": bharat.fp, "msg_id": "msg-1", "direction": "in", "sender": "human", "time": "2026-09-10T10:00:00Z",
			"body": "Hello,\nthis spans two lines.", "reply_to": nil, "status": "delivered", "attachments": []any{}},
		{"id": "m2", "thread": "t1", "contact": bharat.fp, "msg_id": "msg-2", "direction": "out", "sender": "agent", "time": "2026-09-11T10:00:00Z",
			"body": "", "reply_to": "msg-1", "status": "read", "attachments": []any{map[string]any{"file": h, "filename": "a.pdf", "mime": "application/pdf", "size": len(media)}}},
		{"id": "m3", "thread": "t2", "contact": dana.fp, "msg_id": "msg-3", "direction": "out", "sender": "human", "time": "2026-09-12T10:00:00Z",
			"body": "https://files.example/a-link-not-a-file", "reply_to": nil, "status": "queued", "attachments": []any{}},
		{"id": "m4", "thread": "t2", "contact": dana.fp, "msg_id": "msg-4", "direction": "in", "sender": "agent", "time": "2026-09-12T10:05:00Z",
			"body": "=not a formula in JSON", "reply_to": "msg-3", "status": "failed", "attachments": []any{}},
	}
	w, err := call("export_write", map[string]any{"owner": owner.fp, "owner_name": OwnerCN, "exported_at": "2026-09-27T10:00:00Z",
		"tool": "hdtp-identity exportcorpus", "contacts": contacts, "threads": threads, "media": []any{map[string]any{"hash": h, "size": len(media)}}})
	if err != nil {
		return fail, nil, nil, fail, err
	}
	ml, err := call("export_write_messages", map[string]any{"messages": messages})
	if err != nil {
		return fail, nil, nil, fail, err
	}
	var jsonl []byte
	for _, l := range ml["lines"].([]any) {
		jsonl = append(append(jsonl, l.(string)...), '\n')
	}
	m, err := call("export_manifest", map[string]any{"partial": w["partial"], "hashes": map[string]any{"messages.jsonl": sum(jsonl)}, "messages": len(messages)})
	if err != nil {
		return fail, nil, nil, fail, err
	}
	var manifest map[string]any
	if err := json.Unmarshal([]byte(m["manifest"].(string)), &manifest); err != nil {
		return fail, nil, nil, fail, err
	}
	x := export{owner: owner.fp, manifest: manifest, members: []entry{
		{name: "contacts.csv", data: []byte(w["contacts_csv"].(string))},
		{name: "threads.csv", data: []byte(w["threads_csv"].(string))},
		{name: "messages.jsonl", data: jsonl},
		{name: "media/"},
		{name: "media/" + h, data: media},
	}}

	bw, err := call("export_write", map[string]any{"owner": owner.fp, "owner_name": OwnerCN, "exported_at": "2026-09-27T10:00:00Z",
		"tool": "hdtp-identity exportcorpus", "contacts": []any{contacts[0], contacts[3]}})
	if err != nil {
		return fail, nil, nil, fail, err
	}
	bm, err := call("export_manifest", map[string]any{"partial": bw["partial"]})
	if err != nil {
		return fail, nil, nil, fail, err
	}
	book, err := zipOf([]entry{{name: "contacts.csv", data: []byte(bw["contacts_csv"].(string))}, {name: "manifest.json", data: []byte(bm["manifest"].(string))}})
	if err != nil {
		return fail, nil, nil, fail, err
	}

	// The same export, and a conversation with Farid, a former contact: a removed thread carrying
	// his names, and a message carrying a second file.
	farid, err := root("farid", "Farid")
	if err != nil {
		return fail, nil, nil, fail, err
	}
	notes := []byte("notes from the old job\n")
	nh := sum(notes)
	rthreads := append(append([]map[string]any{}, threads...),
		map[string]any{"id": "t3", "contact": farid.fp, "topic": "the handover", "created_at": "2026-09-14T10:00:00Z", "last_at": "2026-09-14T10:00:00Z",
			"contact_name": "Farid, from the old job", "contact_display_name": "Farid K."})
	rmessages := append(append([]map[string]any{}, messages...),
		map[string]any{"id": "m5", "thread": "t3", "contact": farid.fp, "msg_id": "msg-5", "direction": "in", "sender": "human", "time": "2026-09-14T10:00:00Z",
			"body": "", "reply_to": nil, "status": "delivered", "attachments": []any{map[string]any{"file": nh, "filename": "notes.txt", "mime": "text/plain", "size": len(notes)}}})
	rw, err := call("export_write", map[string]any{"owner": owner.fp, "owner_name": OwnerCN, "exported_at": "2026-09-27T10:00:00Z",
		"tool": "hdtp-identity exportcorpus", "contacts": contacts, "threads": rthreads,
		"media": []any{map[string]any{"hash": h, "size": len(media)}, map[string]any{"hash": nh, "size": len(notes)}}})
	if err != nil {
		return fail, nil, nil, fail, err
	}
	rml, err := call("export_write_messages", map[string]any{"messages": rmessages})
	if err != nil {
		return fail, nil, nil, fail, err
	}
	var rjsonl []byte
	for _, l := range rml["lines"].([]any) {
		rjsonl = append(append(rjsonl, l.(string)...), '\n')
	}
	rm, err := call("export_manifest", map[string]any{"partial": rw["partial"], "hashes": map[string]any{"messages.jsonl": sum(rjsonl)}, "messages": len(rmessages)})
	if err != nil {
		return fail, nil, nil, fail, err
	}
	var rmanifest map[string]any
	if err := json.Unmarshal([]byte(rm["manifest"].(string)), &rmanifest); err != nil {
		return fail, nil, nil, fail, err
	}
	xr := export{owner: owner.fp, manifest: rmanifest, members: []entry{
		{name: "contacts.csv", data: []byte(rw["contacts_csv"].(string))},
		{name: "threads.csv", data: []byte(rw["threads_csv"].(string))},
		{name: "messages.jsonl", data: rjsonl},
		{name: "media/"},
		{name: "media/" + h, data: media},
		{name: "media/" + nh, data: notes},
	}}
	return x, book, []string{chen.fp}, xr, nil
}

// alias is a fingerprint with its last character's two spare bits set: the same 32 bytes, spelled a
// second way, which no reader takes (SPEC §2).
func alias(fp string) string {
	const b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	last := strings.IndexByte(b64, fp[len(fp)-1])
	return fp[:len(fp)-1] + string(b64[last+1])
}

// Build answers every file of the corpus by name, cases.json included.
func Build() (map[string][]byte, error) {
	x, book, leafless, xr, err := valid()
	if err != nil {
		return nil, err
	}
	media := ""
	for _, e := range x.members {
		if strings.HasPrefix(e.name, "media/") && len(e.name) > len("media/") {
			media = e.name
		}
	}
	out := map[string][]byte{}
	index := Index{Owner: x.owner, Now: Now}
	add := func(c Case, data []byte, err error) error {
		if err != nil {
			return fmt.Errorf("%s: %w", c.File, err)
		}
		out[c.File] = data
		index.Cases = append(index.Cases, c)
		return nil
	}
	whole, err := x.zip()
	if err := add(Case{File: "valid-export.zip", About: "the control: every member, formula-led cells, a leaf that pins and one that does not, a link message and a file message",
		Accept: &Accept{Contacts: 4, Threads: 2, Messages: 4, Media: 1, Pinned: 1, Leafless: leafless}}, whole, err); err != nil {
		return nil, err
	}
	if err := add(Case{File: "valid-book.zip", About: "the control: a wallet's book, manifest.json and contacts.csv only",
		Accept: &Accept{Contacts: 2, Pinned: 1, Leafless: []string{}}}, book, nil); err != nil {
		return nil, err
	}
	// SPEC 9.2#6: the central directory is the only index. The valid export with every LOCAL file
	// header naming another member of the same length — `../` over its first three bytes — and the
	// central directory as it was: a reader that indexes the directory reads the valid export, one
	// that walks the local headers finds names that climb out of the directory.
	if err := add(Case{File: "local-names-differ.zip", About: "every local header names a path that climbs out; the central directory is the valid export's",
		Accept: &Accept{Contacts: 4, Threads: 2, Messages: 4, Media: 1, Pinned: 1, Leafless: leafless}}, localNamesDiffer(whole), nil); err != nil {
		return nil, err
	}

	withRemoved, err := xr.zip()
	if err := add(Case{File: "valid-export-with-removed-thread.zip", About: "the control with a former contact's conversation: a removed thread carrying his names, and a message carrying a file",
		Accept: &Accept{Contacts: 4, Removed: 1, Threads: 3, Messages: 5, Media: 2, Pinned: 1, Leafless: leafless}}, withRemoved, err); err != nil {
		return nil, err
	}

	// A removed thread for which the host held no name: both names empty, the root its label.
	nameless := xr.clone()
	nameless.set("threads.csv", []byte(strings.Replace(string(xr.get("threads.csv")), ",\"Farid, from the old job\",Farid K.\r\n", ",,\r\n", 1)))
	nameless.relist()
	withNameless, err := nameless.zip()
	if err := add(Case{File: "valid-export-with-a-nameless-removed-thread.zip", About: "the control with a removed thread whose two names are empty",
		Accept: &Accept{Contacts: 4, Removed: 1, Threads: 3, Messages: 5, Media: 2, Pinned: 1, Leafless: leafless}}, withNameless, err); err != nil {
		return nil, err
	}

	// A variant: the valid export (or, for the removed thread's cases, the export with one) with one
	// change, zipped.
	variantOf := func(base export, file, about, stage, refusal string, change func(v *export) []entry) error {
		v := base.clone()
		entries := change(&v)
		var data []byte
		var err error
		if entries != nil {
			data, err = zipOf(entries)
		} else {
			data, err = v.zip()
		}
		c := Case{File: file, About: about, Stage: stage, Refusal: refusal}
		if strings.HasSuffix(refusal, "…") {
			c.Refusal, c.RefusalPrefix = "", strings.TrimSuffix(refusal, "…")
		}
		return add(c, data, err)
	}
	variant := func(file, about, stage, refusal string, change func(v *export) []entry) error {
		return variantOf(x, file, about, stage, refusal, change)
	}
	withManifest := func(v *export, extra ...entry) []entry {
		return append(append(append([]entry{}, v.members...), entry{name: "manifest.json", data: hdtp.Canonical(v.manifest)}), extra...)
	}
	rename := func(v *export, from, to string) {
		for i := range v.members {
			if v.members[i].name == from {
				v.members[i].name = to
			}
		}
	}
	contactsCSV := string(x.get("contacts.csv"))
	jsonl := strings.SplitAfter(string(x.get("messages.jsonl")), "\n")
	line := func(i int) map[string]any {
		var m map[string]any
		_ = json.Unmarshal([]byte(jsonl[i]), &m)
		return m
	}
	setLines := func(v *export, lines []string) {
		v.set("messages.jsonl", []byte(strings.Join(lines, "")))
		v.relist()
	}
	withLine := func(v *export, i int, m map[string]any) {
		lines := append([]string{}, jsonl...)
		lines[i] = string(hdtp.Canonical(m)) + "\n"
		setLines(v, lines)
	}
	someKey, err := hdtp.KeyFromSeed(hdtp.AlgEd25519, seed("some-key"))
	if err != nil {
		return nil, err
	}
	pkcs8, err := someKey.PKCS8()
	if err != nil {
		return nil, err
	}
	// The row Bharat is on: rows are sorted by root, so it is found, not assumed.
	bharatRow := 0
	for i, l := range strings.SplitAfter(contactsCSV, "\r\n") {
		if strings.Contains(l, ",Bharat,") {
			bharatRow = i + 1
		}
	}
	// Chen's row, found the same way: the only name that begins with the HYPERLINK formula.
	chenRow := 0
	for i, l := range strings.SplitAfter(contactsCSV, "\r\n") {
		if strings.Contains(l, "HYPERLINK") {
			chenRow = i + 1
		}
	}
	// deflated is the variant's members and manifest with the named member compressed.
	deflated := func(v *export, name string) []entry {
		e := withManifest(v)
		for i := range e {
			if e[i].name == name {
				e[i].deflate = true
			}
		}
		return e
	}
	// swapMedia puts data where the one media file was: the member named by its hash, the
	// attachment naming it and stating its size.
	swapMedia := func(v *export, data []byte) {
		for i := range v.members {
			if v.members[i].name == media {
				v.members[i] = entry{name: "media/" + sum(data), data: data}
			}
		}
		m := line(1)
		a := m["attachments"].([]any)[0].(map[string]any)
		a["file"], a["size"] = sum(data), len(data)
		withLine(v, 1, m)
	}
	sec1 := append([]byte{0x30, 0x25, 0x02, 0x01, 0x01, 0x04, 0x20}, seed("sec1")...)

	steps := []struct {
		file, about, stage, refusal string
		change                      func(v *export) []entry
	}{
		{"zip-slip.zip", "a name that climbs out of the directory", "core", `entry "../contacts.csv": not a name an export holds`,
			func(v *export) []entry { rename(v, "contacts.csv", "../contacts.csv"); return withManifest(v) }},
		{"absolute-path.zip", "an absolute name", "core", `entry "/contacts.csv": not a name an export holds`,
			func(v *export) []entry { rename(v, "contacts.csv", "/contacts.csv"); return withManifest(v) }},
		{"backslash.zip", "a name with a backslash", "core", `entry "media\\` + media[len("media/"):] + `": not a name an export holds`,
			func(v *export) []entry { rename(v, media, `media\`+media[len("media/"):]); return withManifest(v) }},
		{"unknown-file.zip", "a member §9.2 does not name", "core", `entry "notes.txt": not a name an export holds`,
			func(v *export) []entry { return withManifest(v, entry{name: "notes.txt", data: []byte("hello\n")}) }},
		{"duplicate-name.zip", "the same name twice", "core", `entry "contacts.csv": appears twice`,
			func(v *export) []entry { return withManifest(v, entry{name: "contacts.csv", data: []byte("root\r\n")}) }},
		{"encrypted-entry.zip", "an encrypted entry", "core", `entry "contacts.csv": encrypted`,
			func(v *export) []entry {
				e := withManifest(v)
				e[0].encrypted = true
				return e
			}},
		{"symlink.zip", "a symbolic link", "core", `entry "threads.csv": a symbolic link`,
			func(v *export) []entry {
				e := withManifest(v)
				e[1].mode = fs.ModeSymlink | 0o777
				return e
			}},
		{"directory.zip", "a directory that is not media/", "core", `entry "threads.csv": a directory`,
			func(v *export) []entry {
				e := withManifest(v)
				e[1].mode = fs.ModeDir | 0o755
				return e
			}},
		{"oversize-manifest.zip", "a manifest over 64 KiB, as its header says", "core", `entry "manifest.json": 65537 bytes, over the 65536 an export allows`,
			func(v *export) []entry {
				m := hdtp.Canonical(v.manifest)
				m = append(m, bytes.Repeat([]byte(" "), 65537-len(m))...)
				return append(append([]entry{}, v.members...), entry{name: "manifest.json", data: m})
			}},
		{"understated-size.zip", "a manifest whose headers state 16 bytes and which holds 70000", "host", "manifest.json: …",
			func(v *export) []entry {
				m := hdtp.Canonical(v.manifest)
				m = append(m, bytes.Repeat([]byte(" "), 70000-len(m))...)
				small := uint64(16)
				return append(append([]entry{}, v.members...), entry{name: "manifest.json", data: m, size: &small})
			}},
		{"missing-contacts.zip", "no contacts.csv", "core", "contacts.csv: the file lacks it",
			func(v *export) []entry { v.drop("contacts.csv"); return nil }},
		{"missing-threads.zip", "threads counted and threads.csv absent", "core", "threads.csv: manifest.json's files lists it, and the file lacks it",
			func(v *export) []entry { v.drop("threads.csv"); return nil }},
		{"unlisted-member.zip", "a member manifest.json's files does not list", "core", "messages.jsonl: manifest.json's files does not list it",
			func(v *export) []entry { delete(v.files(), "messages.jsonl"); return nil }},
		{"hash-mismatch.zip", "contacts.csv changed after the manifest hashed it", "core", "contacts.csv: its sha256 is not manifest.json's",
			func(v *export) []entry {
				v.set("contacts.csv", []byte(strings.Replace(contactsCSV, "Bharat S.", "Bharat Z.", 1)))
				return nil
			}},
		{"media-listed-in-files.zip", "manifest.json lists a media member in files, where only text members go", "core",
			`manifest.json: files: "` + media + `" is not a member an export lists`,
			func(v *export) []entry { v.files()[media] = media[len("media/"):]; return nil }},
		{"media-bytes-not-name.zip", "a media file whose bytes are not its name", "host", media + ": its sha256 is not its name",
			func(v *export) []entry { v.set(media, []byte("%PDF-1.7\nnot the bytes named\n")); return nil }},
		{"count-mismatch.zip", "counts that are not what the file holds", "core", "manifest.json: counts: contacts is 5, and contacts.csv holds 4",
			func(v *export) []entry { v.counts()["contacts"] = 5; return nil }},
		{"wrong-owner.zip", "another identity's export", "core", "manifest.json: owner: the file is sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA's, not this identity's (" + x.owner + ")",
			func(v *export) []entry { v.manifest["owner"] = "sha256:" + strings.Repeat("A", 43); return nil }},
		{"owner-as-contact.zip", "a contact row whose root is the owner", "core", "contacts.csv: row 2, column root: the owner's own root",
			func(v *export) []entry {
				lines := strings.SplitAfter(contactsCSV, "\r\n")
				cells := strings.SplitN(lines[1], ",", 2)
				lines[1] = x.owner + "," + cells[1]
				v.set("contacts.csv", []byte(strings.Join(lines, "")))
				v.relist()
				return nil
			}},
		{"contact-root-alias.zip", "a contact row whose root is another row's with its spare bits set", "core", fmt.Sprintf("contacts.csv: row %d, column root: not a fingerprint", 2),
			func(v *export) []entry {
				lines := strings.SplitAfter(contactsCSV, "\r\n")
				lines[1] = alias(strings.SplitN(lines[2], ",", 2)[0]) + "," + strings.SplitN(lines[1], ",", 2)[1]
				v.set("contacts.csv", []byte(strings.Join(lines, "")))
				v.relist()
				return nil
			}},
		{"bad-header.zip", "a header that is not the one §9.2 shows", "core", "contacts.csv: row 1: the header is not root,endpoint,name,display_name,status,was_active,permissions,their_permissions,leaf,root_cert,added",
			func(v *export) []entry {
				v.set("contacts.csv", []byte(strings.Replace(contactsCSV, "display_name", "nickname", 1)))
				v.relist()
				return nil
			}},
		{"blank-row.zip", "a blank row in contacts.csv", "core", "contacts.csv: row 3: a blank row",
			func(v *export) []entry {
				lines := strings.SplitAfter(contactsCSV, "\r\n")
				v.set("contacts.csv", []byte(lines[0]+lines[1]+"\r\n"+strings.Join(lines[2:], "")))
				v.relist()
				return nil
			}},
		{"not-utf8.zip", "a contacts.csv that is not UTF-8", "host", "contacts.csv: not UTF-8 text",
			func(v *export) []entry {
				v.set("contacts.csv", []byte(strings.Replace(contactsCSV, "Bharat S.", "Bharat \xff.", 1)))
				v.relist()
				return nil
			}},
		{"key-in-a-cell.zip", "a PKCS #8 private key in a contact's name", "core", fmt.Sprintf("contacts.csv: row %d, column name: holds a private key", bharatRow),
			func(v *export) []entry {
				v.set("contacts.csv", []byte(strings.Replace(contactsCSV, ",Bharat,", ","+b64u(pkcs8)+",", 1)))
				v.relist()
				return nil
			}},
		{"dangling-thread-contact.zip", "a thread whose contact is in no row", "core", "threads.csv: row 2, column contact: names no contact in contacts.csv",
			func(v *export) []entry {
				t := string(v.get("threads.csv"))
				v.set("threads.csv", []byte(strings.Replace(t, strings.Split(strings.SplitAfter(t, "\r\n")[1], ",")[1], "sha256:"+strings.Repeat("B", 43), 1)))
				v.relist()
				return nil
			}},
		{"dangling-message-thread.zip", "a message in no thread", "core", "messages.jsonl: line 1, member thread: names no thread in threads.csv",
			func(v *export) []entry {
				m := line(0)
				m["thread"] = "t9"
				withLine(v, 0, m)
				return nil
			}},
		{"dangling-reply.zip", "a reply to a message the file lacks", "core", `messages.jsonl: reply_to "msg-9" names no message in the file`,
			func(v *export) []entry {
				m := line(3)
				m["reply_to"] = "msg-9"
				withLine(v, 3, m)
				return nil
			}},
		{"dangling-attachment.zip", "an attachment naming no media member", "core", "messages.jsonl: line 2, member attachments: file names no media member",
			func(v *export) []entry {
				m := line(1)
				m["attachments"].([]any)[0].(map[string]any)["file"] = sum([]byte("elsewhere"))
				withLine(v, 1, m)
				return nil
			}},
		{"unreferenced-media.zip", "a media file nothing names", "core", media + ": nothing names it",
			func(v *export) []entry {
				m := line(1)
				m["attachments"] = []any{}
				withLine(v, 1, m)
				return nil
			}},
		{"two-attachments.zip", "a message with two files", "core", "messages.jsonl: line 2, member attachments: more than one attachment: a message carries at most one file",
			func(v *export) []entry {
				m := line(1)
				a := m["attachments"].([]any)
				m["attachments"] = []any{a[0], a[0]}
				withLine(v, 1, m)
				return nil
			}},
		{"body-with-a-file.zip", "a message carrying a file and text", "core", "messages.jsonl: line 2, member body: not empty, and the message carries a file: a message with an attachment has no text",
			func(v *export) []entry {
				m := line(1)
				m["body"] = "and a caption"
				withLine(v, 1, m)
				return nil
			}},
		{"key-in-a-body.zip", "a SEC1 private key in a message body", "core", "messages.jsonl: line 1, member body: holds a private key",
			func(v *export) []entry {
				m := line(0)
				m["body"] = "my key, for safe keeping: " + base64.StdEncoding.EncodeToString(sec1)
				withLine(v, 0, m)
				return nil
			}},
		{"unknown-message-member.zip", "a message with a member §9.2 does not list", "core", `messages.jsonl: line 1: "note" is not a member of a message`,
			func(v *export) []entry {
				m := line(0)
				m["note"] = "hello"
				withLine(v, 0, m)
				return nil
			}},
		{"long-line.zip", "a line of messages.jsonl over 64 KiB", "host", "messages.jsonl: line 1: over 65536 bytes",
			func(v *export) []entry {
				lines := append([]string{}, jsonl...)
				lines[0] = strings.Repeat(" ", 65537) + lines[0]
				setLines(v, lines)
				return nil
			}},
		{"message-count.zip", "messages counted that are not there", "core", "manifest.json: counts: messages is 5, and messages.jsonl holds 4 lines",
			func(v *export) []entry { v.counts()["messages"] = 5; return nil }},
		{"messages-hash.zip", "messages.jsonl changed after the manifest hashed it", "core", "messages.jsonl: its sha256 is not manifest.json's",
			func(v *export) []entry {
				v.set("messages.jsonl", []byte(strings.Replace(string(v.get("messages.jsonl")), "two lines", "2 lines", 1)))
				return nil
			}},
		// SPEC 9.2#10, one file per bound, each member deflated so the repository holds kilobytes;
		// its headers state its true size, so the directory is where a reader first meets it.
		{"contacts-over-4-mib.zip", "a contacts.csv one byte over 4 MiB", "core",
			fmt.Sprintf(`entry "contacts.csv": %d bytes, over the %d an export allows`, 4<<20+1, 4<<20),
			func(v *export) []entry {
				v.set("contacts.csv", append([]byte(contactsCSV), bytes.Repeat([]byte("x"), 4<<20+1-len(contactsCSV))...))
				v.relist()
				return deflated(v, "contacts.csv")
			}},
		{"contacts-over-5000-rows.zip", "a contacts.csv of 5001 rows, well under 4 MiB", "core", "contacts.csv: over 5000 rows",
			func(v *export) []entry {
				header := strings.SplitAfter(contactsCSV, "\r\n")[0]
				v.set("contacts.csv", []byte(header+strings.Repeat("x\r\n", 5001)))
				v.counts()["contacts"] = 5001
				v.relist()
				return deflated(v, "contacts.csv")
			}},
		{"threads-over-16-mib.zip", "a threads.csv one byte over 16 MiB", "core",
			fmt.Sprintf(`entry "threads.csv": %d bytes, over the %d an export allows`, 16<<20+1, 16<<20),
			func(v *export) []entry {
				t := v.get("threads.csv")
				v.set("threads.csv", append(append([]byte{}, t...), bytes.Repeat([]byte("x"), 16<<20+1-len(t))...))
				v.relist()
				return deflated(v, "threads.csv")
			}},
		{"media-over-5-mib.zip", "a media file one byte over 5 MiB, named by its hash and attached", "core",
			fmt.Sprintf(`entry "media/%s": %d bytes, over the %d an export allows`, sum(bytes.Repeat([]byte("m"), 5<<20+1)), 5<<20+1, 5<<20),
			func(v *export) []entry {
				big := bytes.Repeat([]byte("m"), 5<<20+1)
				swapMedia(v, big)
				return deflated(v, "media/"+sum(big))
			}},
		// SPEC 9.2#15: a certificate outside §14.1's profile. Chen's own leaf where Chen's root
		// certificate goes: a real certificate, of Chen's, and not a root.
		{"root-cert-not-a-root.zip", "a contact whose root_cert is a leaf, not a root of §14.1's profile", "core",
			fmt.Sprintf("contacts.csv: row %d, column root_cert: not a root of §14.1's profile", chenRow),
			func(v *export) []entry {
				lines := strings.SplitAfter(contactsCSV, "\r\n")
				c := strings.Split(lines[chenRow-1], ",")
				c[len(c)-2] = c[len(c)-3]
				lines[chenRow-1] = strings.Join(c, ",")
				v.set("contacts.csv", []byte(strings.Join(lines, "")))
				v.relist()
				return nil
			}},
		// SPEC 9.2#25: key material in a media file. Only a host reading the bytes can see it.
		{"media-is-a-key.zip", "a media file whose bytes are a PKCS #8 private key, named by its hash and attached", "host",
			"media/" + sum(pkcs8) + ": holds a private key",
			func(v *export) []entry { swapMedia(v, pkcs8); return nil }},
	}
	for _, s := range steps {
		if err := variant(s.file, s.about, s.stage, s.refusal, s.change); err != nil {
			return nil, err
		}
	}

	// The removed thread (SPEC §9.2): each case is the export with one, with one thing wrong. Its
	// row is the fourth of threads.csv (sorted by id: t1, t2, t3).
	rthreads := string(xr.get("threads.csv"))
	// Lines, not records: t2's topic holds a line break, so t3's record is the line that begins "t3,".
	rlines := strings.SplitAfter(rthreads, "\r\n")
	t3 := 0
	for i, l := range rlines {
		if strings.HasPrefix(l, "t3,") {
			t3 = i
		}
	}
	faridRoot := strings.Split(rlines[t3], ",")[1]
	setThreads := func(v *export, text string) {
		v.set("threads.csv", []byte(text))
		v.relist()
	}
	withRow := func(i int, row string) string {
		lines := append([]string{}, rlines...)
		lines[i] = row
		return strings.Join(lines, "")
	}
	rjsonl := strings.SplitAfter(string(xr.get("messages.jsonl")), "\n")
	bharatRoot := strings.Split(rlines[1], ",")[1]
	removedSteps := []struct {
		file, about, stage, refusal string
		change                      func(v *export) []entry
	}{
		{"removed-thread-is-owner.zip", "a removed thread whose root is the owner", "core", "threads.csv: row 4, column contact: the owner's own root",
			func(v *export) []entry { setThreads(v, strings.Replace(rthreads, faridRoot, x.owner, 1)); return nil }},
		{"removed-thread-not-a-fingerprint.zip", "a removed thread whose root is not a fingerprint", "core", "threads.csv: row 4, column contact: not a fingerprint",
			func(v *export) []entry { setThreads(v, strings.Replace(rthreads, faridRoot, "farid", 1)); return nil }},
		{"names-on-a-live-thread.zip", "a contact's thread carrying names", "core", "threads.csv: row 2, column contact_name: not empty, and the contact is in contacts.csv",
			func(v *export) []entry {
				setThreads(v, withRow(1, strings.TrimSuffix(rlines[1], ",,\r\n")+",x,\r\n"))
				return nil
			}},
		{"removed-thread-name-over-200.zip", "a removed thread whose name is 201 characters", "core", "threads.csv: row 4, column contact_name: over 200 characters",
			func(v *export) []entry {
				setThreads(v, strings.Replace(rthreads, "\"Farid, from the old job\"", strings.Repeat("n", 201), 1))
				return nil
			}},
		{"removed-thread-names-disagree.zip", "two removed threads of one root, naming him differently", "core",
			"threads.csv: row 5, column contact_display_name: not what an earlier removed thread of this contact says",
			func(v *export) []entry {
				setThreads(v, rthreads+strings.Replace(strings.Replace(rlines[t3], "t3,", "t4,", 1), "Farid K.", "Farid Khan", 1))
				v.counts()["threads"] = 4
				return nil
			}},
		{"named-header-without-a-removed-thread.zip", "the longer threads.csv header and no removed thread", "core",
			"threads.csv: row 1: the header names contact_name and contact_display_name, and no thread is a removed thread",
			func(v *export) []entry {
				setThreads(v, strings.Join(rlines[:t3], ""))
				v.counts()["threads"] = 2
				return nil
			}},
		{"threads-bad-header.zip", "a threads.csv header that is neither of §9.2's", "core", "threads.csv: row 1: the header is not id,contact,topic,created_at,last_at, nor that and contact_name,contact_display_name",
			func(v *export) []entry {
				setThreads(v, strings.Replace(rthreads, ",contact_display_name", ",display", 1))
				return nil
			}},
		{"removed-thread-display-name-over-200.zip", "a removed thread whose display name is 201 characters", "core", "threads.csv: row 4, column contact_display_name: over 200 characters",
			func(v *export) []entry {
				setThreads(v, strings.Replace(rthreads, ",Farid K.\r\n", ","+strings.Repeat("d", 201)+"\r\n", 1))
				return nil
			}},
		// A fingerprint has one spelling (SPEC §2): the last character's two spare bits are zero. The
		// same 32 bytes spelled with them set would be a second name for one root.
		{"removed-thread-alias-of-a-contact.zip", "a contact's root with its spare bits set, as a removed thread's root", "core", "threads.csv: row 2, column contact: not a fingerprint",
			func(v *export) []entry {
				setThreads(v, withRow(1, strings.Replace(rlines[1], bharatRoot, alias(bharatRoot), 1)))
				return nil
			}},
		{"removed-thread-alias-of-the-owner.zip", "the owner's root with its spare bits set, as a removed thread's root", "core", "threads.csv: row 4, column contact: not a fingerprint",
			func(v *export) []entry {
				setThreads(v, strings.Replace(rthreads, faridRoot, alias(x.owner), 1))
				return nil
			}},
		{"key-in-a-thread-name.zip", "a PKCS #8 private key in a removed thread's name", "core", "threads.csv: row 4, column contact_name: holds a private key",
			func(v *export) []entry {
				setThreads(v, strings.Replace(rthreads, "\"Farid, from the old job\"", b64u(pkcs8), 1))
				return nil
			}},
		{"removed-thread-six-fields.zip", "a removed thread of six fields under the longer header", "core", "threads.csv: row 4: 6 fields, not 7",
			func(v *export) []entry {
				setThreads(v, withRow(t3, strings.TrimSuffix(rlines[t3], ",Farid K.\r\n")+"\r\n"))
				return nil
			}},
		{"message-names-no-contact.zip", "a message whose contact is no contact and no removed thread's", "core",
			"messages.jsonl: line 5, member contact: names no contact in contacts.csv and no removed thread",
			func(v *export) []entry {
				var m map[string]any
				_ = json.Unmarshal([]byte(rjsonl[4]), &m)
				m["contact"] = "sha256:" + strings.Repeat("C", 43)
				lines := append([]string{}, rjsonl...)
				lines[4] = string(hdtp.Canonical(m)) + "\n"
				v.set("messages.jsonl", []byte(strings.Join(lines, "")))
				v.relist()
				return nil
			}},
	}
	for _, s := range removedSteps {
		if err := variantOf(xr, s.file, s.about, s.stage, s.refusal, s.change); err != nil {
			return nil, err
		}
	}
	idx, err := json.MarshalIndent(index, "", "  ")
	if err != nil {
		return nil, err
	}
	out["cases.json"] = append(idx, '\n')
	return out, nil
}
