package exportcorpus

// Build makes the whole corpus, deterministically: the same bytes on every run, so a test can hold
// the committed files to it. Every member is stored, never deflated — a compressor's output may
// change with the toolchain, and a stored member's bytes are its own — and every time and serial is
// fixed. The valid export and the book are what the library's own writer makes (export_write,
// export_write_messages, export_manifest); each hostile file is the valid export with ONE thing
// wrong, and cases.json names the refusal it must produce.

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

	pact "github.com/pact-cloud/pact-identity/go"
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
}

func seed(label string) []byte {
	s := sha256.Sum256([]byte("pact-identity/exportcorpus/" + label))
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
	if err := json.Unmarshal(pact.Call(name, in), &out); err != nil {
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

// relist sets manifest.files to the true hash of every member but the manifest and media/.
func (x *export) relist() {
	files := map[string]any{}
	for _, e := range x.members {
		if e.name != "media/" {
			files[e.name] = sum(e.data)
		}
	}
	for name := range files {
		if strings.HasPrefix(name, "media/") {
			files[name] = name[len("media/"):]
		}
	}
	x.manifest["files"] = files
}

func (x export) zip() ([]byte, error) {
	manifest := pact.Canonical(x.manifest)
	return zipOf(append(append([]entry{}, x.members...), entry{name: "manifest.json", data: manifest}))
}

type identity struct {
	key  *pact.PrivateKey
	fp   string
	cert string
}

func root(label, cn string) (identity, error) {
	k, err := pact.KeyFromSeed(pact.AlgEd25519, seed(label))
	if err != nil {
		return identity{}, err
	}
	der, err := pact.BuildRoot(pact.RootOpts{CN: cn, Key: k, NotBefore: born, Serial: serial(label)})
	if err != nil {
		return identity{}, err
	}
	return identity{key: k, fp: pact.Fingerprint(k.Public.SPKI), cert: b64u(der)}, nil
}

func leaf(of identity, cn, host, endpoint string) (string, error) {
	h, err := pact.KeyFromSeed(pact.AlgEd25519, seed("host/"+host))
	if err != nil {
		return "", err
	}
	der, err := pact.BuildLeaf(pact.LeafOpts{CN: cn, RootCN: cn, RootKey: of.key, HostPub: h.Public, Endpoint: endpoint,
		NotBefore: born, NotAfter: dies, Serial: serial("leaf/" + host)})
	return b64u(der), err
}

// valid builds the valid export and the book, through the library's own writer.
func valid() (export, []byte, []string, error) {
	var fail export
	owner, err := root("owner", OwnerCN)
	if err != nil {
		return fail, nil, nil, err
	}
	bharat, err := root("bharat", "Bharat")
	if err != nil {
		return fail, nil, nil, err
	}
	chen, err := root("chen", "Chen")
	if err != nil {
		return fail, nil, nil, err
	}
	dana, err := root("dana", "Dana")
	if err != nil {
		return fail, nil, nil, err
	}
	eve, err := root("eve", "Eve")
	if err != nil {
		return fail, nil, nil, err
	}
	bharatLeaf, err := leaf(bharat, "Bharat", "bharat", "https://agent.bharat.example/mcp")
	if err != nil {
		return fail, nil, nil, err
	}
	// Chen's leaf names another address than Chen's row: it validates nowhere the row points, so
	// it pins nothing and the reader answers it null.
	chenLeaf, err := leaf(chen, "Chen", "chen", "https://old.chen.example/mcp")
	if err != nil {
		return fail, nil, nil, err
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
		"tool": "pact-identity exportcorpus", "contacts": contacts, "threads": threads, "media": []any{map[string]any{"hash": h, "size": len(media)}}})
	if err != nil {
		return fail, nil, nil, err
	}
	ml, err := call("export_write_messages", map[string]any{"messages": messages})
	if err != nil {
		return fail, nil, nil, err
	}
	var jsonl []byte
	for _, l := range ml["lines"].([]any) {
		jsonl = append(append(jsonl, l.(string)...), '\n')
	}
	m, err := call("export_manifest", map[string]any{"partial": w["partial"], "hashes": map[string]any{"messages.jsonl": sum(jsonl)}, "messages": len(messages)})
	if err != nil {
		return fail, nil, nil, err
	}
	var manifest map[string]any
	if err := json.Unmarshal([]byte(m["manifest"].(string)), &manifest); err != nil {
		return fail, nil, nil, err
	}
	x := export{owner: owner.fp, manifest: manifest, members: []entry{
		{name: "contacts.csv", data: []byte(w["contacts_csv"].(string))},
		{name: "threads.csv", data: []byte(w["threads_csv"].(string))},
		{name: "messages.jsonl", data: jsonl},
		{name: "media/"},
		{name: "media/" + h, data: media},
	}}

	bw, err := call("export_write", map[string]any{"owner": owner.fp, "owner_name": OwnerCN, "exported_at": "2026-09-27T10:00:00Z",
		"tool": "pact-identity exportcorpus", "contacts": []any{contacts[0], contacts[3]}})
	if err != nil {
		return fail, nil, nil, err
	}
	bm, err := call("export_manifest", map[string]any{"partial": bw["partial"]})
	if err != nil {
		return fail, nil, nil, err
	}
	book, err := zipOf([]entry{{name: "contacts.csv", data: []byte(bw["contacts_csv"].(string))}, {name: "manifest.json", data: []byte(bm["manifest"].(string))}})
	return x, book, []string{chen.fp}, err
}

// Build answers every file of the corpus by name, cases.json included.
func Build() (map[string][]byte, error) {
	x, book, leafless, err := valid()
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

	// A variant: the valid export with one change, zipped.
	variant := func(file, about, stage, refusal string, change func(v *export) []entry) error {
		v := x.clone()
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
	withManifest := func(v *export, extra ...entry) []entry {
		return append(append(append([]entry{}, v.members...), entry{name: "manifest.json", data: pact.Canonical(v.manifest)}), extra...)
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
		lines[i] = string(pact.Canonical(m)) + "\n"
		setLines(v, lines)
	}
	someKey, err := pact.KeyFromSeed(pact.AlgEd25519, seed("some-key"))
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
				m := pact.Canonical(v.manifest)
				m = append(m, bytes.Repeat([]byte(" "), 65537-len(m))...)
				return append(append([]entry{}, v.members...), entry{name: "manifest.json", data: m})
			}},
		{"understated-size.zip", "a manifest whose headers state 16 bytes and which holds 70000", "host", "manifest.json: …",
			func(v *export) []entry {
				m := pact.Canonical(v.manifest)
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
		{"media-name-not-hash.zip", "manifest.json lists a media file under another hash", "core",
			"manifest.json: files: " + media + ": the hash is not the name",
			func(v *export) []entry { v.files()[media] = sum([]byte("other")); return nil }},
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
	}
	for _, s := range steps {
		if err := variant(s.file, s.about, s.stage, s.refusal, s.change); err != nil {
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
