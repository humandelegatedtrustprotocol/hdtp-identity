package hdtpidentity

// The export (SPEC §9.2; CONTRACT §6.2): one unencrypted zip carrying a person's contacts,
// conversations and files between hosts, and the wallet's book in the same format. The Rust core's
// export module, rule for rule and word for word; js/parity.mjs holds the two to each other.
//
// The core never opens a zip. A host reads the container and hands these functions what it read;
// what only the host can do — counting the bytes it decompresses, hashing messages.jsonl and each
// media file as it streams them, refusing a member that is not UTF-8 — is the host's (export_zip.go
// does it for a Go host). Every refusal is bad_request, and its why begins with where.

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	ExportManifestMax    = 64 * 1024
	ExportContactsMax    = 4 * 1024 * 1024
	ExportContactsRowMax = 5000
	ExportThreadsMax     = 16 * 1024 * 1024
	ExportLineMax        = 64 * 1024
	ExportMediaMax       = 5 * 1024 * 1024
	ExportBodyMax        = 16 * 1024
	ExportNameMax        = 200
	ExportAttachmentsMax = 1
	// ExportControlMax is this library's ceiling, as a host's own (SPEC §9.2, Ceilings), on the
	// characters below U+0020 but tab, line feed and carriage return in one CSV member: export_read's
	// answer writes U+0008 and U+000C as two bytes (\b, \f) and every other one as six (\u00XX), so a
	// member dense with them would take a reader up to six times its size again. A conforming writer
	// drops them from every name and topic.
	ExportControlMax = 65536
	exportVersion    = 1
)

var (
	contactColumns = []string{"root", "endpoint", "name", "display_name", "status", "was_active", "permissions", "their_permissions", "leaf", "root_cert", "added"}
	threadColumns  = []string{"id", "contact", "topic", "created_at", "last_at"}
	// threadColumnsNamed is threads.csv's header when it holds a removed thread: the two names a
	// former contact is known by travel on its conversation (SPEC §9.2, SEP-0004).
	threadColumnsNamed = append(append([]string{}, threadColumns...), "contact_name", "contact_display_name")
	contactStatuses    = []string{"active", "blocked", "pending_out"}
	exportPerms        = []string{"message.text", "message.media", "status.view", "calendar.availability", "calendar.book"}
	manifestMembers    = []string{"hdtp_export", "owner", "owner_name", "exported_at", "tool", "counts", "files"}
	manifestCounts     = []string{"contacts", "threads", "messages", "media"}
	manifestListed     = []string{"contacts.csv", "threads.csv", "messages.jsonl"}
	messageMembers     = []string{"id", "thread", "contact", "msg_id", "direction", "sender", "time", "body", "reply_to", "status", "attachments"}
	attachmentFields   = []string{"file", "filename", "mime", "size"}
	msgDirections      = []string{"in", "out"}
	msgSenders         = []string{"agent", "human"}
	msgStatuses        = []string{"delivered", "queued", "failed", "read"}
	pinFields          = []string{"endpoint", "leaf", "root_cert"}
)

// strSet is a set of strings. Every name the export's rules look up in a list the FILE sizes (the
// directory, the roots, the thread ids, the msg_ids, the media) is looked up in one of these, never
// by a scan: a scan per row made export_read quadratic in threads.csv's rows (16k threads: 12 s in
// the Wasm core), and a file within every bound pinned a host for minutes.
type strSet map[string]struct{}

func setOf(list []string) strSet {
	s := make(strSet, len(list))
	for _, x := range list {
		s[x] = struct{}{}
	}
	return s
}

func (s strSet) has(x string) bool { _, in := s[x]; return in }

func (s strSet) add(x string) { s[x] = struct{}{} }

// contains is for the short lists the rules name (statuses, members, permissions), never for one
// the file sizes: those are strSets.
func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func exportRefuse(why string) error { return errors.New(why) }

// asU64 is serde_json's as_u64: a non-negative integer, never a fraction or an exponent.
func asU64(v any) (uint64, bool) {
	switch x := v.(type) {
	case json.Number:
		n, err := strconv.ParseUint(x.String(), 10, 64)
		return n, err == nil
	case int:
		return uint64(x), x >= 0
	case int64:
		return uint64(x), x >= 0
	case uint64:
		return x, true
	}
	return 0, false
}

func isExportHash(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func sha256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func isBase64Text(s string) bool {
	if len(s) < 16 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '+' || c == '/' || c == '=') {
			return false
		}
	}
	return true
}

// Key material (SPEC §9.2: an importer MUST refuse anything "that decodes as a private key") is read
// LENIENTLY, on purpose, where every other reader here is strict: what a lenient decoder reads as a key
// is key material. This port read a base64 word with a spare bit set in its last character, and a
// PKCS #8 whose length is written in a longer form than it needs (`81 2e`), as no key; the cloud's copy
// of the check and OpenSSL read both as the key (CW-07, R38). So a word forgives its padding, either
// alphabet and its spare bits, and a length may take any definite form of up to four octets, as the
// core's export/mod.rs reads them. js/key-material.json is the list both ports' tests and the parity
// cases read. TO REVERSE (a reading the owner may change): looseRead back to derRead and looseB64 back
// to DecodeB64url, here and in the core.

// looseNode is a DER-shaped element read for detection.
type looseNode struct {
	tag     byte
	content []byte
	end     int
}

// looseRead reads a tag and a definite length in the short form or a long form of one to four octets,
// minimal or not.
func looseRead(b []byte, at int) (looseNode, bool) {
	if at+2 > len(b) {
		return looseNode{}, false
	}
	tag, first := b[at], int(b[at+1])
	length, start := first, at+2
	if first&0x80 != 0 {
		n := first & 0x7f
		if n == 0 || n > 4 || at+2+n > len(b) {
			return looseNode{}, false
		}
		length = 0
		for _, o := range b[at+2 : at+2+n] {
			length = length<<8 | int(o)
		}
		start = at + 2 + n
	}
	// Four octets wrap a 32-bit int negative: a length that is not one is no element.
	if length < 0 || length > len(b)-start {
		return looseNode{}, false
	}
	return looseNode{tag: tag, content: b[start : start+length], end: start + length}, true
}

func looseChildren(content []byte) ([]looseNode, bool) {
	var out []looseNode
	for at := 0; at < len(content); {
		c, ok := looseRead(content, at)
		if !ok {
			return nil, false
		}
		out = append(out, c)
		at = c.end
	}
	return out, true
}

// looseB64 decodes a word as base64 or base64url for detection: its padding, either alphabet and a last
// character with a spare bit set are forgiven, as a lenient decoder forgives them. RawURLEncoding
// without Strict() allows the spare bits; a word holds no \r or \n, which it would also skip.
func looseB64(w string) ([]byte, bool) {
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(strings.NewReplacer("+", "-", "/", "_").Replace(w), "="))
	return b, err == nil
}

// isPrivateKeyDER is PKCS #8 or SEC1 by shape, whatever the algorithm, read by looseRead.
func isPrivateKeyDER(b []byte) bool {
	node, ok := looseRead(b, 0)
	if !ok || node.tag != 0x30 || node.end != len(b) {
		return false
	}
	f, ok := looseChildren(node.content)
	if !ok {
		return false
	}
	version := func(n looseNode, allowed ...byte) bool {
		if n.tag != 0x02 || len(n.content) != 1 {
			return false
		}
		for _, a := range allowed {
			if n.content[0] == a {
				return true
			}
		}
		return false
	}
	pkcs8 := false
	if len(f) >= 3 && version(f[0], 0, 1) && f[1].tag == 0x30 && f[2].tag == 0x04 {
		alg, ok := looseChildren(f[1].content)
		pkcs8 = ok && len(alg) > 0 && alg[0].tag == 0x06
	}
	sec1 := len(f) >= 2 && len(f) <= 4 && version(f[0], 1) && f[1].tag == 0x04
	if sec1 {
		for k, n := range f[2:] {
			if !(n.tag == 0xa0+byte(k) || (k == 0 && n.tag == 0xa1)) {
				sec1 = false
			}
		}
	}
	return pkcs8 || sec1
}

func asciiSpace(r rune) bool { return r == ' ' || r == '\t' || r == '\n' || r == '\f' || r == '\r' }

// holdsPrivateKey is SPEC §9.2's key material: PEM armour naming a private key, or any word
// (split at ASCII whitespace) that decodes as base64 or base64url to a PKCS #8 or SEC1 key.
func holdsPrivateKey(text string) bool {
	if strings.Contains(text, "PRIVATE KEY-----") {
		return true
	}
	// Word by word, without a list of the words: a cell of a 16 MiB member is read once and kept.
	// A private key's DER begins with 0x30, which base64 of either alphabet writes as `M`, so only a
	// word that begins so is decoded.
	for start := 0; start < len(text); {
		for start < len(text) && asciiSpace(rune(text[start])) {
			start++
		}
		end := start
		for end < len(text) && !asciiSpace(rune(text[end])) {
			end++
		}
		if w := text[start:end]; len(w) > 0 && w[0] == 'M' && isBase64Text(w) {
			if der, ok := looseB64(w); ok && isPrivateKeyDER(der) {
				return true
			}
		}
		start = end
	}
	return false
}

// isExportPermission is a permission of §8: one of its names, or integration.<name>.
func isExportPermission(p string) bool {
	if contains(exportPerms, p) {
		return true
	}
	n, found := strings.CutPrefix(p, "integration.")
	if !found || n == "" || len(n) > 64 {
		return false
	}
	for i := 0; i < len(n); i++ {
		c := n[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

func exportPermissions(cell string) ([]any, string) {
	out := []any{}
	if cell == "" {
		return out, ""
	}
	seen := strSet{}
	for _, p := range strings.Split(cell, " ") {
		if p == "" {
			return nil, "not names separated by single spaces"
		}
		if !isExportPermission(p) {
			return nil, jsonString(p) + " is not a permission of §8"
		}
		if seen.has(p) {
			return nil, p + " twice"
		}
		seen.add(p)
		out = append(out, p)
	}
	return out, ""
}

func exportCertificate(cell string) (*Cert, string) {
	if cell == "" {
		return nil, ""
	}
	if !isB64url(cell) {
		return nil, "not base64url"
	}
	der, err := DecodeB64url(cell)
	if err != nil {
		return nil, "not base64url"
	}
	c, err := Parse(der)
	if err != nil {
		return nil, "not a certificate"
	}
	return c, ""
}

// cellRefusal is a column (or a message member) and why.
type cellRefusal struct {
	col int
	why string
}

// contactRow checks one contact row's cells, in column order. pinAt decides the leaf: kept only
// when [leaf, root_cert] validates at the row's endpoint at that instant, null otherwise; nil keeps
// it as written.
func contactRow(cells []string, owner string, pinAt *time.Time) (map[string]any, *cellRefusal) {
	for k, c := range cells {
		if holdsPrivateKey(c) {
			return nil, &cellRefusal{k, "holds a private key"}
		}
	}
	if len(cells) != 11 {
		return nil, &cellRefusal{0, fmt.Sprintf("%d fields, not 11", len(cells))}
	}
	root, endpoint, name, display, status, was, perms, theirs, leaf, rootCert, added := cells[0], cells[1], cells[2], cells[3], cells[4], cells[5], cells[6], cells[7], cells[8], cells[9], cells[10]
	if !IsFingerprint(root) {
		return nil, &cellRefusal{0, "not a fingerprint"}
	}
	if root == owner {
		return nil, &cellRefusal{0, "the owner's own root"}
	}
	if !IsNormalHTTPS(endpoint) {
		return nil, &cellRefusal{1, "not an https URL in normal form"}
	}
	if ok, why := AddressGuard(endpoint, "", false); !ok {
		return nil, &cellRefusal{1, why}
	}
	for _, kv := range []struct {
		k int
		v string
	}{{2, name}, {3, display}} {
		if utf8.RuneCountInString(kv.v) > ExportNameMax {
			return nil, &cellRefusal{kv.k, fmt.Sprintf("over %d characters", ExportNameMax)}
		}
	}
	if !contains(contactStatuses, status) {
		return nil, &cellRefusal{4, "not active, blocked or pending_out"}
	}
	var wasActive bool
	switch was {
	case "true":
		wasActive = true
	case "false":
	default:
		return nil, &cellRefusal{5, "not true or false"}
	}
	granted, why := exportPermissions(perms)
	if why != "" {
		return nil, &cellRefusal{6, why}
	}
	told, why := exportPermissions(theirs)
	if why != "" {
		return nil, &cellRefusal{7, why}
	}
	leafCert, why := exportCertificate(leaf)
	if why != "" {
		return nil, &cellRefusal{8, why}
	}
	if leafCert != nil && ProfileError(leafCert, "leaf") != "" {
		return nil, &cellRefusal{8, "not a leaf of §14.1's profile"}
	}
	rootParsed, why := exportCertificate(rootCert)
	if why != "" {
		return nil, &cellRefusal{9, why}
	}
	if rootParsed != nil {
		if ProfileError(rootParsed, "root") != "" {
			return nil, &cellRefusal{9, "not a root of §14.1's profile"}
		}
		if FingerprintOf(rootParsed) != root {
			return nil, &cellRefusal{9, "not the certificate of this row's root"}
		}
	}
	addedAt, ok := parseInstantZ(added)
	if !ok {
		return nil, &cellRefusal{10, "not an RFC 3339 instant"}
	}
	var pinned any
	switch {
	case pinAt == nil && leafCert != nil:
		pinned = leaf
	case pinAt != nil && leafCert != nil && rootParsed != nil:
		if ValidateChain([][]byte{leafCert.DER, rootParsed.DER}, ChainOpts{Now: *pinAt, ExpectedRoot: root, ExpectedEndpoint: endpoint}).OK {
			pinned = leaf
		}
	}
	var rc any
	if rootParsed != nil {
		rc = rootCert
	}
	return map[string]any{
		"root": root, "endpoint": endpoint, "name": name, "display_name": display, "status": status,
		"was_active": wasActive, "permissions": granted, "their_permissions": told,
		"leaf": pinned, "root_cert": rc, "added": timeOut(addedAt),
	}, nil
}

// threadRow checks one thread row's cells against the contacts' roots: the row, its cells shared
// with the member's text. named is the longer header: a thread whose contact is no root of
// contacts.csv is then a removed thread, a former contact's conversation, which carries the names it
// is known by; any other thread's two names are empty. owner is the export's.
func threadRow(cells []string, roots strSet, named bool, owner string) (ThreadRow, *cellRefusal) {
	for k, c := range cells {
		if holdsPrivateKey(c) {
			return ThreadRow{}, &cellRefusal{k, "holds a private key"}
		}
	}
	want := len(threadColumns)
	if named {
		want = len(threadColumnsNamed)
	}
	if len(cells) != want {
		return ThreadRow{}, &cellRefusal{0, fmt.Sprintf("%d fields, not %d", len(cells), want)}
	}
	if cells[0] == "" {
		return ThreadRow{}, &cellRefusal{0, "empty"}
	}
	var contactName, contactDisplay string
	removed := false
	switch {
	case !named && !roots.has(cells[1]):
		return ThreadRow{}, &cellRefusal{1, "names no contact in contacts.csv"}
	case named && roots.has(cells[1]):
		for k := 5; k <= 6; k++ {
			if cells[k] != "" {
				return ThreadRow{}, &cellRefusal{k, "not empty, and the contact is in contacts.csv"}
			}
		}
	case named:
		switch {
		case !IsFingerprint(cells[1]):
			return ThreadRow{}, &cellRefusal{1, "not a fingerprint"}
		case cells[1] == owner:
			return ThreadRow{}, &cellRefusal{1, "the owner's own root"}
		}
		for k := 5; k <= 6; k++ {
			if utf8.RuneCountInString(cells[k]) > ExportNameMax {
				return ThreadRow{}, &cellRefusal{k, fmt.Sprintf("over %d characters", ExportNameMax)}
			}
		}
		contactName, contactDisplay = cells[5], cells[6]
		removed = true
	}
	var times [2]string
	for j, k := range []int{3, 4} {
		t, ok := parseInstantZ(cells[k])
		if !ok {
			return ThreadRow{}, &cellRefusal{k, "not an RFC 3339 instant"}
		}
		times[j] = instantOut(cells[k], t)
	}
	return ThreadRow{ID: cells[0], Contact: cells[1], Topic: cells[2], CreatedAt: times[0], LastAt: times[1],
		ContactName: contactName, ContactDisplayName: contactDisplay, removed: removed}, nil
}

// removedAt is a removed thread as the reader passes it: its place among the rows read and its row
// number. Eight bytes a row, the names held by the row itself, so a file whose every thread is
// removed costs no copy of any name (export_memory_test.go holds it for a file whose every thread has
// a root of its own, and for one whose every thread shares one root).
type removedAt struct{ idx, n int32 }

// firstNamesDiffer is the earliest removed thread whose names are not those of the earliest removed
// thread of its root, and the column that differs, among `at`: the refusal reading them in order
// would give (SPEC §9.2: one former contact, one pair of names). It sorts a copy, by root and row.
func firstNamesDiffer(threads []ThreadRow, at []removedAt) (n, col int, found bool) {
	sorted := append([]removedAt(nil), at...)
	sort.Slice(sorted, func(i, j int) bool {
		a, b := threads[sorted[i].idx].Contact, threads[sorted[j].idx].Contact
		if a != b {
			return a < b
		}
		return sorted[i].n < sorted[j].n
	})
	for i, first := 0, 0; i < len(sorted); i++ {
		t, base := threads[sorted[i].idx], threads[sorted[first].idx]
		if t.Contact != base.Contact {
			first = i
			continue
		}
		c := 0
		switch {
		case t.ContactName != base.ContactName:
			c = 5
		case t.ContactDisplayName != base.ContactDisplayName:
			c = 6
		}
		if c != 0 && (!found || int(sorted[i].n) < n) {
			n, col, found = int(sorted[i].n), c, true
		}
	}
	return n, col, found
}

// escapedControl is a character below U+0020 but tab, line feed and carriage return: one a JSON
// answer writes as two bytes (U+0008, U+000C) or six (the rest).
func escapedControl(b byte) bool { return b < 0x20 && b != '\t' && b != '\n' && b != '\r' }

// controlCeiling refuses a member holding more of them than ExportControlMax, naming the ceiling,
// and answers how many bytes more than the member its text becomes as JSON strings: one for each
// U+0008, U+000C, tab, line feed, carriage return and backslash, five for each other character below
// U+0020 (a quote is written as two bytes in either).
func controlCeiling(member, text string) (int, error) {
	n, more := 0, 0
	for i := 0; i < len(text); i++ {
		switch c := text[i]; {
		case c == '\b' || c == '\f':
			n++
			more++
		case c == '\t' || c == '\n' || c == '\r' || c == '\\':
			more++
		case escapedControl(c):
			n++
			more += 5
		}
	}
	if n > ExportControlMax {
		return 0, exportRefuse(fmt.Sprintf("%s: %d characters below U+0020 but tab, line feed and carriage return, over the %d this library takes in one member", member, n, ExportControlMax))
	}
	return more, nil
}

// dropControl is s without them: what a writer does to what a contact controls (SPEC §9.2).
func dropControl(s string) string {
	if strings.IndexFunc(s, func(r rune) bool { return r < 0x20 && escapedControl(byte(r)) }) < 0 {
		return s
	}
	return strings.Map(func(r rune) rune {
		if r < 0x20 && escapedControl(byte(r)) {
			return -1
		}
		return r
	}, s)
}

// threadsHeaderRefusal is the refusal of a threads.csv header that is neither of SPEC §9.2's two.
const threadsHeaderRefusal = "threads.csv: row 1: the header is not id,contact,topic,created_at,last_at, nor that and contact_name,contact_display_name"

// threadsHeader is the header a threads.csv's first record names: the longer one when it is exactly
// that, and the shorter one otherwise (csvTable refuses anything else, naming it).
func threadsHeader(text string) []string {
	named := false
	csvEach(text, func(n int, fields []string) bool {
		named = strings.Join(fields, "\x00") == strings.Join(threadColumnsNamed, "\x00")
		return false
	})
	if named {
		return threadColumnsNamed
	}
	return threadColumns
}

// removedNames holds every removed thread of one root to the names its first gives (SPEC §9.2: one
// former contact, one pair of names): the row and column of the first that differs, or 0.
type removedNames map[string][2]string

func (r removedNames) differs(t ThreadRow) int {
	got := [2]string{t.ContactName, t.ContactDisplayName}
	first, seen := r[t.Contact]
	switch {
	case !seen:
		r[t.Contact] = got
	case first[0] != got[0]:
		return 5
	case first[1] != got[1]:
		return 6
	}
	return 0
}

// instantOut is an instant as an answer writes it: the cell itself when it is already written that
// way (no copy), else written again.
func instantOut(cell string, t time.Time) string {
	var buf [32]byte
	if w := t.UTC().AppendFormat(buf[:0], time.RFC3339); string(w) == cell {
		return cell
	}
	return timeOut(t)
}

type tableRow struct {
	n     int
	cells []string
}

// csvTable checks a CSV member whole (every record reads, and the header is `columns`) and then
// hands fn its data records one at a time, each with its row number (the header is row 1), one
// leading ' stripped from every cell. Two passes over the text and never a copy of it: the first
// refuses what the second would otherwise find partway, so a syntax fault anywhere is still the
// first thing named. count is the data records'.
func csvTable(member, text string, columns []string, count *int, fn func(r tableRow) error) error {
	header, rows := false, 0
	bad := csvEach(text, func(n int, fields []string) bool {
		if n == 1 {
			header = strings.Join(fields, "\x00") == strings.Join(columns, "\x00") && len(fields) == len(columns)
		} else {
			rows++
		}
		return true
	})
	if bad != nil {
		return exportRefuse(fmt.Sprintf("%s: row %d: %s", member, bad.record, bad.why))
	}
	if !header {
		return exportRefuse(fmt.Sprintf("%s: row 1: the header is not %s", member, strings.Join(columns, ",")))
	}
	if count != nil {
		*count = rows
		if fn == nil {
			return nil
		}
	}
	var err error
	csvEach(text, func(n int, fields []string) bool {
		if n == 1 {
			return true
		}
		for k, c := range fields {
			fields[k] = csvUnguard(c)
		}
		err = fn(tableRow{n, fields})
		return err == nil
	})
	return err
}

// ── the manifest ────────────────────────────────────────────────────────────────────────────────

type exportManifest struct {
	contacts, threads, messages, media uint64
	files                              map[string]string
}

// orderedKeys is an object's member names in document order, a repeated name at its first place —
// the order serde_json's preserve_order map iterates in, which the Rust core reads `files` in.
func orderedKeys(raw json.RawMessage) []string {
	d := json.NewDecoder(bytes.NewReader(raw))
	if t, err := d.Token(); err != nil || t != json.Delim('{') {
		return nil
	}
	var keys []string
	have := strSet{}
	for d.More() {
		t, err := d.Token()
		if err != nil {
			return keys
		}
		k, _ := t.(string)
		if !have.has(k) {
			have.add(k)
			keys = append(keys, k)
		}
		var skip json.RawMessage
		if d.Decode(&skip) != nil {
			return keys
		}
	}
	return keys
}

func filesOrder(raw []byte) []string {
	var top map[string]json.RawMessage
	if json.Unmarshal(raw, &top) != nil {
		return nil
	}
	return orderedKeys(top["files"])
}

func manifestAt(why string) error { return exportRefuse("manifest.json: " + why) }

// checkManifest holds a manifest's members to §9.2, and its owner to *owner when owner is not nil —
// the core's `Option`: nil is no owner to compare (a manifest this process is finishing or has
// finished), and an owner that is given is compared whatever it is, "" included. "" meant "no owner"
// here, so export_read with an owner of "" read another identity's file, which the core refuses.
// order is the document order of `files`.
func checkManifest(doc map[string]any, order []string, owner *string) (*exportManifest, error) {
	if k := stranger(doc, manifestMembers); k != "" {
		return nil, manifestAt(jsonString(k) + " is not a member of a manifest")
	}
	for _, m := range manifestMembers {
		if _, has := doc[m]; !has {
			return nil, manifestAt(m + " is missing")
		}
	}
	if v, ok := asU64(doc["hdtp_export"]); !ok || v != exportVersion {
		return nil, manifestAt("hdtp_export is 1")
	}
	fileOwner, isText := doc["owner"].(string)
	if !isText || !IsFingerprint(fileOwner) {
		return nil, manifestAt("owner is not a fingerprint")
	}
	if owner != nil && *owner != fileOwner {
		return nil, manifestAt(fmt.Sprintf("owner: the file is %s's, not this identity's (%s)", fileOwner, *owner))
	}
	for _, m := range []string{"owner_name", "tool"} {
		text, isText := doc[m].(string)
		if !isText {
			return nil, manifestAt(m + " is a string")
		}
		// SPEC §9.2, key material: every string member of the manifest, as every cell.
		if holdsPrivateKey(text) {
			return nil, manifestAt(m + " holds a private key")
		}
	}
	if at, isText := doc["exported_at"].(string); !isText {
		return nil, manifestAt("exported_at is not an RFC 3339 instant")
	} else if _, ok := parseInstantZ(at); !ok {
		return nil, manifestAt("exported_at is not an RFC 3339 instant")
	}
	counts, isObj := doc["counts"].(map[string]any)
	if !isObj {
		return nil, manifestAt("counts is an object")
	}
	if k := stranger(counts, manifestCounts); k != "" {
		return nil, manifestAt("counts: " + jsonString(k) + " is not a count of a manifest")
	}
	var n [4]uint64
	for i, k := range manifestCounts {
		v, ok := asU64(counts[k])
		if !ok {
			return nil, manifestAt("counts: " + k + " is not a whole number")
		}
		n[i] = v
	}
	listed, isObj := doc["files"].(map[string]any)
	if !isObj {
		return nil, manifestAt("files is an object")
	}
	// Document order, as the core reads it; a name order does not know comes after, sorted.
	names := append([]string{}, order...)
	ordered := setOf(order)
	var rest []string
	for k := range listed {
		if !ordered.has(k) {
			rest = append(rest, k)
		}
	}
	sort.Strings(rest)
	names = append(names, rest...)
	files := map[string]string{}
	for _, name := range names {
		v, has := listed[name]
		if !has {
			continue
		}
		// SPEC 9.2#11: files lists the text members only; a media member is bound by its
		// name, the sha256 of its bytes, and counted by counts.media.
		if !contains(manifestListed, name) {
			return nil, manifestAt("files: " + jsonString(name) + " is not a member an export lists")
		}
		hash, isText := v.(string)
		if !isText || !isExportHash(hash) {
			return nil, manifestAt("files: " + name + ": not a lowercase hex sha256")
		}
		files[name] = hash
	}
	return &exportManifest{contacts: n[0], threads: n[1], messages: n[2], media: n[3], files: files}, nil
}

// loneSurrogate reports a \u escape of a UTF-16 surrogate that is not half of a pair. serde_json
// refuses such JSON; encoding/json reads it as U+FFFD, so without this the two ports answered one
// manifest or message line two ways. An escaped backslash before a `u` is text, not an escape.
func loneSurrogate(text []byte) bool {
	hex4 := func(i int) (int, bool) {
		if i+4 > len(text) {
			return 0, false
		}
		n, err := strconv.ParseUint(string(text[i:i+4]), 16, 16)
		return int(n), err == nil
	}
	for i := 0; i < len(text); i++ {
		if text[i] != '\\' || i+1 >= len(text) {
			continue
		}
		if text[i+1] != 'u' {
			i++ // the escaped character, whatever it is, is not the start of another escape
			continue
		}
		u, ok := hex4(i + 2)
		switch {
		case !ok:
		case u >= 0xdc00 && u <= 0xdfff:
			return true
		case u >= 0xd800 && u <= 0xdbff:
			low, ok := 0, false
			if i+7 < len(text) && text[i+6] == '\\' && text[i+7] == 'u' {
				low, ok = hex4(i + 8)
			}
			if !ok || low < 0xdc00 || low > 0xdfff {
				return true
			}
			i += 6
		}
		i += 5
	}
	return false
}

func parseManifest(text string, owner *string) (*exportManifest, error) {
	if len(text) > ExportManifestMax {
		return nil, manifestAt(fmt.Sprintf("over %d bytes", ExportManifestMax))
	}
	v, err := decodeJSON([]byte(text))
	doc, isObj := v.(map[string]any)
	if err != nil || !isObj || loneSurrogate([]byte(text)) {
		return nil, manifestAt("not a JSON object")
	}
	return checkManifest(doc, filesOrder([]byte(text)), owner)
}

// finishManifest is the finished manifest, from export_write's partial one (raw, as the caller sent
// it) and what the host counted and hashed while it streamed messages.jsonl.
func finishManifest(raw json.RawMessage, messagesSHA *string, messages uint64) (string, error) {
	v, err := decodeJSON(raw)
	doc, isObj := v.(map[string]any)
	if err != nil || !isObj {
		return "", exportRefuse("partial is required")
	}
	before, err := checkManifest(doc, filesOrder(raw), nil)
	if err != nil {
		return "", err
	}
	if _, has := before.files["messages.jsonl"]; before.messages != 0 || has {
		return "", exportRefuse("partial: the messages are counted and hashed here, not before")
	}
	switch {
	case messagesSHA != nil && isExportHash(*messagesSHA):
		doc["files"].(map[string]any)["messages.jsonl"] = *messagesSHA
	case messagesSHA != nil:
		return "", exportRefuse("hashes: messages.jsonl: not a lowercase hex sha256")
	case messages > 0:
		return "", exportRefuse("hashes: messages.jsonl is required when there are messages")
	}
	doc["counts"].(map[string]any)["messages"] = json.Number(strconv.FormatUint(messages, 10))
	text := string(Canonical(doc))
	if _, err := parseManifest(text, nil); err != nil {
		return "", err
	}
	return text, nil
}

// ── the directory, contacts.csv, threads.csv ────────────────────────────────────────────────────

// ExportEntry is one entry of a zip's central directory, as the host read it.
type ExportEntry struct {
	Name      string `json:"name"`
	Size      uint64 `json:"size"`
	Encrypted bool   `json:"encrypted"`
	Mode      uint32 `json:"mode"`
}

func isExportMedia(name string) bool {
	h, found := strings.CutPrefix(name, "media/")
	return found && isExportHash(h)
}

func allowedExportName(name string) bool {
	switch name {
	case "manifest.json", "contacts.csv", "threads.csv", "messages.jsonl", "media/":
		return true
	}
	return isExportMedia(name)
}

func memberLimit(name string) int {
	switch {
	case name == "manifest.json":
		return ExportManifestMax
	case name == "contacts.csv":
		return ExportContactsMax
	case name == "threads.csv":
		return ExportThreadsMax
	case strings.HasPrefix(name, "media/") && len(name) > 6:
		return ExportMediaMax
	}
	return -1
}

type exportReadResult struct {
	// threadsEscapes is how many bytes more than threads.csv its text becomes in the answer.
	threadsEscapes int
	contacts       []any
	threads        []ThreadRow
	media          []ExportMedia
}

// exportRead is §9.2's validation of everything but the messages and the media bytes, in the core's
// order.
func exportRead(directory []ExportEntry, manifestText, contactsCSV, threadsCSV *string, owner string, now time.Time) (*exportReadResult, error) {
	seen := strSet{}
	for _, e := range directory {
		label := "entry " + jsonString(e.Name)
		if !allowedExportName(e.Name) {
			return nil, exportRefuse(label + ": not a name an export holds")
		}
		if seen.has(e.Name) {
			return nil, exportRefuse(label + ": appears twice")
		}
		seen.add(e.Name)
		if e.Encrypted {
			return nil, exportRefuse(label + ": encrypted")
		}
		if e.Mode&0o170000 == 0o120000 {
			return nil, exportRefuse(label + ": a symbolic link")
		}
		if e.Mode&0o170000 == 0o040000 && e.Name != "media/" {
			return nil, exportRefuse(label + ": a directory")
		}
		if limit := memberLimit(e.Name); limit >= 0 && e.Size > uint64(limit) {
			return nil, exportRefuse(fmt.Sprintf("%s: %d bytes, over the %d an export allows", label, e.Size, limit))
		}
	}
	has := seen.has
	for _, required := range []string{"manifest.json", "contacts.csv"} {
		if !has(required) {
			return nil, exportRefuse(required + ": the file lacks it")
		}
	}
	if manifestText == nil {
		return nil, exportRefuse("manifest is required")
	}
	m, err := parseManifest(*manifestText, &owner)
	if err != nil {
		return nil, err
	}
	for _, e := range directory {
		if e.Name == "manifest.json" || e.Name == "media/" || isExportMedia(e.Name) {
			continue
		}
		if _, listed := m.files[e.Name]; !listed {
			return nil, exportRefuse(e.Name + ": manifest.json's files does not list it")
		}
	}
	listedNames := make([]string, 0, len(m.files))
	for k := range m.files {
		listedNames = append(listedNames, k)
	}
	sort.Strings(listedNames)
	for _, name := range listedNames {
		if !has(name) {
			return nil, exportRefuse(name + ": manifest.json's files lists it, and the file lacks it")
		}
	}
	for _, mc := range []struct {
		member string
		count  uint64
	}{{"threads.csv", m.threads}, {"messages.jsonl", m.messages}, {"media/", m.media}} {
		if mc.count > 0 && !has(mc.member) {
			return nil, exportRefuse(mc.member + ": the file lacks it")
		}
	}
	media := []ExportMedia{}
	for _, e := range directory {
		if isExportMedia(e.Name) {
			media = append(media, ExportMedia{Hash: e.Name[6:], Size: int64(e.Size)})
		}
	}
	sort.Slice(media, func(i, j int) bool {
		if media[i].Hash != media[j].Hash {
			return media[i].Hash < media[j].Hash
		}
		return media[i].Size < media[j].Size
	})
	if uint64(len(media)) != m.media {
		return nil, exportRefuse(fmt.Sprintf("manifest.json: counts: media is %d, and the file holds %d", m.media, len(media)))
	}

	if contactsCSV == nil {
		return nil, exportRefuse("contacts_csv is required")
	}
	if len(*contactsCSV) > ExportContactsMax {
		return nil, exportRefuse(fmt.Sprintf("contacts.csv: over %d bytes", ExportContactsMax))
	}
	if sha256Hex([]byte(*contactsCSV)) != m.files["contacts.csv"] {
		return nil, exportRefuse("contacts.csv: its sha256 is not manifest.json's")
	}
	if _, err := controlCeiling("contacts.csv", *contactsCSV); err != nil {
		return nil, err
	}
	var count int
	if err := csvTable("contacts.csv", *contactsCSV, contactColumns, &count, nil); err != nil {
		return nil, err
	}
	if count > ExportContactsRowMax {
		return nil, exportRefuse(fmt.Sprintf("contacts.csv: over %d rows", ExportContactsRowMax))
	}
	contacts := make([]any, 0, count)
	roots := strSet{}
	err = csvTable("contacts.csv", *contactsCSV, contactColumns, nil, func(r tableRow) error {
		if len(r.cells) != len(contactColumns) {
			return exportRefuse(fmt.Sprintf("contacts.csv: row %d: %d fields, not %d", r.n, len(r.cells), len(contactColumns)))
		}
		row, bad := contactRow(r.cells, owner, &now)
		if bad != nil {
			return exportRefuse(fmt.Sprintf("contacts.csv: row %d, column %s: %s", r.n, contactColumns[bad.col], bad.why))
		}
		if roots.has(row["root"].(string)) {
			return exportRefuse(fmt.Sprintf("contacts.csv: row %d, column root: appears twice", r.n))
		}
		roots.add(row["root"].(string))
		contacts = append(contacts, row)
		return nil
	})
	if err != nil {
		return nil, err
	}
	if uint64(len(contacts)) != m.contacts {
		return nil, exportRefuse(fmt.Sprintf("manifest.json: counts: contacts is %d, and contacts.csv holds %d", m.contacts, len(contacts)))
	}

	var threads []ThreadRow
	escapes := 0
	if has("threads.csv") {
		if threadsCSV == nil {
			return nil, exportRefuse("threads_csv is required: the file has threads.csv")
		}
		if len(*threadsCSV) > ExportThreadsMax {
			return nil, exportRefuse(fmt.Sprintf("threads.csv: over %d bytes", ExportThreadsMax))
		}
		if sha256Hex([]byte(*threadsCSV)) != m.files["threads.csv"] {
			return nil, exportRefuse("threads.csv: its sha256 is not manifest.json's")
		}
		if escapes, err = controlCeiling("threads.csv", *threadsCSV); err != nil {
			return nil, err
		}
		columns := threadsHeader(*threadsCSV)
		named := len(columns) == len(threadColumnsNamed)
		if err := csvTable("threads.csv", *threadsCSV, columns, &count, nil); err != nil {
			// A header that is neither of the two is refused naming both.
			if err.Error() == "threads.csv: row 1: the header is not "+strings.Join(threadColumns, ",") {
				return nil, exportRefuse(threadsHeaderRefusal)
			}
			return nil, err
		}
		threads = make([]ThreadRow, 0, count)
		// The ids seen: the rows' own id strings, which share the member's text — no copy of any.
		ids := make(strSet, count)
		// The removed threads, checked for their names when the rows end or one is refused: the
		// earliest refusal of either kind is the one named, as reading them in order names it.
		var removed []removedAt
		namesRefusal := func() error {
			if n, col, found := firstNamesDiffer(threads, removed); found {
				return exportRefuse(fmt.Sprintf("threads.csv: row %d, column %s: not what an earlier removed thread of this contact says", n, columns[col]))
			}
			return nil
		}
		refuse := func(why string) error {
			if err := namesRefusal(); err != nil {
				return err
			}
			return exportRefuse(why)
		}
		err = csvTable("threads.csv", *threadsCSV, columns, nil, func(r tableRow) error {
			if len(r.cells) != len(columns) {
				return refuse(fmt.Sprintf("threads.csv: row %d: %d fields, not %d", r.n, len(r.cells), len(columns)))
			}
			row, bad := threadRow(r.cells, roots, named, owner)
			if bad != nil {
				return refuse(fmt.Sprintf("threads.csv: row %d, column %s: %s", r.n, columns[bad.col], bad.why))
			}
			if ids.has(row.ID) {
				return refuse(fmt.Sprintf("threads.csv: row %d, column id: appears twice", r.n))
			}
			if row.removed {
				removed = append(removed, removedAt{int32(len(threads)), int32(r.n)})
			}
			ids.add(row.ID)
			threads = append(threads, row)
			return nil
		})
		if err != nil {
			return nil, err
		}
		if err := namesRefusal(); err != nil {
			return nil, err
		}
		// The longer header only for a file that holds a removed thread: one form for one content.
		if named && len(removed) == 0 {
			return nil, exportRefuse("threads.csv: row 1: the header names contact_name and contact_display_name, and no thread is a removed thread")
		}
		if uint64(len(threads)) != m.threads {
			return nil, exportRefuse(fmt.Sprintf("manifest.json: counts: threads is %d, and threads.csv holds %d", m.threads, len(threads)))
		}
	} else if threadsCSV != nil {
		return nil, exportRefuse("threads_csv is given, and the file has no threads.csv")
	}
	return &exportReadResult{threadsEscapes: escapes, contacts: contacts, threads: threads, media: media}, nil
}

// exportEnd is what the host gathered while it streamed messages.jsonl.
type exportEnd struct {
	messagesSHA256                   *string
	lines                            uint64
	ids, msgIDs, replyTos, mediaSeen []string
	// media is the file's media members, by hash: export_read's media. Each must be named.
	media []string
}

// exportReadEnd is §9.2's cross-batch rules, once the host has streamed messages.jsonl.
func exportReadEnd(manifestText string, e exportEnd) error {
	m, err := parseManifest(manifestText, nil)
	if err != nil {
		return err
	}
	if e.lines != m.messages {
		return exportRefuse(fmt.Sprintf("manifest.json: counts: messages is %d, and messages.jsonl holds %d lines", m.messages, e.lines))
	}
	want, listed := m.files["messages.jsonl"]
	switch {
	case listed && e.messagesSHA256 != nil && want == *e.messagesSHA256:
	case listed:
		return exportRefuse("messages.jsonl: its sha256 is not manifest.json's")
	case e.messagesSHA256 != nil:
		return exportRefuse("messages.jsonl: manifest.json's files does not list it")
	}
	sorted := append([]string{}, e.ids...)
	sort.Strings(sorted)
	for i := 1; i < len(sorted); i++ {
		if sorted[i] == sorted[i-1] {
			return exportRefuse("messages.jsonl: id " + jsonString(sorted[i]) + " appears twice")
		}
	}
	// The msg_ids sorted, looked up by binary search: a list of the strings already held, 16 bytes
	// each, where a set of them cost some 50.
	msgIDs := append([]string{}, e.msgIDs...)
	sort.Strings(msgIDs)
	for _, r := range e.replyTos {
		if i := sort.SearchStrings(msgIDs, r); i == len(msgIDs) || msgIDs[i] != r {
			return exportRefuse("messages.jsonl: reply_to " + jsonString(r) + " names no message in the file")
		}
	}
	mediaSeen := setOf(e.mediaSeen)
	for _, h := range e.media {
		if !mediaSeen.has(h) {
			return exportRefuse("media/" + h + ": nothing names it")
		}
	}
	return nil
}

// ── messages.jsonl ──────────────────────────────────────────────────────────────────────────────

// messageNames is what a message may name, as sets built once per call.
type messageNames struct{ threads, contacts, media strSet }

type memberRefusal struct {
	member string // "" for the message as a whole
	why    string
}

func keyMaterial(v any) bool {
	switch x := v.(type) {
	case string:
		return holdsPrivateKey(x)
	case []any:
		for _, i := range x {
			if keyMaterial(i) {
				return true
			}
		}
	case map[string]any:
		for _, i := range x {
			if keyMaterial(i) {
				return true
			}
		}
	}
	return false
}

// checkMessage holds one message's members to §9.2; names nil skips the references.
func checkMessage(doc map[string]any, names *messageNames) (map[string]any, *memberRefusal) {
	if k := stranger(doc, messageMembers); k != "" {
		return nil, &memberRefusal{"", jsonString(k) + " is not a member of a message"}
	}
	for _, m := range messageMembers {
		if _, has := doc[m]; !has {
			return nil, &memberRefusal{"", m + " is missing"}
		}
	}
	for _, m := range messageMembers {
		if keyMaterial(doc[m]) {
			return nil, &memberRefusal{m, "holds a private key"}
		}
	}
	text := func(m string) (string, *memberRefusal) {
		s, isText := doc[m].(string)
		if !isText {
			return "", &memberRefusal{m, "not a string"}
		}
		return s, nil
	}
	oneOf := func(m string, allowed []string) *memberRefusal {
		s, bad := text(m)
		if bad != nil {
			return bad
		}
		if !contains(allowed, s) {
			return &memberRefusal{m, "not " + strings.Join(allowed, " or ")}
		}
		return nil
	}
	for _, m := range []string{"id", "msg_id"} {
		s, bad := text(m)
		if bad != nil {
			return nil, bad
		}
		if s == "" {
			return nil, &memberRefusal{m, "empty"}
		}
	}
	thread, bad := text("thread")
	if bad != nil {
		return nil, bad
	}
	contact, bad := text("contact")
	if bad != nil {
		return nil, bad
	}
	if names != nil {
		if !names.threads.has(thread) {
			return nil, &memberRefusal{"thread", "names no thread in threads.csv"}
		}
		if !names.contacts.has(contact) {
			return nil, &memberRefusal{"contact", "names no contact in contacts.csv and no removed thread"}
		}
	}
	if bad := oneOf("direction", msgDirections); bad != nil {
		return nil, bad
	}
	if bad := oneOf("sender", msgSenders); bad != nil {
		return nil, bad
	}
	ts, bad := text("time")
	if bad != nil {
		return nil, bad
	}
	at, ok := parseInstantZ(ts)
	if !ok {
		return nil, &memberRefusal{"time", "not an RFC 3339 instant"}
	}
	body, bad := text("body")
	if bad != nil {
		return nil, bad
	}
	if len(body) > ExportBodyMax {
		return nil, &memberRefusal{"body", fmt.Sprintf("over %d bytes", ExportBodyMax)}
	}
	switch r := doc["reply_to"].(type) {
	case nil:
	case string:
		if r == "" {
			return nil, &memberRefusal{"reply_to", "not a msg_id or null"}
		}
	default:
		return nil, &memberRefusal{"reply_to", "not a msg_id or null"}
	}
	if bad := oneOf("status", msgStatuses); bad != nil {
		return nil, bad
	}
	attachments, isList := doc["attachments"].([]any)
	if !isList {
		return nil, &memberRefusal{"attachments", "not a list"}
	}
	if len(attachments) > ExportAttachmentsMax {
		return nil, &memberRefusal{"attachments", "more than one attachment: a message carries at most one file"}
	}
	kept := []any{}
	for _, a := range attachments {
		refuse := func(why string) (map[string]any, *memberRefusal) { return nil, &memberRefusal{"attachments", why} }
		o, isObj := a.(map[string]any)
		if !isObj {
			return refuse("an attachment is an object")
		}
		if k := stranger(o, attachmentFields); k != "" {
			return refuse(jsonString(k) + " is not a member of an attachment")
		}
		for _, m := range attachmentFields {
			if _, has := o[m]; !has {
				return refuse(m + " is missing")
			}
		}
		file, isText := o["file"].(string)
		if !isText || !isExportHash(file) {
			return refuse("file is not a lowercase hex sha256")
		}
		if names != nil && !names.media.has(file) {
			return refuse("file names no media member")
		}
		_, fn := o["filename"].(string)
		_, mt := o["mime"].(string)
		if !fn || !mt {
			return refuse("filename and mime are strings")
		}
		size, ok := asU64(o["size"])
		if !ok || size > ExportMediaMax {
			return refuse(fmt.Sprintf("size is a number of bytes up to %d", ExportMediaMax))
		}
		kept = append(kept, map[string]any{"file": file, "filename": o["filename"], "mime": o["mime"], "size": int64(size)})
	}
	// A message carries a file or text, never both: neither host's send_media carries a caption.
	if len(kept) > 0 && body != "" {
		return nil, &memberRefusal{"body", "not empty, and the message carries a file: a message with an attachment has no text"}
	}
	return map[string]any{
		"id": doc["id"], "thread": thread, "contact": contact, "msg_id": doc["msg_id"], "direction": doc["direction"],
		"sender": doc["sender"], "time": timeOut(at), "body": body, "reply_to": doc["reply_to"],
		"status": doc["status"], "attachments": kept,
	}, nil
}

// exportReadMessages reads one batch of lines; firstLine is the number of the first in the file.
func exportReadMessages(lines []string, firstLine uint64, names messageNames) ([]any, []string, error) {
	messages := []any{}
	seen := []string{}
	seenSet := strSet{}
	for i, line := range lines {
		n := firstLine + uint64(i)
		if len(line) > ExportLineMax {
			return nil, nil, exportRefuse(fmt.Sprintf("messages.jsonl: line %d: over %d bytes", n, ExportLineMax))
		}
		v, err := decodeJSON([]byte(line))
		doc, isObj := v.(map[string]any)
		if err != nil || !isObj || loneSurrogate([]byte(line)) {
			return nil, nil, exportRefuse(fmt.Sprintf("messages.jsonl: line %d: not a JSON object", n))
		}
		m, bad := checkMessage(doc, &names)
		if bad != nil {
			if bad.member != "" {
				return nil, nil, exportRefuse(fmt.Sprintf("messages.jsonl: line %d, member %s: %s", n, bad.member, bad.why))
			}
			return nil, nil, exportRefuse(fmt.Sprintf("messages.jsonl: line %d: %s", n, bad.why))
		}
		for _, a := range m["attachments"].([]any) {
			f := a.(map[string]any)["file"].(string)
			if !seenSet.has(f) {
				seenSet.add(f)
				seen = append(seen, f)
			}
		}
		messages = append(messages, m)
	}
	sort.Strings(seen)
	return messages, seen, nil
}

// exportWriteMessages is the lines of messages.jsonl for these messages, in the order given, each
// checked by the reader's rules but the references and written as RFC 8785 JSON.
// ExportLeftOut is a message the writer left out, and why (SPEC §9.2, what a contact controls).
type ExportLeftOut struct {
	ID     string `json:"id"`
	Reason string `json:"reason"`
}

// exportBodyHoldsAKey is why a message is left out: its body is what the key-material check refuses.
const exportBodyHoldsAKey = "its body holds what reads as a private key, which an export never carries"

// exportWriteMessages is the lines of messages.jsonl for these messages, in the order given, each
// checked by the reader's rules but the references (the host holds those) and written as RFC 8785
// JSON. What a contact controls never stops the export (SPEC §9.2): a message whose body holds what
// reads as a private key is left out and listed, and a reply_to naming a message the file does not
// carry is written null. The file's messages are these, less those left out; a host writing in
// batches names them all in fileMsgIDs.
func exportWriteMessages(messages []any, fileMsgIDs []string) ([]string, []ExportLeftOut, error) {
	var kept []map[string]any
	var at []int
	leftOut := []ExportLeftOut{}
	for i, v := range messages {
		doc, isObj := v.(map[string]any)
		if !isObj {
			return nil, nil, exportRefuse(fmt.Sprintf("messages[%d]: a message is an object", i))
		}
		if body, isText := doc["body"].(string); isText && holdsPrivateKey(body) {
			id, _ := doc["id"].(string)
			leftOut = append(leftOut, ExportLeftOut{ID: id, Reason: exportBodyHoldsAKey})
			continue
		}
		m, bad := checkMessage(doc, nil)
		if bad != nil {
			if bad.member != "" {
				return nil, nil, exportRefuse(fmt.Sprintf("messages[%d], member %s: %s", i, bad.member, bad.why))
			}
			return nil, nil, exportRefuse(fmt.Sprintf("messages[%d]: %s", i, bad.why))
		}
		kept = append(kept, m)
		at = append(at, i)
	}
	carried := strSet{}
	if fileMsgIDs != nil {
		carried = setOf(fileMsgIDs)
	} else {
		for _, m := range kept {
			if id, isText := m["msg_id"].(string); isText {
				carried.add(id)
			}
		}
	}
	lines := make([]string, 0, len(kept))
	for k, m := range kept {
		if r, isText := m["reply_to"].(string); isText && !carried.has(r) {
			m["reply_to"] = nil
		}
		line := string(Canonical(m))
		if len(line) > ExportLineMax {
			return nil, nil, exportRefuse(fmt.Sprintf("messages[%d]: over %d bytes as a line", at[k], ExportLineMax))
		}
		lines = append(lines, line)
	}
	return lines, leftOut, nil
}

// ── the writer ──────────────────────────────────────────────────────────────────────────────────

func contactCells(v any) ([]string, *cellRefusal) {
	o, isObj := v.(map[string]any)
	if !isObj {
		return nil, &cellRefusal{0, "a contact row is an object"}
	}
	if k := stranger(o, contactColumns); k != "" {
		return nil, &cellRefusal{0, k + " is not a column of contacts.csv"}
	}
	var cells []string
	for k, col := range contactColumns {
		val, has := o[col]
		wrong := &cellRefusal{k, "missing, or of the wrong type"}
		switch col {
		case "was_active":
			b, isBool := val.(bool)
			if !isBool {
				return nil, wrong
			}
			cells = append(cells, strconv.FormatBool(b))
		case "permissions", "their_permissions":
			items, isList := val.([]any)
			if !isList {
				return nil, wrong
			}
			var names []string
			for _, i := range items {
				s, isText := i.(string)
				if !isText {
					return nil, &cellRefusal{k, "a list of names"}
				}
				names = append(names, s)
			}
			if col == "their_permissions" {
				// SPEC §9.2, what a contact controls: the column is the contact's own claim and
				// informative only, so a name §8 does not have, or one repeated, is dropped rather
				// than stopping the owner's export.
				kept, seen := names[:0], strSet{}
				for _, n := range names {
					if isExportPermission(n) && !seen.has(n) {
						seen.add(n)
						kept = append(kept, n)
					}
				}
				names = kept
			}
			sort.Strings(names)
			cells = append(cells, strings.Join(names, " "))
		default:
			if (col == "leaf" || col == "root_cert") && (!has || val == nil) {
				cells = append(cells, "")
				continue
			}
			s, isText := val.(string)
			if !isText {
				return nil, wrong
			}
			if col == "display_name" {
				// The contact's name for themselves is their own claim: its control characters
				// dropped, and cut to 200 characters, on a character, rather than refused (SPEC §9.2,
				// what a contact controls).
				s = truncateRunes(dropControl(s), ExportNameMax)
			}
			if col == "name" {
				s = dropControl(s)
			}
			cells = append(cells, s)
		}
	}
	return cells, nil
}

// truncateRunes is s cut to at most n characters (Unicode scalar values), never inside one.
func truncateRunes(s string, n int) string {
	for i := range s {
		if n == 0 {
			return s[:i]
		}
		n--
	}
	return s
}

// threadCells is a thread row handed to export_write, as the longer header's cells: the two names
// absent are empty, and the contact's own name for themselves is cut to 200 characters, on a
// character (SPEC §9.2, what a contact controls).
func threadCells(v any) ([]string, *cellRefusal) {
	o, isObj := v.(map[string]any)
	if !isObj {
		return nil, &cellRefusal{0, "a thread row is an object"}
	}
	if k := stranger(o, threadColumnsNamed); k != "" {
		return nil, &cellRefusal{0, k + " is not a column of threads.csv"}
	}
	var cells []string
	for k, col := range threadColumnsNamed {
		val, has := o[col]
		s, isText := val.(string)
		switch {
		case k >= len(threadColumns) && !has:
		case !isText:
			return nil, &cellRefusal{k, "missing, or not a string"}
		case col == "contact_display_name":
			s = truncateRunes(dropControl(s), ExportNameMax)
		case col == "topic", col == "contact_name":
			s = dropControl(s)
		}
		cells = append(cells, s)
	}
	return cells, nil
}

type exportWritten struct {
	partial     map[string]any
	contactsCSV string
	threadsCSV  *string
}

type csvRowSort struct {
	key   string
	cells []string
}

func sortRows(rows []csvRowSort) {
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].key != rows[j].key {
			return rows[i].key < rows[j].key
		}
		return strings.Join(rows[i].cells, "\x00") < strings.Join(rows[j].cells, "\x00")
	})
}

// exportWrite is the canonical contacts.csv and threads.csv and the manifest without the messages.
func exportWrite(owner, ownerName string, exportedAt time.Time, tool string, contacts, threads, media []any) (*exportWritten, error) {
	if !IsFingerprint(owner) {
		return nil, exportRefuse("owner is not a fingerprint")
	}
	// SPEC 9.2#28: the owner's and the host's own strings are refused, naming the member —
	// there is nothing of a contact's to leave out.
	for _, m := range [][2]string{{"owner_name", ownerName}, {"tool", tool}} {
		if holdsPrivateKey(m[1]) {
			return nil, exportRefuse(m[0] + " holds a private key")
		}
	}
	var rows []csvRowSort
	written := strSet{}
	for i, c := range contacts {
		located := func(b *cellRefusal) error {
			return exportRefuse(fmt.Sprintf("contacts[%d], column %s: %s", i, contactColumns[b.col], b.why))
		}
		r, bad := contactCells(c)
		if bad != nil {
			return nil, located(bad)
		}
		row, bad := contactRow(r, owner, nil)
		if bad != nil {
			return nil, located(bad)
		}
		r[10] = row["added"].(string)
		if written.has(r[0]) {
			return nil, exportRefuse(fmt.Sprintf("contacts[%d], column root: appears twice", i))
		}
		written.add(r[0])
		rows = append(rows, csvRowSort{r[0], r})
	}
	if len(rows) > ExportContactsRowMax {
		return nil, exportRefuse(fmt.Sprintf("contacts: over %d rows", ExportContactsRowMax))
	}
	sortRows(rows)
	roots := written
	guarded := func(cells []string) []string {
		out := make([]string, len(cells))
		for k, c := range cells {
			out[k] = csvGuard(c)
		}
		return out
	}
	var cb strings.Builder
	csvWriteRecord(&cb, contactColumns)
	for _, r := range rows {
		csvWriteRecord(&cb, guarded(r.cells))
	}
	contactsCSV := cb.String()
	if len(contactsCSV) > ExportContactsMax {
		return nil, exportRefuse(fmt.Sprintf("contacts: over %d bytes as contacts.csv", ExportContactsMax))
	}

	// Each thread held to the longer header's rules: a thread whose contact is no contact here is a
	// removed thread, carrying its former contact's names, the same on every thread of that root.
	// The longer header is written only when one is (SPEC §9.2): every other file is a 1.0 file.
	var trows []csvRowSort
	threadIDs := strSet{}
	removed := removedNames{}
	for i, t := range threads {
		located := func(b *cellRefusal) error {
			return exportRefuse(fmt.Sprintf("threads[%d], column %s: %s", i, threadColumnsNamed[b.col], b.why))
		}
		r, bad := threadCells(t)
		if bad != nil {
			return nil, located(bad)
		}
		row, bad := threadRow(r, roots, true, owner)
		if bad != nil {
			return nil, located(bad)
		}
		r[3], r[4] = row.CreatedAt, row.LastAt
		if threadIDs.has(r[0]) {
			return nil, exportRefuse(fmt.Sprintf("threads[%d], column id: appears twice", i))
		}
		if !roots.has(row.Contact) {
			if col := removed.differs(row); col != 0 {
				return nil, located(&cellRefusal{col, "not what an earlier removed thread of this contact says"})
			}
		}
		threadIDs.add(r[0])
		trows = append(trows, csvRowSort{r[0], r})
	}
	sortRows(trows)
	columns := threadColumnsNamed
	if len(removed) == 0 {
		columns = threadColumns
	}
	var threadsCSV *string
	if len(trows) > 0 {
		var tb strings.Builder
		csvWriteRecord(&tb, columns)
		for _, r := range trows {
			csvWriteRecord(&tb, guarded(r.cells[:len(columns)]))
		}
		t := tb.String()
		threadsCSV = &t
	}
	if threadsCSV != nil && len(*threadsCSV) > ExportThreadsMax {
		return nil, exportRefuse(fmt.Sprintf("threads: over %d bytes as threads.csv", ExportThreadsMax))
	}

	files := map[string]any{"contacts.csv": sha256Hex([]byte(contactsCSV))}
	if threadsCSV != nil {
		files["threads.csv"] = sha256Hex([]byte(*threadsCSV))
	}
	// The media are counted, never listed: files holds the text members alone (SPEC 9.2#11).
	hashes := strSet{}
	for i, item := range media {
		o, _ := item.(map[string]any)
		hash, _ := o["hash"].(string)
		if !isExportHash(hash) {
			return nil, exportRefuse(fmt.Sprintf("media[%d]: hash is not a lowercase hex sha256", i))
		}
		if s, ok := asU64(o["size"]); !ok || s > ExportMediaMax {
			return nil, exportRefuse(fmt.Sprintf("media[%d]: size is a number of bytes up to %d", i, ExportMediaMax))
		}
		if hashes.has(hash) {
			return nil, exportRefuse(fmt.Sprintf("media[%d]: appears twice", i))
		}
		hashes.add(hash)
	}
	partial := map[string]any{
		"hdtp_export": int64(exportVersion), "owner": owner, "owner_name": ownerName,
		"exported_at": timeOut(exportedAt), "tool": tool,
		"counts": map[string]any{"contacts": int64(len(rows)), "threads": int64(len(trows)), "messages": int64(0), "media": int64(len(media))},
		"files":  files,
	}
	return &exportWritten{partial: partial, contactsCSV: contactsCSV, threadsCSV: threadsCSV}, nil
}

// ── the merge ───────────────────────────────────────────────────────────────────────────────────

// mergeRoot is a row's root, with the two other members the merge reads a meaning from held to what
// the contract says they are (ContactRow), in export_read's words, as the core's root_of: a status
// outside the three was read as not blocked, so a held contact written as "Blocked" lost its block on
// an import, and an added that is no instant was carried into what the host writes (the review of
// 2026-09-30, found by parity's nested "" cases). A member that is absent is left to the host.
func mergeRoot(v any, what string, i int) (string, error) {
	o, _ := v.(map[string]any)
	r, isText := o["root"].(string)
	if !isText || !IsFingerprint(r) {
		return "", exportRefuse(fmt.Sprintf("%s[%d]: root is not a fingerprint", what, i))
	}
	if status, isText := o["status"].(string); isText && !contains(contactStatuses, status) {
		return "", exportRefuse(fmt.Sprintf("%s[%d]: status is not active, blocked or pending_out", what, i))
	}
	if added, isText := o["added"].(string); isText {
		if _, ok := parseInstantZ(added); !ok {
			return "", exportRefuse(fmt.Sprintf("%s[%d]: added is not an RFC 3339 instant", what, i))
		}
	}
	return r, nil
}

// exportMerge is SPEC §9.2's import step 2: an imported leaf never replaces a pin the host holds.
func exportMerge(held, rows []any) (write []any, keep []any, conflicts []any, err error) {
	// The held rows by root, the first of each kept, as a scan would have found it.
	heldBy := map[string]map[string]any{}
	for i, h := range held {
		r, err := mergeRoot(h, "held", i)
		if err != nil {
			return nil, nil, nil, err
		}
		o, _ := h.(map[string]any)
		if _, dup := heldBy[r]; !dup {
			heldBy[r] = o
		}
	}
	write, keep, conflicts = []any{}, []any{}, []any{}
	conflict := func(root, f string, h, r map[string]any) {
		was, now := h[f], r[f]
		if now != nil && !mergeSame(was, now) {
			conflicts = append(conflicts, map[string]any{"root": root, "field": f, "held": was, "row": now})
		}
	}
	for i, v := range rows {
		root, err := mergeRoot(v, "rows", i)
		if err != nil {
			return nil, nil, nil, err
		}
		r, _ := v.(map[string]any)
		h, found := heldBy[root]
		if !found {
			write = append(write, v)
			continue
		}
		if h["leaf"] == nil && r["leaf"] != nil {
			// The leaf that validated is taken; what the person decided about the contact is kept
			// as held — a blocked contact stays blocked, the grants stay the person's — and each
			// difference the file carried is a conflict.
			for _, f := range decidedFields {
				conflict(root, f, h, r)
			}
			w := make(map[string]any, len(r))
			for k, x := range r {
				w[k] = x
			}
			if h["status"] == "blocked" {
				w["status"] = "blocked"
			}
			if p, has := h["permissions"]; has && p != nil {
				w["permissions"] = p
			}
			write = append(write, w)
			continue
		}
		for _, f := range append(append([]string{}, pinFields...), decidedFields...) {
			conflict(root, f, h, r)
		}
		keep = append(keep, root)
	}
	return write, keep, conflicts, nil
}

// decidedFields are what the person decided about a contact the host holds: never taken from a file.
var decidedFields = []string{"status", "permissions"}

// mergeSame is two values alike: a list of names compared as a set, anything else as JSON.
func mergeSame(a, b any) bool {
	x, xl := a.([]any)
	y, yl := b.([]any)
	if xl && yl {
		sx, sy := make([]string, len(x)), make([]string, len(y))
		for i, v := range x {
			sx[i] = string(Canonical(v))
		}
		for i, v := range y {
			sy[i] = string(Canonical(v))
		}
		sort.Strings(sx)
		sort.Strings(sy)
		return strings.Join(sx, "\x00") == strings.Join(sy, "\x00") && len(sx) == len(sy)
	}
	return bytes.Equal(Canonical(a), Canonical(b))
}

// vaultContactMembers are the members of the wallet's own copy of a contact (CONTRACT §6).
var vaultContactMembers = []string{"root", "endpoint", "name", "leaf", "root_cert", "added"}

// bookRows is the wallet's book as rows of contacts.csv (SPEC §9.2), as the core's book_rows: the
// book keeps the root, the endpoint, the name, the leaf, the root certificate and when the contact
// was added; a row's other columns are what a contact the wallet keeps is (active, ever active,
// nothing granted), and added is the export's time when the book has none.
func bookRows(contacts []any, exportedAt time.Time) ([]any, error) {
	rows := []any{}
	for i, c := range contacts {
		o, isObj := c.(map[string]any)
		if !isObj {
			return nil, exportRefuse(fmt.Sprintf("contacts[%d] is an object", i))
		}
		if k := stranger(o, vaultContactMembers); k != "" {
			return nil, exportRefuse(fmt.Sprintf("contacts[%d]: %s is not a member of a wallet contact", i, jsonString(k)))
		}
		for _, m := range []string{"root", "endpoint"} {
			if _, isText := o[m].(string); !isText {
				return nil, exportRefuse(fmt.Sprintf("contacts[%d]: %s is required", i, m))
			}
		}
		for _, m := range []string{"name", "leaf", "root_cert", "added"} {
			if v, has := o[m]; has {
				if _, isText := v.(string); !isText {
					return nil, exportRefuse(fmt.Sprintf("contacts[%d]: %s is a string", i, m))
				}
			}
		}
		// A row carries the root and added into export_write and to the host as the contract types
		// them, as the core's book_rows: a root that is no fingerprint, or an added that is no
		// instant, came back in a row off the contract (the review of 2026-09-30).
		if !IsFingerprint(o["root"].(string)) {
			return nil, exportRefuse(fmt.Sprintf("contacts[%d]: root is not a fingerprint", i))
		}
		added, has := o["added"].(string)
		if has {
			if _, ok := parseInstantZ(added); !ok {
				return nil, exportRefuse(fmt.Sprintf("contacts[%d]: added is not an RFC 3339 instant", i))
			}
		} else {
			added = timeOut(exportedAt)
		}
		opt := func(m string) any {
			if s, isText := o[m].(string); isText {
				return s
			}
			return nil
		}
		name, _ := o["name"].(string)
		rows = append(rows, map[string]any{
			"root": o["root"], "endpoint": o["endpoint"], "name": name, "display_name": "",
			"status": "active", "was_active": true, "permissions": []any{}, "their_permissions": []any{},
			"leaf": opt("leaf"), "root_cert": opt("root_cert"), "added": added,
		})
	}
	return rows, nil
}
