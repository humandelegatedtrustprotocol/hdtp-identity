package pactidentity

// The Export section of contract/contract.json: a body for each function it declares, which
// api.go's `functions` map dispatches by name. Arguments are read in the core's order and named in
// its words (api/export.rs), so a caller's mistake is one answer from both ports.

import (
	"bytes"
	"encoding/json"
	"time"
)

type exportArgs map[string]json.RawMessage

func readExportArgs(raw json.RawMessage) (exportArgs, json.RawMessage) {
	a := exportArgs{}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &a); err != nil {
			return nil, fail(codeArgs, "args is a JSON object")
		}
	}
	return a, nil
}

func (a exportArgs) value(k string) any {
	raw, has := a[k]
	if !has {
		return nil
	}
	v, err := decodeJSON(raw)
	if err != nil {
		return nil
	}
	return v
}

// text is a string member, decoded straight into a string: a 16 MiB CSV member decoded through a
// generic Decoder was buffered twice over before it was a string once.
func (a exportArgs) text(k string) (string, bool) {
	raw, has := a[k]
	if !has || len(raw) == 0 || raw[0] != '"' {
		return "", false
	}
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return "", false
	}
	return s, true
}

// str is the core's `s`: a string, or `<k> is required`.
func (a exportArgs) str(k string) (string, error) {
	s, isText := a.text(k)
	if !isText {
		return "", errArg(k + " is required")
	}
	return s, nil
}

// optStr is the core's `opt_s`: anything but a string is absent.
func (a exportArgs) optStr(k string) *string {
	s, isText := a.text(k)
	if !isText {
		return nil
	}
	return &s
}

func (a exportArgs) instant(k string) (time.Time, json.RawMessage) {
	s, err := a.str(k)
	if err != nil {
		return time.Time{}, failErr(codeArgs, err)
	}
	t, ok := parseInstantZ(s)
	if !ok {
		return time.Time{}, fail("parse", "not an RFC 3339 instant: "+s)
	}
	return t, nil
}

func (a exportArgs) list(k string) ([]any, error) {
	l, isList := a.value(k).([]any)
	if !isList {
		return nil, errArg(k + " is required")
	}
	return l, nil
}

func (a exportArgs) optList(k string) ([]any, error) {
	switch v := a.value(k).(type) {
	case nil:
		return []any{}, nil
	case []any:
		return v, nil
	}
	return nil, errArg(k + " is required")
}

// strings is a list of strings, decoded straight into one: a list of an id per message decoded as
// a list of interfaces first held each id twice over. A member that is not a list is `<k> is
// required`; a list holding anything but strings — null included, which a decoder into strings
// would quietly read as "" — is `<k> is a list of strings`.
func (a exportArgs) strings(k string) ([]string, error) {
	raw, has := a[k]
	if !has || len(raw) == 0 || raw[0] != '[' {
		return nil, errArg(k + " is required")
	}
	out := []string{}
	if json.Unmarshal(raw, &out) != nil || holdsNull(raw) {
		return nil, errArg(k + " is a list of strings")
	}
	return out, nil
}

// holdsNull is whether JSON text holds a null outside every string in it.
func holdsNull(raw []byte) bool {
	in := false
	for i := 0; i < len(raw); i++ {
		switch c := raw[i]; {
		case in && c == '\\':
			i++
		case c == '"':
			in = !in
		case !in && c == 'n':
			return true
		}
	}
	return false
}

func (a exportArgs) count(k string) (uint64, error) {
	v := a.value(k)
	if v == nil {
		return 0, nil
	}
	n, ok := asU64(v)
	if !ok {
		return 0, errArg(k + " is a whole number")
	}
	return n, nil
}

func mediaOut(media []ExportMedia) []any {
	out := []any{}
	for _, m := range media {
		out = append(out, map[string]any{"hash": m.Hash, "size": m.Size})
	}
	return out
}

func callExportRead(args json.RawMessage) json.RawMessage {
	a, bad := readExportArgs(args)
	if bad != nil {
		return bad
	}
	entries, err := a.list("directory")
	if err != nil {
		return failErr(codeArgs, err)
	}
	var directory []ExportEntry
	for i, e := range entries {
		o, _ := e.(map[string]any)
		name, nameOK := o["name"].(string)
		size, sizeOK := asU64(o["size"])
		encrypted, encOK := o["encrypted"].(bool)
		mode, modeOK := asU64(o["mode"])
		if !nameOK || !sizeOK || !encOK || !modeOK || mode > 0xffffffff {
			return fail(codeArgs, "directory["+itoa(i)+"] does not read")
		}
		directory = append(directory, ExportEntry{Name: name, Size: size, Encrypted: encrypted, Mode: uint32(mode)})
	}
	owner, err := a.str("owner")
	if err != nil {
		return failErr(codeArgs, err)
	}
	now, bad := a.instant("now")
	if bad != nil {
		return bad
	}
	threadsCSV := a.optStr("threads_csv")
	r, err := exportRead(directory, a.optStr("manifest"), a.optStr("contacts_csv"), threadsCSV, owner, now)
	if err != nil {
		return fail(codeArgs, err.Error())
	}
	threadsBytes := 0
	if threadsCSV != nil {
		threadsBytes = len(*threadsCSV)
	}
	return readAnswer(r, threadsBytes)
}

func callExportReadMessages(args json.RawMessage) json.RawMessage {
	a, bad := readExportArgs(args)
	if bad != nil {
		return bad
	}
	lines, err := a.strings("lines")
	if err != nil {
		return failErr(codeArgs, err)
	}
	var names messageNames
	for _, f := range []struct {
		k  string
		to *strSet
	}{{"threads", &names.threads}, {"contacts", &names.contacts}, {"media", &names.media}} {
		list, err := a.strings(f.k)
		if err != nil {
			return failErr(codeArgs, err)
		}
		*f.to = setOf(list)
	}
	first := uint64(1)
	if v := a.value("first_line"); v != nil {
		n, isN := asU64(v)
		if !isN || n < 1 {
			return fail(codeArgs, "first_line is a line number from 1")
		}
		first = n
	}
	messages, seen, err := exportReadMessages(lines, first, names)
	if err != nil {
		return fail(codeArgs, err.Error())
	}
	return ok(map[string]any{"messages": messages, "media_seen": seen})
}

func callExportReadEnd(args json.RawMessage) json.RawMessage {
	a, bad := readExportArgs(args)
	if bad != nil {
		return bad
	}
	text, err := a.str("manifest")
	if err != nil {
		return failErr(codeArgs, err)
	}
	var sha *string
	switch v := a.value("messages_sha256").(type) {
	case nil:
	case string:
		sha = &v
	default:
		return fail(codeArgs, "messages_sha256 is a lowercase hex sha256 or null")
	}
	e := exportEnd{messagesSHA256: sha}
	if e.lines, err = a.count("lines"); err != nil {
		return failErr(codeArgs, err)
	}
	for _, f := range []struct {
		k  string
		to *[]string
	}{{"ids", &e.ids}, {"msg_ids", &e.msgIDs}, {"reply_tos", &e.replyTos}, {"media_seen", &e.mediaSeen}} {
		if *f.to, err = a.strings(f.k); err != nil {
			return failErr(codeArgs, err)
		}
	}
	if err := exportReadEnd(text, e); err != nil {
		return fail(codeArgs, err.Error())
	}
	return ok(map[string]any{"ok": true})
}

func callExportWrite(args json.RawMessage) json.RawMessage {
	a, bad := readExportArgs(args)
	if bad != nil {
		return bad
	}
	owner, err := a.str("owner")
	if err != nil {
		return failErr(codeArgs, err)
	}
	ownerName, err := a.str("owner_name")
	if err != nil {
		return failErr(codeArgs, err)
	}
	at, bad := a.instant("exported_at")
	if bad != nil {
		return bad
	}
	tool, err := a.str("tool")
	if err != nil {
		return failErr(codeArgs, err)
	}
	contacts, err := a.list("contacts")
	if err != nil {
		return failErr(codeArgs, err)
	}
	threads, err := a.optList("threads")
	if err != nil {
		return failErr(codeArgs, err)
	}
	media, err := a.optList("media")
	if err != nil {
		return failErr(codeArgs, err)
	}
	w, err := exportWrite(owner, ownerName, at, tool, contacts, threads, media)
	if err != nil {
		return fail(codeArgs, err.Error())
	}
	var threadsCSV any
	if w.threadsCSV != nil {
		threadsCSV = *w.threadsCSV
	}
	return ok(map[string]any{"partial": w.partial, "contacts_csv": w.contactsCSV, "threads_csv": threadsCSV})
}

func callExportWriteMessages(args json.RawMessage) json.RawMessage {
	a, bad := readExportArgs(args)
	if bad != nil {
		return bad
	}
	messages, err := a.list("messages")
	if err != nil {
		return failErr(codeArgs, err)
	}
	var fileMsgIDs []string
	if raw, has := a["msg_ids"]; has && string(raw) != "null" {
		if fileMsgIDs, err = a.strings("msg_ids"); err != nil {
			return failErr(codeArgs, err)
		}
	}
	lines, leftOut, err := exportWriteMessages(messages, fileMsgIDs)
	if err != nil {
		return fail(codeArgs, err.Error())
	}
	return ok(map[string]any{"lines": lines, "left_out": leftOut})
}

func callExportManifest(args json.RawMessage) json.RawMessage {
	a, bad := readExportArgs(args)
	if bad != nil {
		return bad
	}
	if _, isObj := a.value("partial").(map[string]any); !isObj {
		return fail(codeArgs, "partial is required")
	}
	var sha *string
	switch h := a.value("hashes").(type) {
	case nil:
	case map[string]any:
		if k := stranger(h, []string{"messages.jsonl"}); k != "" {
			return fail(codeArgs, "hashes: "+jsonString(k)+" is not hashed by the host: only messages.jsonl is")
		}
		switch v := h["messages.jsonl"].(type) {
		case nil:
			if _, has := h["messages.jsonl"]; has {
				return fail(codeArgs, "hashes: messages.jsonl: not a lowercase hex sha256")
			}
		case string:
			sha = &v
		default:
			return fail(codeArgs, "hashes: messages.jsonl: not a lowercase hex sha256")
		}
	default:
		return fail(codeArgs, "hashes is an object")
	}
	n, err := a.count("messages")
	if err != nil {
		return failErr(codeArgs, err)
	}
	text, err := finishManifest(a["partial"], sha, n)
	if err != nil {
		return fail(codeArgs, err.Error())
	}
	return ok(map[string]any{"manifest": text})
}

func callExportMerge(args json.RawMessage) json.RawMessage {
	a, bad := readExportArgs(args)
	if bad != nil {
		return bad
	}
	held, err := a.list("held")
	if err != nil {
		return failErr(codeArgs, err)
	}
	rows, err := a.list("rows")
	if err != nil {
		return failErr(codeArgs, err)
	}
	write, keep, conflicts, err := exportMerge(held, rows)
	if err != nil {
		return fail(codeArgs, err.Error())
	}
	return ok(map[string]any{"write": write, "keep": keep, "conflicts": conflicts})
}

func callBookRows(args json.RawMessage) json.RawMessage {
	a, bad := readExportArgs(args)
	if bad != nil {
		return bad
	}
	contacts, err := a.list("contacts")
	if err != nil {
		return failErr(codeArgs, err)
	}
	at, bad := a.instant("exported_at")
	if bad != nil {
		return bad
	}
	rows, err := bookRows(contacts, at)
	if err != nil {
		return fail(codeArgs, err.Error())
	}
	return ok(map[string]any{"rows": rows})
}

// readAnswer is export_read's answer, written straight from the rows: the threads, which a file can
// hold by the hundred thousand, are never turned into maps to be marshalled. The contacts (5000 at
// most) and the media go through encoding/json as every other answer does.
func readAnswer(r *exportReadResult, threadsBytes int) json.RawMessage {
	contacts, err := json.Marshal(r.contacts)
	if err != nil {
		return fail("internal", err.Error())
	}
	media, err := json.Marshal(mediaOut(r.media))
	if err != nil {
		return fail("internal", err.Error())
	}
	var b bytes.Buffer
	// A thread's answer is its CSV row and some 57 bytes of keys and quotes.
	b.Grow(len(contacts) + len(media) + threadsBytes + 64*len(r.threads) + 64)
	b.WriteString(`{"contacts":`)
	b.Write(contacts)
	b.WriteString(`,"threads":[`)
	for k, t := range r.threads {
		if k > 0 {
			b.WriteByte(',')
		}
		b.WriteString(`{"id":`)
		writeJSONString(&b, t.ID)
		b.WriteString(`,"contact":`)
		writeJSONString(&b, t.Contact)
		b.WriteString(`,"topic":`)
		writeJSONString(&b, t.Topic)
		b.WriteString(`,"created_at":`)
		writeJSONString(&b, t.CreatedAt)
		b.WriteString(`,"last_at":`)
		writeJSONString(&b, t.LastAt)
		b.WriteByte('}')
	}
	b.WriteString(`],"media":`)
	b.Write(media)
	b.WriteByte('}')
	return b.Bytes()
}
