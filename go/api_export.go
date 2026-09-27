package pactidentity

// The Export section of contract/contract.json: a body for each function it declares, which
// api.go's `functions` map dispatches by name. Arguments are read in the core's order and named in
// its words (api/export.rs), so a caller's mistake is one answer from both ports.

import (
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

// str is the core's `s`: a string, or `<k> is required`.
func (a exportArgs) str(k string) (string, error) {
	s, isText := a.value(k).(string)
	if !isText {
		return "", errArg(k + " is required")
	}
	return s, nil
}

// optStr is the core's `opt_s`: anything but a string is absent.
func (a exportArgs) optStr(k string) *string {
	s, isText := a.value(k).(string)
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

func (a exportArgs) strings(k string) ([]string, error) {
	l, err := a.list(k)
	if err != nil {
		return nil, err
	}
	out := []string{}
	for _, v := range l {
		s, isText := v.(string)
		if !isText {
			return nil, errArg(k + " is a list of strings")
		}
		out = append(out, s)
	}
	return out, nil
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
	r, err := exportRead(directory, a.optStr("manifest"), a.optStr("contacts_csv"), a.optStr("threads_csv"), owner, now)
	if err != nil {
		return fail(codeArgs, err.Error())
	}
	return ok(map[string]any{"contacts": r.contacts, "threads": r.threads, "media": mediaOut(r.media)})
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
	lines, err := exportWriteMessages(messages)
	if err != nil {
		return fail(codeArgs, err.Error())
	}
	return ok(map[string]any{"lines": lines})
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
