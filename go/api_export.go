package hdtpidentity

// The Export section of contract/contract.json: a body for each function it declares, which
// api.go's `functions` map dispatches by name. Arguments are read in the core's order and named in
// its words (api/export.rs), so a caller's mistake is one answer from both ports.

import (
	"bytes"
	"encoding/json"
)

func mediaOut(media []ExportMedia) []any {
	out := []any{}
	for _, m := range media {
		out = append(out, map[string]any{"hash": m.Hash, "size": m.Size})
	}
	return out
}

func callExportRead(a args) json.RawMessage {
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
	now, err := a.instant("now")
	if err != nil {
		return failErr(codeFor(err, "parse"), err)
	}
	// The four texts, in the core's order, each a string or not given: one of another type is refused,
	// where both ports read it as absent (CONTRACT §0, F5).
	var texts [4]*string
	for i, k := range []string{"manifest", "contacts_csv", "removed_csv", "threads_csv"} {
		if texts[i], err = a.optStr(k); err != nil {
			return failErr(codeArgs, err)
		}
	}
	threadsCSV := texts[3]
	r, err := exportRead(directory, texts[0], texts[1], texts[2], threadsCSV, owner, now)
	if err != nil {
		return fail(codeArgs, err.Error())
	}
	threadsBytes := 0
	if threadsCSV != nil {
		threadsBytes = len(*threadsCSV)
	}
	return readAnswer(r, threadsBytes)
}

func callExportReadMessages(a args) json.RawMessage {
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

func callExportReadEnd(a args) json.RawMessage {
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
	// Absent, it was 0 lines, and the file was refused for its count instead (S1-3).
	if a.present("lines") == nil {
		return fail(codeArgs, "lines is required")
	}
	if e.lines, err = a.count("lines"); err != nil {
		return failErr(codeArgs, err)
	}
	for _, f := range []struct {
		k  string
		to *[]string
	}{{"ids", &e.ids}, {"msg_ids", &e.msgIDs}, {"reply_tos", &e.replyTos}, {"media_seen", &e.mediaSeen}, {"media", &e.media}} {
		if *f.to, err = a.strings(f.k); err != nil {
			return failErr(codeArgs, err)
		}
	}
	if err := exportReadEnd(text, e); err != nil {
		return fail(codeArgs, err.Error())
	}
	return ok(map[string]any{"ok": true})
}

func callExportWrite(a args) json.RawMessage {
	owner, err := a.str("owner")
	if err != nil {
		return failErr(codeArgs, err)
	}
	ownerName, err := a.str("owner_name")
	if err != nil {
		return failErr(codeArgs, err)
	}
	at, err := a.instant("exported_at")
	if err != nil {
		return failErr(codeFor(err, "parse"), err)
	}
	tool, err := a.str("tool")
	if err != nil {
		return failErr(codeArgs, err)
	}
	contacts, err := a.list("contacts")
	if err != nil {
		return failErr(codeArgs, err)
	}
	removed, err := a.optList("removed")
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
	w, err := exportWrite(owner, ownerName, at, tool, contacts, removed, threads, media)
	if err != nil {
		return fail(codeArgs, err.Error())
	}
	var removedCSV, threadsCSV any
	if w.removedCSV != nil {
		removedCSV = *w.removedCSV
	}
	if w.threadsCSV != nil {
		threadsCSV = *w.threadsCSV
	}
	return ok(map[string]any{"partial": w.partial, "contacts_csv": w.contactsCSV, "removed_csv": removedCSV, "threads_csv": threadsCSV})
}

func callExportWriteMessages(a args) json.RawMessage {
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

func callExportManifest(a args) json.RawMessage {
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

func callExportMerge(a args) json.RawMessage {
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

// callMediaHoldsPrivateKey answers whether a media file's bytes are key material (SPEC §9.2), as
// ReadExportZip judges a media file: the check a host makes on the files it streams, which the core
// never sees. The cloud kept a third copy in TypeScript that read spellings the ports did not (CW-07,
// R38).
func callMediaHoldsPrivateKey(a args) json.RawMessage {
	b, err := a.bytes("bytes")
	if err != nil {
		return failAs("parse", err)
	}
	return ok(map[string]any{"holds_private_key": mediaHoldsPrivateKey(b)})
}

func callBookRows(a args) json.RawMessage {
	contacts, err := a.list("contacts")
	if err != nil {
		return failErr(codeArgs, err)
	}
	at, err := a.instant("exported_at")
	if err != nil {
		return failErr(codeFor(err, "parse"), err)
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
	removed, err := json.Marshal(r.removed)
	if err != nil {
		return fail("internal", err.Error())
	}
	var b bytes.Buffer
	// A thread's answer is its CSV row and some 57 bytes of keys and quotes.
	b.Grow(len(contacts) + len(removed) + len(media) + threadsBytes + 64*len(r.threads) + 64)
	b.WriteString(`{"contacts":`)
	b.Write(contacts)
	b.WriteString(`,"removed":`)
	b.Write(removed)
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
