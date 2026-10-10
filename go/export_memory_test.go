package hdtpidentity

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"runtime"
	"runtime/debug"
	"strings"
	"testing"
)

// What the export's readers allocate, per byte they are handed, in the Go port: every byte one call
// allocates with the collector off (runtime.MemStats.TotalAlloc), an upper bound on what the call
// holds at its peak and the same number on every run. The Rust core's tests/memory.rs and
// js/export-memory.test.mjs hold the core's own peak and the Wasm instance's linear memory.
//
// The bounds are ratios to what a call is handed, checked at N and 4N rows, so they cannot go stale
// with file sizes and a cost growing faster than the rows fails:
//
//   export_read, at most 9 bytes allocated per byte of threads.csv: the argument's raw JSON copied
//   out of the arguments, the text it decodes to, the answer (the rows again with some 57 bytes of
//   keys each), a ThreadRow of five string headers per thread sharing the text, a set of the ids, and
//   the garbage of slices grown on the way — 6.6–6.8× measured on 2026-09-27. 0.3.1 allocated 28×.
//   Measured again on 2026-10-10 with removed threads (SEP-0004): 6.8–7.0× for contacts' threads;
//   7.5–7.7× for a file whose every thread is removed with a root of its own (11.3–11.6× before a
//   removed thread's names were held by the row rather than copied); 7.6× for 64,000 of them holding
//   the 65,536 control characters ExportControlMax lets through. At the largest legal threads.csv: every
//   topic 1000 line feeds or tabs, which the answer writes as two bytes each, 7.91× (9.15× before the
//   answer's room counted them, its buffer doubling); every thread removed under one root with names
//   of 200 characters, 5.67×. A member denser with U+0001, which a JSON answer writes as six bytes, is
//   refused before it is parsed; such a file's argument is some six times its CSV, which the call
//   decodes once, 2.4× the argument (it built an answer as large again before: 30× the CSV). A host
//   bounds the argument by the member's bytes before the call: BatonDeck takes a threads.csv of 4 MiB
//   at most, a quarter of what these figures are measured at.
//
//   export_read_end, at most 6 bytes per byte of its lists: each list's raw JSON and the strings it
//   decodes to, and the ids and msg_ids sorted — 4.4× measured. 0.3.1 allocated 10×.

// memUUID is a UUID-shaped thread id, as hosts mint them.
func memUUID(i int) string {
	s := sha256.Sum256([]byte(fmt.Sprintf("u%d", i)))
	h := hex.EncodeToString(s[:])
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

func memFP(i int) string {
	s := sha256.Sum256([]byte(fmt.Sprintf("c%d", i)))
	return "sha256:" + base64.RawURLEncoding.EncodeToString(s[:])
}

// memReadArgs is export_read's arguments for 200 contacts and `rows` threads, and the CSV's size.
func memReadArgs(t *testing.T, rows int) ([]byte, int) { return memReadArgsOf(t, rows, false) }

// memReadArgsOf is memReadArgs, or, when removed, the same rows each a removed thread with a root of
// its own (SPEC §9.2): what the reader keeps of a removed thread, on every row.
func memReadArgsOf(t *testing.T, rows int, removed bool) ([]byte, int) {
	if !removed {
		return memReadArgsWith(t, rows, nil)
	}
	return memReadArgsWith(t, rows, func(i int, th map[string]any) { th["contact"] = memFP(1000 + i) })
}

// memReadArgsWith is memReadArgs with each thread handed to `edit` before export_write writes it.
func memReadArgsWith(t *testing.T, rows int, edit func(i int, th map[string]any)) ([]byte, int) {
	owner := "sha256:" + strings.Repeat("O", 42) + "A"
	contacts := []any{}
	for i := 0; i < 200; i++ {
		contacts = append(contacts, map[string]any{"root": memFP(i), "endpoint": fmt.Sprintf("https://c%d.example/mcp", i), "name": "",
			"display_name": "", "status": "active", "was_active": true, "permissions": []any{}, "their_permissions": []any{}, "added": "2026-09-01T00:00:00Z"})
	}
	threads := []any{}
	for i := 0; i < rows; i++ {
		th := map[string]any{"id": memUUID(i), "contact": memFP(i % 200), "topic": "a topic",
			"created_at": "2026-09-01T00:00:00Z", "last_at": "2026-09-01T00:00:00Z"}
		if edit != nil {
			edit(i, th)
		}
		threads = append(threads, th)
	}
	var w map[string]any
	in, _ := json.Marshal(map[string]any{"owner": owner, "owner_name": "", "exported_at": "2026-09-27T00:00:00Z", "tool": "t", "contacts": contacts, "threads": threads})
	if err := json.Unmarshal(Call("export_write", in), &w); err != nil || w["error"] != nil {
		t.Fatalf("export_write: %v %v", err, w["why"])
	}
	var m map[string]any
	in, _ = json.Marshal(map[string]any{"partial": w["partial"]})
	_ = json.Unmarshal(Call("export_manifest", in), &m)
	dir := []any{}
	for _, n := range []string{"manifest.json", "contacts.csv", "threads.csv"} {
		dir = append(dir, map[string]any{"name": n, "size": 1, "encrypted": false, "mode": 0})
	}
	args, _ := json.Marshal(map[string]any{"directory": dir, "manifest": m["manifest"], "contacts_csv": w["contacts_csv"],
		"threads_csv": w["threads_csv"], "owner": owner, "now": "2026-09-27T00:00:00Z"})
	return args, len(w["threads_csv"].(string))
}

// memOf is every byte one call allocates, with the collector off so nothing is freed and reused
// under it: an upper bound on what the call holds at its peak, the answer included, and a number
// the same on every run.
func memOf(t *testing.T, name string, args []byte) (uint64, json.RawMessage) {
	defer debug.SetGCPercent(debug.SetGCPercent(-1))
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	out := Call(name, args)
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc, out
}

func TestExportReadAllocatesABoundedAmountPerRow(t *testing.T) {
	for _, c := range []struct {
		rows    int
		removed bool
	}{{16000, false}, {64000, false}, {16000, true}, {64000, true}} {
		rows := c.rows
		args, csvBytes := memReadArgsOf(t, rows, c.removed)
		n, out := memOf(t, "export_read", args)
		if strings.Contains(string(out[:min(len(out), 100)]), `"error"`) {
			t.Fatal(string(out[:200]))
		}
		t.Logf("export_read, %d threads, removed %v (%d bytes of threads.csv): %d bytes allocated, %d per row, %.2fx the CSV", rows, c.removed, csvBytes, n, n/uint64(rows), float64(n)/float64(csvBytes))
		if n > 9*uint64(csvBytes) {
			t.Errorf("%d threads: %.2fx the CSV allocated, over 9x", rows, float64(n)/float64(csvBytes))
		}
	}
}

func TestExportReadEndAllocatesABoundedAmountPerID(t *testing.T) {
	for _, rows := range []int{16000, 64000} {
		ids, msgIDs := []string{}, []string{}
		for i := 0; i < rows; i++ {
			ids = append(ids, memUUID(i))
			msgIDs = append(msgIDs, "x"+memUUID(i))
		}
		hash := strings.Repeat("a", 64)
		manifest, _ := json.Marshal(map[string]any{"hdtp_export": 1, "owner": "sha256:" + strings.Repeat("O", 42) + "A", "owner_name": "", "exported_at": "2026-09-27T00:00:00Z",
			"tool": "t", "counts": map[string]any{"contacts": 0, "threads": 0, "messages": rows, "media": 0}, "files": map[string]any{"messages.jsonl": hash}})
		args, _ := json.Marshal(map[string]any{"manifest": string(manifest), "messages_sha256": hash, "lines": rows, "ids": ids, "msg_ids": msgIDs, "reply_tos": msgIDs[1:], "media_seen": []string{}, "media": []string{}})
		lists, _ := json.Marshal([]any{ids, msgIDs, msgIDs[1:]})
		n, out := memOf(t, "export_read_end", args)
		if !strings.Contains(string(out), `"ok":true`) {
			t.Fatal(string(out))
		}
		t.Logf("export_read_end, %d ids (%d bytes of lists): %d bytes allocated, %d per id, %.2fx the lists", rows, len(lists), n, n/uint64(rows), float64(n)/float64(len(lists)))
		if n > 6*uint64(len(lists)) {
			t.Errorf("%d ids: %.2fx the lists allocated, over 6x", rows, float64(n)/float64(len(lists)))
		}
	}
}

// The two absolute figures, recorded as measured: the largest threads.csv SPEC §9.2 allows (16 MiB,
// 120,684 threads with UUID ids), and a 64 MiB messages.jsonl read in batches of 500 lines as a host
// streams it, whose every batch must cost what one batch costs, never what the file does. Measured
// 2026-09-27: export_read of the largest threads.csv allocated 109.5 MB (6.5×; 0.3.1: 477.1 MB,
// 28.4×); the costliest batch of the 64 MiB messages.jsonl (160,430 lines) 4.4 MB (0.3.1: 5.6 MB).
// 2026-10-10: the largest threads.csv 114.3 MB (6.81×), and the largest of removed threads, each with a
// root of its own, 125.9 MB (7.50×; 189.1 MB, 11.27×, before the names were held by the row).
// memLargest is memReadArgsWith at the most rows whose threads.csv fits the 16 MiB SPEC §9.2 allows,
// within 64 KiB of it: a row's size is measured on 1000 of them.
func memLargest(t *testing.T, edit func(i int, th map[string]any)) ([]byte, int, int) {
	_, one := memReadArgsWith(t, 1, edit)
	_, more := memReadArgsWith(t, 1001, edit)
	per := (more - one) / 1000
	rows := (16*1024*1024 - 4096 - (one - per)) / per
	args, csv := memReadArgsWith(t, rows, edit)
	if csv > 16*1024*1024 || csv < 16*1024*1024-64*1024 {
		t.Fatalf("threads.csv is %d bytes, not the largest the bound allows", csv)
	}
	return args, csv, rows
}

// The largest legal threads.csv that each costs the reader most per byte, as this library's writer
// writes it, each within the same 9x: every topic a run of line feeds (or tabs), which the answer
// writes as two bytes each, and every thread removed under ONE root with two names of 200 characters,
// which the reader compares rather than keeps.
func TestTheCostliestLargestFilesAllocateWithinTheirBounds(t *testing.T) {
	for _, c := range []struct {
		what string
		edit func(i int, th map[string]any)
	}{
		{"every topic 1000 line feeds", func(i int, th map[string]any) { th["topic"] = strings.Repeat("\n", 1000) }},
		{"every topic 1000 tabs", func(i int, th map[string]any) { th["topic"] = "a" + strings.Repeat("\t", 1000) }},
		{"every thread removed under one root, names of 200 characters", func(i int, th map[string]any) {
			th["contact"], th["contact_name"], th["contact_display_name"] = memFP(1000), strings.Repeat("n", 200), strings.Repeat("d", 200)
		}},
	} {
		args, csv, rows := memLargest(t, c.edit)
		n, out := memOf(t, "export_read", args)
		if strings.Contains(string(out[:min(len(out), 100)]), `"error"`) {
			t.Fatal(string(out[:200]))
		}
		t.Logf("export_read of the largest threads.csv, %s (%d threads, %d bytes): %.1f MB allocated, %.2fx", c.what, rows, csv, float64(n)/1e6, float64(n)/float64(csv))
		if n > 9*uint64(csv) {
			t.Errorf("%s: %.2fx the CSV, over 9x", c.what, float64(n)/float64(csv))
		}
	}
}

func TestTheLargestFilesAllocateWithinTheirBounds(t *testing.T) {
	rows := (16*1024*1024 - 2048) / 139
	args, csvBytes := memReadArgs(t, rows)
	if csvBytes > 16*1024*1024 || csvBytes < 16*1024*1024-64*1024 {
		t.Fatalf("threads.csv is %d bytes, not the largest the bound allows", csvBytes)
	}
	n, _ := memOf(t, "export_read", args)
	t.Logf("export_read of the largest threads.csv (%d threads, %d bytes): %.1f MB allocated, %.2fx", rows, csvBytes, float64(n)/1e6, float64(n)/float64(csvBytes))
	if n > 9*uint64(csvBytes) {
		t.Errorf("%.2fx the CSV, over 9x", float64(n)/float64(csvBytes))
	}

	// The same, every thread removed with a root of its own (SPEC §9.2): what the reader keeps of a
	// removed thread at the largest legal threads.csv.
	rrows := (16*1024*1024 - 2048) / 141
	rargs, rcsv := memReadArgsOf(t, rrows, true)
	if rcsv > 16*1024*1024 || rcsv < 16*1024*1024-64*1024 {
		t.Fatalf("threads.csv of removed threads is %d bytes, not the largest the bound allows", rcsv)
	}
	rn, _ := memOf(t, "export_read", rargs)
	t.Logf("export_read of the largest threads.csv of removed threads (%d threads, %d bytes): %.1f MB allocated, %.2fx", rrows, rcsv, float64(rn)/1e6, float64(rn)/float64(rcsv))
	if rn > 9*uint64(rcsv) {
		t.Errorf("removed threads: %.2fx the CSV, over 9x", float64(rn)/float64(rcsv))
	}

	threads, roots := []string{}, []string{}
	for i := 0; i < 2000; i++ {
		threads = append(threads, memUUID(i))
	}
	for i := 0; i < 200; i++ {
		roots = append(roots, memFP(i))
	}
	body := strings.Repeat("x", 120)
	var worst uint64
	bytes, line := 0, 0
	for bytes < 64*1024*1024 {
		lines := []string{}
		for k := 0; k < 500 && bytes < 64*1024*1024; k++ {
			l, _ := json.Marshal(map[string]any{"id": memUUID(1_000_000 + line), "thread": threads[line%2000], "contact": roots[(line%2000)%200],
				"msg_id": fmt.Sprintf("x%d", line), "direction": "in", "sender": "human", "time": "2026-09-01T00:00:00Z", "body": body,
				"reply_to": nil, "status": "read", "attachments": []any{}})
			lines = append(lines, string(l))
			bytes += len(l) + 1
			line++
		}
		batch, _ := json.Marshal(map[string]any{"lines": lines, "threads": threads, "contacts": roots, "media": []string{}, "first_line": line - len(lines) + 1})
		n, out := memOf(t, "export_read_messages", batch)
		if strings.Contains(string(out[:min(len(out), 40)]), `"error"`) {
			t.Fatal(string(out))
		}
		worst = max(worst, n)
	}
	t.Logf("export_read_messages over %d bytes (%d lines) in batches of 500: %.1f MB allocated by the costliest batch", bytes, line, float64(worst)/1e6)
	if worst > 8*1024*1024 {
		t.Errorf("a batch of 500 lines allocated %.1f MB, over 8 MiB", float64(worst)/1e6)
	}
}

// memControlArgs is memReadArgsOf's file of removed threads with every topic and both names of every
// thread `per` characters U+0001 (each six bytes as JSON: \u0001), the manifest re-hashed: what a writer no
// longer writes, and a reader is handed all the same.
func memControlArgs(t *testing.T, rows, per int) ([]byte, int) {
	return memControlArgsOn(t, rows, per, -1)
}

// memControlArgsOn is memControlArgs with only the first `on` rows so written (-1: every row).
func memControlArgsOn(t *testing.T, rows, per, on int) ([]byte, int) {
	args, _ := memReadArgsOf(t, rows, true)
	var a map[string]any
	if err := json.Unmarshal(args, &a); err != nil {
		t.Fatal(err)
	}
	c := strings.Repeat("\x01", per)
	csv := a["threads_csv"].(string)
	csv = strings.Replace(csv, ",a topic,", ","+c+",", on)
	csv = strings.Replace(csv, ",,\r\n", ","+c+","+c+"\r\n", on)
	a["threads_csv"] = csv
	out, _ := json.Marshal(a)
	return memRewrite(t, out, func(s string) string { return s })
}

// memRewrite is export_read's arguments with threads.csv rewritten by `change` and the manifest
// re-hashed for it.
func memRewrite(t *testing.T, args []byte, change func(string) string) ([]byte, int) {
	var a map[string]any
	if err := json.Unmarshal(args, &a); err != nil {
		t.Fatal(err)
	}
	csv := change(a["threads_csv"].(string))
	var m map[string]any
	if err := json.Unmarshal([]byte(a["manifest"].(string)), &m); err != nil {
		t.Fatal(err)
	}
	s := sha256.Sum256([]byte(csv))
	m["files"].(map[string]any)["threads.csv"] = hex.EncodeToString(s[:])
	a["threads_csv"], a["manifest"] = csv, string(Canonical(m))
	out, _ := json.Marshal(a)
	return out, len(csv)
}

// A member dense with U+0001, which a JSON answer writes as six bytes each, is refused before it is
// parsed, at N and 4N rows and at the largest the format allows; one at the ceiling (ExportControlMax)
// is read. Such a file reaches the reader as an argument some six times its CSV (each U+0001 is
// \u0001 in the argument's JSON too, which the host wrote), so its cost is held per byte of that
// argument: the call decodes the argument once, at most 3 bytes per byte of it. Before the ceiling a
// threads.csv of removed threads named and titled with U+0001 allocated some 30× its CSV, 5× its
// argument, building an answer as large again.
func TestControlCharactersAreBoundedWhereTheyEnter(t *testing.T) {
	for _, rows := range []int{4000, 16000, (16*1024*1024 - 2048) / 741} {
		args, csvBytes := memControlArgs(t, rows, 200)
		n, out := memOf(t, "export_read", args)
		if !strings.Contains(string(out), "characters below U+0020") {
			t.Fatalf("%d rows of control characters: %s", rows, string(out[:min(len(out), 200)]))
		}
		t.Logf("export_read refusing %d threads dense with U+0001 (%d bytes of threads.csv, %d of argument): %.1f MB allocated, %.2fx the argument", rows, csvBytes, len(args), float64(n)/1e6, float64(n)/float64(len(args)))
		if n > 3*uint64(len(args)) {
			t.Errorf("%d rows: %.2fx the argument, over 3x", rows, float64(n)/float64(len(args)))
		}
	}
	// At the ceiling: 64,000 threads, a topic and two names of one U+0001 each on as many of them as
	// the ceiling takes.
	rows := 64000
	args, csvBytes := memControlArgsOn(t, rows, 1, ExportControlMax/3)
	args, csvBytes = memRewrite(t, args, func(csv string) string {
		return strings.Replace(csv, ",a topic,", ","+strings.Repeat("\x01", ExportControlMax-3*(ExportControlMax/3))+",", 1)
	})
	n, out := memOf(t, "export_read", args)
	if strings.Contains(string(out[:min(len(out), 100)]), `"error"`) {
		t.Fatal(string(out[:200]))
	}
	t.Logf("export_read of %d threads holding %d control characters (%d bytes of threads.csv): %.2fx", rows, ExportControlMax, csvBytes, float64(n)/float64(csvBytes))
	if n > 9*uint64(csvBytes) {
		t.Errorf("at the ceiling: %.2fx the CSV, over 9x", float64(n)/float64(csvBytes))
	}
}
