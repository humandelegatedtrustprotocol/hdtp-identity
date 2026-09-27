package pactidentity

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
func memReadArgs(t *testing.T, rows int) ([]byte, int) {
	owner := "sha256:" + strings.Repeat("O", 43)
	contacts := []any{}
	for i := 0; i < 200; i++ {
		contacts = append(contacts, map[string]any{"root": memFP(i), "endpoint": fmt.Sprintf("https://c%d.example/mcp", i), "name": "",
			"display_name": "", "status": "active", "was_active": true, "permissions": []any{}, "their_permissions": []any{}, "added": "2026-09-01T00:00:00Z"})
	}
	threads := []any{}
	for i := 0; i < rows; i++ {
		threads = append(threads, map[string]any{"id": memUUID(i), "contact": memFP(i % 200), "topic": "a topic",
			"created_at": "2026-09-01T00:00:00Z", "last_at": "2026-09-01T00:00:00Z"})
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
	for _, rows := range []int{16000, 64000} {
		args, csvBytes := memReadArgs(t, rows)
		n, out := memOf(t, "export_read", args)
		if strings.Contains(string(out[:min(len(out), 100)]), `"error"`) {
			t.Fatal(string(out[:200]))
		}
		t.Logf("export_read, %d threads (%d bytes of threads.csv): %d bytes allocated, %d per row, %.2fx the CSV", rows, csvBytes, n, n/uint64(rows), float64(n)/float64(csvBytes))
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
		manifest, _ := json.Marshal(map[string]any{"pact_export": 2, "owner": "sha256:" + strings.Repeat("O", 43), "owner_name": "", "exported_at": "2026-09-27T00:00:00Z",
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
