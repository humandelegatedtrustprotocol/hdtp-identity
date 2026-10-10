//go:build unix

package hdtpidentity

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"runtime"
	"runtime/debug"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The export's functions grow linearly in the rows a file holds. Each is timed at N and 4N rows
// (threads, messages, and held and imported contacts), the two sizes interleaved over five rounds,
// the best round of each kept; 4N may take at most 8× N. Why 8: linear work is 4×, n·log n about
// 4.6×, and a scan per row 16× — the defect of 0.3.0, where export_read took 0.2 s at 2k threads
// and 11 s at 16k in the Wasm core. 8 is halfway (in log terms) between linear and quadratic: a 2×
// margin for noise that no quadratic fits in. A function under 20 ms at 4N is too fast to judge and
// passes. The bound is on rows and a ratio, never on seconds, so it cannot go stale with the
// machine.
//
// The time is the process's CPU time (getrusage), not the wall clock, with the collector off while
// a function runs and a collection before each: the bound is on the functions' own work. On the wall
// clock, with 24 busy processes beside the test, the bound failed 10 runs of 10 at ratios up to 31×
// for unchanged code; on CPU time with the collector running it failed 3 of 50, export_read_messages
// at 8.1× to 8.3× (5.7× on an idle machine), and 4.0× with the collector off. The Rust core's
// export_functions_grow_linearly_in_the_rows_of_a_file holds the same bound on the wall clock.
func TestExportFunctionsGrowLinearlyInTheRowsOfAFile(t *testing.T) {
	const n = 5000
	owner := "sha256:" + strings.Repeat("O", 42) + "A"
	fp := func(i int) string {
		s := sha256.Sum256([]byte(fmt.Sprintf("c%d", i)))
		return "sha256:" + base64.RawURLEncoding.EncodeToString(s[:])
	}
	contacts := []any{}
	roots := []string{}
	for i := 0; i < 200; i++ {
		contacts = append(contacts, map[string]any{"root": fp(i), "endpoint": fmt.Sprintf("https://c%d.example/mcp", i), "name": "",
			"display_name": "", "status": "active", "was_active": true, "permissions": []any{}, "their_permissions": []any{}, "added": "2026-09-01T00:00:00Z"})
		roots = append(roots, fp(i))
	}
	type data struct {
		rows                             int
		threads, messages, many          []any
		threadIDs, ids, msgIDs, replyTos []string
	}
	make1 := func(rows int) data {
		d := data{rows: rows}
		for i := 0; i < rows; i++ {
			d.threads = append(d.threads, map[string]any{"id": fmt.Sprintf("t%d", i), "contact": fp(i % 200), "topic": "x",
				"created_at": "2026-09-01T00:00:00Z", "last_at": "2026-09-01T00:00:00Z"})
			var reply any
			if i > 0 {
				reply = fmt.Sprintf("x%d", i-1)
				d.replyTos = append(d.replyTos, fmt.Sprintf("x%d", i-1))
			}
			d.messages = append(d.messages, map[string]any{"id": fmt.Sprintf("m%d", i), "thread": fmt.Sprintf("t%d", i), "contact": fp(i % 200),
				"msg_id": fmt.Sprintf("x%d", i), "direction": "in", "sender": "human", "time": "2026-09-01T00:00:00Z", "body": "hi",
				"reply_to": reply, "status": "read", "attachments": []any{}})
			d.many = append(d.many, map[string]any{"root": fp(1000 + i), "leaf": nil})
			d.threadIDs = append(d.threadIDs, fmt.Sprintf("t%d", i))
			d.ids = append(d.ids, fmt.Sprintf("m%d", i))
			d.msgIDs = append(d.msgIDs, fmt.Sprintf("x%d", i))
		}
		return d
	}
	directory := []ExportEntry{{Name: "manifest.json", Size: 1}, {Name: "contacts.csv", Size: 1}, {Name: "threads.csv", Size: 1}}
	hash := strings.Repeat("a", 64)
	must := func(err error) {
		if err != nil {
			t.Fatal(err)
		}
	}
	cpu := func() float64 {
		var ru syscall.Rusage
		must(syscall.Getrusage(syscall.RUSAGE_SELF, &ru))
		return float64(ru.Utime.Nano()+ru.Stime.Nano()) / 1e9
	}
	start := func() float64 {
		runtime.GC()
		return cpu()
	}
	defer debug.SetGCPercent(debug.SetGCPercent(-1))
	pass := func(d data) [6]float64 {
		var out [6]float64
		clock := start()
		w, err := exportWrite(owner, "", time.Unix(0, 0), "t", contacts, d.threads, nil)
		must(err)
		out[0] = cpu() - clock
		partial, _ := json.Marshal(w.partial)
		manifest, err := finishManifest(partial, nil, 0)
		must(err)
		clock = start()
		_, err = exportRead(directory, &manifest, &w.contactsCSV, w.threadsCSV, owner, time.Unix(0, 0))
		must(err)
		out[1] = cpu() - clock
		clock = start()
		lines, _, err := exportWriteMessages(d.messages, nil)
		must(err)
		out[2] = cpu() - clock
		clock = start()
		_, _, err = exportReadMessages(lines, 1, messageNames{threads: setOf(d.threadIDs), contacts: setOf(roots), media: strSet{}})
		must(err)
		out[3] = cpu() - clock
		withMessages, err := finishManifest(partial, &hash, uint64(d.rows))
		must(err)
		clock = start()
		must(exportReadEnd(withMessages, exportEnd{messagesSHA256: &hash, lines: uint64(d.rows), ids: d.ids, msgIDs: d.msgIDs, replyTos: d.replyTos, mediaSeen: []string{}}))
		out[4] = cpu() - clock
		clock = start()
		_, _, _, err = exportMerge(d.many, d.many)
		must(err)
		out[5] = cpu() - clock
		return out
	}
	names := []string{"export_write", "export_read", "export_write_messages", "export_read_messages", "export_read_end", "export_merge"}
	small, large := make1(n), make1(4*n)
	var a, b [6]float64
	for k := range a {
		a[k], b[k] = math.MaxFloat64, math.MaxFloat64
	}
	for round := 0; round < 5; round++ {
		for k, v := range pass(small) {
			a[k] = math.Min(a[k], v)
		}
		for k, v := range pass(large) {
			b[k] = math.Min(b[k], v)
		}
	}
	for k := range names {
		line := fmt.Sprintf("%s: %.1f ms at %d rows, %.1f ms at %d (%.1f×)", names[k], a[k]*1e3, n, b[k]*1e3, 4*n, b[k]/a[k])
		t.Log(line)
		if b[k] >= 0.020 && b[k]/a[k] > 8 {
			t.Errorf("superlinear in the rows of a file: %s", line)
		}
	}
}
