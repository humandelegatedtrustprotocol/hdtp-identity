// hdtp-identity-go is the stdin adapter of the Go port: one JSON request {"fn": name, "args": {...}}
// per line in, one JSON answer per line out, until stdin closes. A driver keeps one process open for
// a whole suite (js/port.mjs does); a single request piped in is the same protocol with one line. It
// always exits 0; every failure is in the JSON.
package main

import (
	"bufio"
	"encoding/json"
	"os"

	hdtp "github.com/humandelegatedtrustprotocol/hdtp-identity/go"
)

type request struct {
	Fn   string          `json:"fn"`
	Args json.RawMessage `json:"args"`
}

func answer(line []byte) []byte {
	var r request
	if err := json.Unmarshal(line, &r); err != nil {
		return []byte(`{"error":"parse","why":"request is not {\"fn\", \"args\"}"}`)
	}
	// A request with no `args` means none, `{}`, as the JS loader sends it; Call itself refuses
	// arguments with no text, as the core's `call` does.
	if r.Args == nil {
		r.Args = json.RawMessage(`{}`)
	}
	return hdtp.Call(r.Fn, r.Args)
}

func main() {
	in := bufio.NewReaderSize(os.Stdin, 1<<20)
	out := bufio.NewWriter(os.Stdout)
	for {
		line, err := in.ReadBytes('\n')
		if len(line) > 1 {
			out.Write(answer(line))
			out.WriteByte('\n')
			out.Flush()
		}
		if err != nil {
			return
		}
	}
}
