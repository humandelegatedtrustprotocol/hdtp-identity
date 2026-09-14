// pact-identity-go is the stdin adapter of the Go port: one JSON request {"fn": name, "args": {...}} in,
// one JSON answer out. With --stream it reads one request per line and answers one line each, so a
// driver can keep one process open. It always exits 0; every failure is in the JSON.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"

	pact "github.com/tech-sumit/pact-gateway/pact-identity"
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
	return pact.Call(r.Fn, r.Args)
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "--stream" {
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
	body, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Println(`{"error":"internal","why":"cannot read stdin"}`)
		return
	}
	os.Stdout.Write(answer(body))
	os.Stdout.Write([]byte("\n"))
}
