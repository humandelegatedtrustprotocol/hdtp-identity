// Command gen writes the export corpus into the directory above it: `go run ./exportcorpus/gen`
// from go/. The files are what exportcorpus.Build makes, and a test holds the committed ones to it.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/humandelegatedtrustprotocol/hdtp-identity/go/exportcorpus"
)

func main() {
	files, err := exportcorpus.Build()
	if err != nil {
		fmt.Fprintln(os.Stderr, "gen:", err)
		os.Exit(1)
	}
	dir := "exportcorpus"
	if len(os.Args) > 1 {
		dir = os.Args[1]
	}
	old, _ := filepath.Glob(filepath.Join(dir, "*.zip"))
	for _, f := range old {
		if _, kept := files[filepath.Base(f)]; !kept {
			if err := os.Remove(f); err != nil {
				fmt.Fprintln(os.Stderr, "gen:", err)
				os.Exit(1)
			}
		}
	}
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	total := 0
	for _, n := range names {
		if err := os.WriteFile(filepath.Join(dir, n), files[n], 0o644); err != nil {
			fmt.Fprintln(os.Stderr, "gen:", err)
			os.Exit(1)
		}
		total += len(files[n])
	}
	fmt.Printf("wrote %d files, %d bytes, into %s (%s)\n", len(names), total, dir, strings.Join(names[:3], ", ")+", …")
}
