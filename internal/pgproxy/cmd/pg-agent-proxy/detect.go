package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/kotisivukamu/pg-agent-proxy/internal/detect"
)

// runDetectPII connects to the upstream database and prints a suggested pii
// config block based on column-name heuristics. It never modifies anything.
func runDetectPII(args []string) {
	fs := flag.NewFlagSet("detect-pii", flag.ExitOnError)
	upstream := fs.String("upstream", "", "upstream connection string to scan (required)")
	_ = fs.Parse(args)

	if *upstream == "" {
		fmt.Fprintln(os.Stderr, "-upstream connection string is required")
		os.Exit(2)
	}

	matches, err := detect.Scan(context.Background(), *upstream)
	if err != nil {
		fmt.Fprintln(os.Stderr, "scan failed:", err)
		os.Exit(1)
	}

	if len(matches) == 0 {
		fmt.Println("# No likely PII columns detected by name heuristics.")
		return
	}

	fmt.Println("# Likely PII columns (review carefully — name heuristics only):")
	seen := map[string]bool{}
	var spec []string
	for _, m := range matches {
		fmt.Printf("#   %s.%s -> %s\n", m.Table, m.Column, m.Action)
		key := m.Column + ":" + m.Action
		if !seen[key] {
			seen[key] = true
			spec = append(spec, key)
		}
	}
	fmt.Println("\n# Pass to `connections add` with:")
	fmt.Printf("#   -pii %s\n", strings.Join(spec, ","))
}
