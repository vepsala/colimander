package main

import (
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/kotisivukamu/pg-agent-proxy/internal/config"
	"github.com/kotisivukamu/pg-agent-proxy/internal/policy"
	"github.com/kotisivukamu/pg-agent-proxy/internal/store"
)

// runConnections handles the `connections` subcommands.
func runConnections(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: pg-agent-proxy connections add|list|rotate|rm [flags]")
		os.Exit(2)
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "add":
		connAdd(rest)
	case "list", "ls":
		connList(rest)
	case "rotate":
		connRotate(rest)
	case "rm", "delete":
		connRemove(rest)
	default:
		fmt.Fprintf(os.Stderr, "unknown connections subcommand %q\n", sub)
		os.Exit(2)
	}
}

func openStore(cfgPath string) (*store.Store, *config.Config) {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "configuration error:", err)
		os.Exit(1)
	}
	st, err := store.Open(cfg.Database)
	if err != nil {
		fmt.Fprintln(os.Stderr, "open registry failed:", err)
		os.Exit(1)
	}
	return st, cfg
}

func connAdd(args []string) {
	fs := flag.NewFlagSet("connections add", flag.ExitOnError)
	cfgPath := fs.String("config", "config.yaml", "config file")
	name := fs.String("name", "", "connection name (required)")
	upstream := fs.String("upstream", "", "upstream connection string (required)")
	maxRows := fs.Int("max-rows", 1000, "rows above which a read needs approval (0 = unlimited)")
	gate := fs.Bool("gate", true, "require approval for mutations")
	piiSpec := fs.String("pii", "", "comma-separated PII rules, e.g. email:hash,ssn:redact,phone:hash")
	_ = fs.Parse(args)

	if *name == "" || *upstream == "" {
		fmt.Fprintln(os.Stderr, "both -name and -upstream are required")
		os.Exit(2)
	}

	st, cfg := openStore(*cfgPath)
	defer st.Close()

	conn, password, err := st.Create(store.CreateInput{
		Name:          *name,
		UpstreamURL:   *upstream,
		MaxRows:       *maxRows,
		GateMutations: *gate,
		PIIRules:      parsePII(*piiSpec),
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "create failed:", err)
		os.Exit(1)
	}

	fmt.Printf("Created connection %q (agent user: %s)\n\n", conn.Name, conn.AgentUsername)
	fmt.Println("Connection string (password shown only once):")
	fmt.Println("  " + connString(cfg.Listen, conn.AgentUsername, password))
}

func connList(args []string) {
	fs := flag.NewFlagSet("connections list", flag.ExitOnError)
	cfgPath := fs.String("config", "config.yaml", "config file")
	_ = fs.Parse(args)

	st, _ := openStore(*cfgPath)
	defer st.Close()

	conns, err := st.List()
	if err != nil {
		fmt.Fprintln(os.Stderr, "list failed:", err)
		os.Exit(1)
	}
	if len(conns) == 0 {
		fmt.Println("No connections.")
		return
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tNAME\tAGENT USER\tMAX ROWS\tGATE\tPII")
	for _, c := range conns {
		var rules []string
		for _, r := range c.PIIRules {
			rules = append(rules, r.Name+":"+r.Action)
		}
		fmt.Fprintf(tw, "%d\t%s\t%s\t%d\t%v\t%s\n", c.ID, c.Name, c.AgentUsername, c.MaxRows, c.GateMutations, strings.Join(rules, ","))
	}
	_ = tw.Flush()
}

func connRotate(args []string) {
	fs := flag.NewFlagSet("connections rotate", flag.ExitOnError)
	cfgPath := fs.String("config", "config.yaml", "config file")
	id := fs.Int64("id", 0, "connection id (required)")
	_ = fs.Parse(args)

	st, cfg := openStore(*cfgPath)
	defer st.Close()

	password, err := st.Rotate(*id)
	if err != nil {
		fmt.Fprintln(os.Stderr, "rotate failed:", err)
		os.Exit(1)
	}
	conns, _ := st.List()
	username := ""
	for _, c := range conns {
		if c.ID == *id {
			username = c.AgentUsername
		}
	}
	fmt.Println("New connection string (password shown only once):")
	fmt.Println("  " + connString(cfg.Listen, username, password))
}

func connRemove(args []string) {
	fs := flag.NewFlagSet("connections rm", flag.ExitOnError)
	cfgPath := fs.String("config", "config.yaml", "config file")
	id := fs.Int64("id", 0, "connection id (required)")
	_ = fs.Parse(args)

	st, _ := openStore(*cfgPath)
	defer st.Close()

	if err := st.Delete(*id); err != nil {
		fmt.Fprintln(os.Stderr, "delete failed:", err)
		os.Exit(1)
	}
	fmt.Println("Deleted connection", *id)
}

// parsePII parses "email:hash,ssn:redact" into rules.
func parsePII(spec string) []policy.PIIRule {
	var rules []policy.PIIRule
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name, action, ok := strings.Cut(part, ":")
		if !ok {
			action = "redact"
		}
		rules = append(rules, policy.PIIRule{Name: strings.TrimSpace(name), Action: strings.TrimSpace(action)})
	}
	return rules
}

func connString(listen, username, password string) string {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		host, port = "127.0.0.1", "6432"
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	return fmt.Sprintf("postgres://%s:%s@%s/postgres?sslmode=disable",
		url.QueryEscape(username), url.QueryEscape(password), net.JoinHostPort(host, port))
}
