// `colimander logs` — a live TUI over the broker audit log.
//
// Reads ~/.colimander/audit.log (JSONL of auditEntry) and follows it as the
// broker appends, so you can watch git/API operations flow through the proxy
// in real time. Pure log *viewer*: it never talks to the broker process, so
// it works whether or not the broker is up, and can replay history offline.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

const logsPollInterval = 500 * time.Millisecond

// ------------------------------ file tailing -------------------------------

// readAuditFrom parses complete JSONL lines starting at offset and returns the
// entries plus the offset just past the last complete line. Incomplete trailing
// data (a line the broker is mid-write on) is left for the next poll. If the
// file shrank below offset (rotation/truncation), it rereads from the start.
func readAuditFrom(path string, offset int64) ([]auditEntry, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, 0, nil
		}
		return nil, offset, err
	}
	defer f.Close()

	st, err := f.Stat()
	if err != nil {
		return nil, offset, err
	}
	if st.Size() < offset {
		offset = 0
	}
	if st.Size() == offset {
		return nil, offset, nil
	}
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return nil, offset, err
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, offset, err
	}
	last := strings.LastIndexByte(string(data), '\n')
	if last < 0 {
		return nil, offset, nil
	}
	var out []auditEntry
	for _, line := range strings.Split(string(data[:last]), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var e auditEntry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			continue // tolerate the odd corrupt line rather than dying mid-watch
		}
		out = append(out, e)
	}
	return out, offset + int64(last) + 1, nil
}

// ------------------------------ bubbletea model ----------------------------

type logsTickMsg struct{}

type logsModel struct {
	path    string
	offset  int64
	limit   int
	entries []auditEntry

	profiles    []string // unique profiles seen, sorted; drives the `p` cycle
	profileIdx  int      // 0 = all, else profiles[profileIdx-1]
	surfaceIdx  int      // 0 = all, 1 = GIT, 2 = API
	actionIdx   int      // 0 = all, 1 = ALLOW, 2 = DENY
	search      string
	searchInput string
	searching   bool
	follow      bool
	fromBottom  int // scroll offset in rows when not following

	width, height int
	err           error
}

var (
	logsHeaderStyle = lipgloss.NewStyle().Bold(true).Underline(true)
	logsDimStyle    = lipgloss.NewStyle().Faint(true)
	logsDenyStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("9")).Bold(true)
	logsAllowStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("10"))
	logsGitStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("14"))
	logsAPIStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("13"))
	logsBarStyle    = lipgloss.NewStyle().Reverse(true)
)

func newLogsModel(path string, limit int) logsModel {
	return logsModel{path: path, limit: limit, follow: true, width: 80, height: 24}
}

func logsTick() tea.Cmd {
	return tea.Tick(logsPollInterval, func(time.Time) tea.Msg { return logsTickMsg{} })
}

func (m logsModel) Init() tea.Cmd {
	return func() tea.Msg { return logsTickMsg{} }
}

func (m *logsModel) ingest() {
	fresh, off, err := readAuditFrom(m.path, m.offset)
	m.err = err
	m.offset = off
	if len(fresh) == 0 {
		return
	}
	m.entries = append(m.entries, fresh...)
	if len(m.entries) > m.limit {
		m.entries = m.entries[len(m.entries)-m.limit:]
	}
	seen := map[string]bool{}
	for _, p := range m.profiles {
		seen[p] = true
	}
	for _, e := range fresh {
		if !seen[e.Profile] {
			seen[e.Profile] = true
			m.profiles = append(m.profiles, e.Profile)
		}
	}
	sort.Strings(m.profiles)
}

func (m logsModel) filtered() []auditEntry {
	surface := [...]string{"", "GIT", "API"}[m.surfaceIdx]
	action := [...]string{"", "ALLOW", "DENY"}[m.actionIdx]
	profile := ""
	if m.profileIdx > 0 && m.profileIdx <= len(m.profiles) {
		profile = m.profiles[m.profileIdx-1]
	}
	needle := strings.ToLower(m.search)
	var out []auditEntry
	for _, e := range m.entries {
		if profile != "" && e.Profile != profile {
			continue
		}
		if surface != "" && e.Surface != surface {
			continue
		}
		// The "DENY" slot means "anything that wasn't allowed" — policy
		// denials and auth failures alike.
		if action == "ALLOW" && e.Action != "ALLOW" {
			continue
		}
		if action == "DENY" && e.Action == "ALLOW" {
			continue
		}
		if needle != "" &&
			!strings.Contains(strings.ToLower(e.Path), needle) &&
			!strings.Contains(strings.ToLower(e.Detail), needle) &&
			!strings.Contains(strings.ToLower(e.Method), needle) {
			continue
		}
		out = append(out, e)
	}
	return out
}

func (m logsModel) visibleRows() int {
	// Two chrome lines: column header + status bar.
	if m.height <= 2 {
		return 1
	}
	return m.height - 2
}

func (m logsModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		return m, nil

	case logsTickMsg:
		m.ingest()
		return m, logsTick()

	case tea.KeyMsg:
		if m.searching {
			switch msg.String() {
			case "enter":
				m.search = m.searchInput
				m.searching = false
			case "esc":
				m.searching = false
				m.searchInput = ""
			case "backspace":
				if len(m.searchInput) > 0 {
					m.searchInput = m.searchInput[:len(m.searchInput)-1]
				}
			case "ctrl+c":
				return m, tea.Quit
			default:
				if msg.Type == tea.KeyRunes || msg.Type == tea.KeySpace {
					m.searchInput += msg.String()
				}
			}
			return m, nil
		}
		maxUp := len(m.filtered()) - m.visibleRows()
		if maxUp < 0 {
			maxUp = 0
		}
		switch msg.String() {
		case "q", "ctrl+c", "esc":
			return m, tea.Quit
		case "f":
			m.follow = true
			m.fromBottom = 0
		case "p":
			m.profileIdx = (m.profileIdx + 1) % (len(m.profiles) + 1)
			m.fromBottom = 0
		case "s":
			m.surfaceIdx = (m.surfaceIdx + 1) % 3
			m.fromBottom = 0
		case "a":
			m.actionIdx = (m.actionIdx + 1) % 3
			m.fromBottom = 0
		case "c":
			m.profileIdx, m.surfaceIdx, m.actionIdx, m.search = 0, 0, 0, ""
			m.fromBottom = 0
		case "/":
			m.searching = true
			m.searchInput = m.search
		case "k", "up":
			m.follow = false
			if m.fromBottom < maxUp {
				m.fromBottom++
			}
		case "j", "down":
			m.follow = false
			if m.fromBottom > 0 {
				m.fromBottom--
			}
		case "pgup":
			m.follow = false
			m.fromBottom = min(maxUp, m.fromBottom+m.visibleRows())
		case "pgdown":
			m.follow = false
			m.fromBottom = max(0, m.fromBottom-m.visibleRows())
		case "g":
			m.follow = false
			m.fromBottom = maxUp
		case "G":
			m.follow = true
			m.fromBottom = 0
		}
	}
	return m, nil
}

func logsTruncate(s string, w int) string {
	if w <= 0 {
		return ""
	}
	r := []rune(s)
	if len(r) <= w {
		return s + strings.Repeat(" ", w-len(r))
	}
	if w == 1 {
		return "…"
	}
	return string(r[:w-1]) + "…"
}

func (m logsModel) View() string {
	rows := m.filtered()
	visible := m.visibleRows()

	fromBottom := m.fromBottom
	if m.follow {
		fromBottom = 0
	}
	end := len(rows) - fromBottom
	start := end - visible
	if start < 0 {
		start = 0
	}

	// Fixed columns; whatever is left splits ~60/40 between path and detail.
	const wTime, wProf, wSurf, wMeth, wAct = 8, 14, 4, 6, 5
	rest := m.width - (wTime + wProf + wSurf + wMeth + wAct + 5)
	if rest < 20 {
		rest = 20
	}
	wPath := rest * 3 / 5
	wDetail := rest - wPath

	var b strings.Builder
	b.WriteString(logsHeaderStyle.Render(fmt.Sprintf("%s %s %s %s %s %s %s",
		logsTruncate("TIME", wTime), logsTruncate("PROFILE", wProf),
		logsTruncate("SURF", wSurf), logsTruncate("METHOD", wMeth),
		logsTruncate("ACT", wAct), logsTruncate("PATH", wPath),
		logsTruncate("DETAIL", wDetail))))
	b.WriteString("\n")

	for i := start; i < end; i++ {
		e := rows[i]
		surfStyle := logsGitStyle
		if e.Surface == "API" {
			surfStyle = logsAPIStyle
		}
		actStyle := logsAllowStyle
		if e.Action != "ALLOW" {
			actStyle = logsDenyStyle
		}
		line := fmt.Sprintf("%s %s %s %s %s %s %s",
			logsDimStyle.Render(logsTruncate(e.Time.Local().Format("15:04:05"), wTime)),
			logsTruncate(e.Profile, wProf),
			surfStyle.Render(logsTruncate(e.Surface, wSurf)),
			logsTruncate(e.Method, wMeth),
			actStyle.Render(logsTruncate(e.Action, wAct)),
			logsTruncate(e.Path, wPath),
			logsDimStyle.Render(logsTruncate(e.Detail, wDetail)))
		b.WriteString(line)
		b.WriteString("\n")
	}
	for i := end - start; i < visible; i++ {
		b.WriteString("\n")
	}

	filters := []string{}
	if m.profileIdx > 0 && m.profileIdx <= len(m.profiles) {
		filters = append(filters, "profile="+m.profiles[m.profileIdx-1])
	}
	if m.surfaceIdx > 0 {
		filters = append(filters, "surface="+[...]string{"", "GIT", "API"}[m.surfaceIdx])
	}
	if m.actionIdx > 0 {
		filters = append(filters, "action="+[...]string{"", "ALLOW", "DENY/AUTH"}[m.actionIdx])
	}
	if m.search != "" {
		filters = append(filters, fmt.Sprintf("search=%q", m.search))
	}
	filterStr := "no filters"
	if len(filters) > 0 {
		filterStr = strings.Join(filters, "  ")
	}
	mode := "SCROLL"
	if m.follow {
		mode = "FOLLOW"
	}
	status := fmt.Sprintf(" %s │ %d/%d entries │ %s │ p/s/a filter · / search · c clear · f follow · q quit ",
		mode, len(rows), len(m.entries), filterStr)
	if m.searching {
		status = fmt.Sprintf(" search: %s█  (enter apply · esc cancel) ", m.searchInput)
	}
	if m.err != nil {
		status = fmt.Sprintf(" read error: %v ", m.err)
	}
	b.WriteString(logsBarStyle.Render(logsTruncate(status, m.width)))
	return b.String()
}

// ------------------------------ command ------------------------------------

func cmdLogs(args []string) error {
	fs := flag.NewFlagSet("logs", flag.ExitOnError)
	limit := fs.Int("limit", 5000, "max audit entries to keep in memory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected extra arguments: %v", fs.Args())
	}
	m := newLogsModel(auditFile(), *limit)
	_, err := tea.NewProgram(m, tea.WithAltScreen()).Run()
	return err
}
