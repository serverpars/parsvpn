package tui

import (
	"regexp"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

var (
	accent = lipgloss.AdaptiveColor{Light: "#0E6B66", Dark: "#3FC1B5"}
	subtle = lipgloss.AdaptiveColor{Light: "#666666", Dark: "#8A8A8A"}

	errStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("9")).Bold(true)
	okStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("10"))
	busyStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("11"))
	keyStyle    = lipgloss.NewStyle().Foreground(accent).Bold(true)
	labelStyle  = lipgloss.NewStyle().Foreground(subtle)
	panelStyle  = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(subtle).Padding(0, 1)
	sectionHead = lipgloss.NewStyle().Foreground(accent).Bold(true)
)

// helpKeyRE matches one "[key] description" pair in a help string.
var helpKeyRE = regexp.MustCompile(`\[([^\]]+)\]\s*([^\[]*)`)

// help renders "[k] Desc  [k2] Desc2" with highlighted keys, wrapped to the
// terminal width so long key lists stay readable on narrow terminals.
func (m model) help(s string) string {
	matches := helpKeyRE.FindAllStringSubmatch(s, -1)
	if len(matches) == 0 {
		return helpStyle.Render(s)
	}
	width := m.width
	if width <= 0 {
		width = 100
	}
	var lines []string
	var line strings.Builder
	lineLen := 0
	for _, mt := range matches {
		desc := strings.TrimSpace(mt[2])
		plainLen := len(mt[1]) + 1 + len(desc) + 3
		if lineLen > 0 && lineLen+plainLen > width {
			lines = append(lines, line.String())
			line.Reset()
			lineLen = 0
		}
		if lineLen > 0 {
			line.WriteString(helpStyle.Render(" · "))
		}
		line.WriteString(keyStyle.Render(mt[1]) + " " + helpStyle.Render(desc))
		lineLen += plainLen
	}
	if line.Len() > 0 {
		lines = append(lines, line.String())
	}
	return strings.Join(lines, "\n")
}

// messages renders the busy spinner, success notice and error lines shared by
// every screen. Empty when there is nothing to report.
func (m model) messages() string {
	var out []string
	if m.busy != "" {
		out = append(out, busyStyle.Render(m.spin.View()+" "+m.busy))
	}
	if m.notice != "" {
		out = append(out, okStyle.Render("✓ "+m.notice))
	}
	if m.err != "" {
		out = append(out, errStyle.Render("✗ "+m.err))
	}
	if len(out) == 0 {
		return ""
	}
	return "\n" + strings.Join(out, "\n") + "\n"
}

// kv renders an aligned "label  value" detail line.
func kv(label, value string) string {
	return labelStyle.Render(padRight(label, 11)) + value + "\n"
}

func padRight(s string, n int) string {
	if len(s) >= n {
		return s + " "
	}
	return s + strings.Repeat(" ", n-len(s))
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// withBusy starts cmd with a spinner labelled label; the matching done
// message clears it.
func (m model) withBusy(label string, cmd tea.Cmd) (tea.Model, tea.Cmd) {
	m.busy = label
	m.err = ""
	m.notice = ""
	return m, tea.Batch(cmd, m.spin.Tick)
}
