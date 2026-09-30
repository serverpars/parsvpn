package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/serverpars/parsvpn/internal/constants"
	"github.com/serverpars/parsvpn/internal/ipc"
	"github.com/serverpars/parsvpn/internal/profile"
)

var (
	titleStyle  = lipgloss.NewStyle().Bold(true)
	statusOn    = lipgloss.NewStyle().Foreground(lipgloss.Color("10")).Bold(true)
	statusOff   = lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
	helpStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
	detailStyle = lipgloss.NewStyle().PaddingLeft(2)
)

type item struct {
	name   string
	active bool
}

func (i item) Title() string {
	if i.active {
		return "* " + i.name
	}
	return "  " + i.name
}
func (i item) Description() string { return "" }
func (i item) FilterValue() string { return i.name }

type model struct {
	list   list.Model
	status ipc.StatusPayload
	err    string
	width  int
	height int
}

type tickMsg struct{}

type statusMsg struct {
	st  ipc.StatusPayload
	err error
}

func Run() error {
	names, err := profile.List()
	if err != nil {
		return err
	}
	st, _ := fetchStatus()
	items := make([]list.Item, 0, len(names))
	for _, n := range names {
		items = append(items, item{name: n, active: st.Active && st.Profile == n})
	}
	delegate := list.NewDefaultDelegate()
	delegate.ShowDescription = false
	l := list.New(items, delegate, 30, 12)
	l.Title = "Profiles"
	l.SetShowHelp(false)
	l.SetShowStatusBar(false)
	m := model{list: l, status: st}
	_, err = tea.NewProgram(m, tea.WithAltScreen()).Run()
	return err
}

func (m model) Init() tea.Cmd {
	return tea.Batch(refreshStatus, scheduleTick())
}

func scheduleTick() tea.Cmd {
	return tea.Tick(time.Duration(constants.HandshakePollIntervalSec)*time.Second, func(time.Time) tea.Msg {
		return tickMsg{}
	})
}

func refreshStatus() tea.Msg {
	st, err := fetchStatus()
	return statusMsg{st: st, err: err}
}

func fetchStatus() (ipc.StatusPayload, error) {
	resp, err := ipc.Call(ipc.Request{Cmd: "status"})
	if err != nil {
		return ipc.StatusPayload{}, err
	}
	if resp.Status == nil {
		return ipc.StatusPayload{}, nil
	}
	return *resp.Status, nil
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.list.SetSize(max(20, msg.Width/2-2), max(5, msg.Height-8))
	case tickMsg:
		return m, tea.Batch(refreshStatus, scheduleTick())
	case statusMsg:
		if msg.err != nil {
			m.err = msg.err.Error()
		} else {
			m.err = ""
			m.status = msg.st
			m.syncActiveFlags()
		}
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case " ":
			it, ok := m.list.SelectedItem().(item)
			if !ok {
				return m, nil
			}
			return m, toggleProfile(it.name, m.status.Active && m.status.Profile == it.name)
		case "r":
			return m, refreshStatus
		}
	}
	var cmd tea.Cmd
	m.list, cmd = m.list.Update(msg)
	return m, cmd
}

func toggleProfile(name string, isActive bool) tea.Cmd {
	return func() tea.Msg {
		var resp *ipc.Response
		var err error
		if isActive {
			resp, err = ipc.Call(ipc.Request{Cmd: "down"})
		} else {
			resp, err = ipc.Call(ipc.Request{Cmd: "up", Profile: name})
		}
		if err != nil {
			return statusMsg{err: err}
		}
		if !resp.OK {
			return statusMsg{err: fmt.Errorf("%s", resp.Error)}
		}
		if resp.Status != nil {
			return statusMsg{st: *resp.Status}
		}
		return refreshStatus()
	}
}

func (m *model) syncActiveFlags() {
	items := m.list.Items()
	for i, it := range items {
		if ii, ok := it.(item); ok {
			ii.active = m.status.Active && m.status.Profile == ii.name
			items[i] = ii
		}
	}
	m.list.SetItems(items)
}

func (m model) View() string {
	statusLine := statusOff.Render("[STATUS: INACTIVE]")
	if m.status.Active {
		statusLine = statusOn.Render(fmt.Sprintf("[STATUS: ACTIVE -> %s]", m.status.Interface))
	}
	header := titleStyle.Render(fmt.Sprintf("parsvpn %s", constants.Version)) + "   " + statusLine

	var detail strings.Builder
	if m.status.Active {
		detail.WriteString(fmt.Sprintf("Endpoint:  %s\n", m.status.Endpoint))
		detail.WriteString(fmt.Sprintf("Local IP:  %s\n", m.status.Address))
		detail.WriteString(fmt.Sprintf("Handshake: %s\n", m.status.Handshake))
		detail.WriteString(fmt.Sprintf("Transfer:  %s RX / %s TX\n", humanBytes(m.status.RxBytes), humanBytes(m.status.TxBytes)))
		detail.WriteString("----------------------------------------------\n")
		detail.WriteString(fmt.Sprintf("Split IPs: %s\n", strings.Join(m.status.SplitIPs, ", ")))
		if len(m.status.Overrides) > 0 {
			detail.WriteString("Host Overrides:\n")
			for _, o := range m.status.Overrides {
				detail.WriteString("  " + o + "\n")
			}
		}
	} else {
		detail.WriteString("No active tunnel.\nSelect a profile and press Space to connect.\n")
	}
	if m.err != "" {
		detail.WriteString("\nError: " + m.err + "\n")
	}

	body := lipgloss.JoinHorizontal(lipgloss.Top, m.list.View(), detailStyle.Render(detail.String()))
	help := helpStyle.Render("[Space] Toggle  [r] Refresh  [q] Quit")
	return header + "\n\n" + body + "\n\n" + help
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTPE"[exp])
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
