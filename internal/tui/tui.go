package tui

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/filepicker"
	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/textarea"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/serverpars/parsvpn/internal/constants"
	"github.com/serverpars/parsvpn/internal/ipc"
	"github.com/serverpars/parsvpn/internal/profile"
	"github.com/serverpars/parsvpn/internal/update"
)

var (
	titleStyle  = lipgloss.NewStyle().Bold(true)
	statusOn    = lipgloss.NewStyle().Foreground(lipgloss.Color("10")).Bold(true)
	statusOff   = lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
	helpStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
	detailStyle = lipgloss.NewStyle().PaddingLeft(2)
	promptStyle = lipgloss.NewStyle().Bold(true)
)

type mode int

const (
	modeBrowse mode = iota
	modeAddChooser
	modeAddFile
	modeAddPaste
	modeAddName
	modeConfirmDelete
)

type addSource int

const (
	addFromFile addSource = iota
	addFromPaste
	addEmpty
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
	mode          mode
	list          list.Model
	status        ipc.StatusPayload
	err           string
	notice        string
	width         int
	height        int
	picker        filepicker.Model
	pasteArea     textarea.Model
	nameInput     textinput.Model
	addPath       string
	addContent    string
	addSource     addSource
	deleteName    string
	updateVersion string
	updating      bool
}

type tickMsg struct{}

type statusMsg struct {
	st  ipc.StatusPayload
	err error
}

type profilesMsg struct {
	names []string
	err   error
}

type opDoneMsg struct {
	err     error
	message string
}

type updateAvailableMsg struct {
	version string
}

type updateAppliedMsg struct {
	version string
	err     error
}

func Run() error {
	names, err := profile.List()
	if err != nil {
		return err
	}
	st, _ := fetchStatus()
	m := newModel(names, st)
	_, err = tea.NewProgram(m, tea.WithAltScreen()).Run()
	return err
}

func newModel(names []string, st ipc.StatusPayload) model {
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

	fp := filepicker.New()
	fp.AllowedTypes = []string{".conf", ".json", ".wg"}
	fp.ShowHidden = false
	fp.DirAllowed = false
	fp.FileAllowed = true
	fp.AutoHeight = false
	fp.Height = 12
	if cwd, err := os.Getwd(); err == nil {
		fp.CurrentDirectory = cwd
	} else if home, err := os.UserHomeDir(); err == nil {
		fp.CurrentDirectory = home
	}
	// Keep esc for canceling the add flow; use h/backspace/left to go up.
	fp.KeyMap.Back = key.NewBinding(
		key.WithKeys("h", "backspace", "left"),
		key.WithHelp("h", "back"),
	)

	ti := textinput.New()
	ti.Placeholder = "profile-name"
	ti.CharLimit = 64
	ti.Width = 32

	ta := textarea.New()
	ta.Placeholder = "Paste a WireGuard .conf here..."
	ta.CharLimit = 64 * 1024
	ta.ShowLineNumbers = false
	ta.Prompt = ""
	ta.SetWidth(60)
	ta.SetHeight(12)

	return model{list: l, status: st, picker: fp, nameInput: ti, pasteArea: ta}
}

func (m model) Init() tea.Cmd {
	return tea.Batch(refreshStatus, scheduleTick(), checkUpdate)
}

func scheduleTick() tea.Cmd {
	return tea.Tick(time.Duration(constants.HandshakePollIntervalSec)*time.Second, func(time.Time) tea.Msg {
		return tickMsg{}
	})
}

func checkUpdate() tea.Msg {
	ctx, cancel := context.WithTimeout(context.Background(), constants.UpdateCheckTimeout)
	defer cancel()
	rel, err := update.Check(ctx, constants.Version)
	if err != nil || rel == nil {
		return nil
	}
	return updateAvailableMsg{version: rel.Version}
}

func applyUpdate() tea.Msg {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	rel, err := update.Check(ctx, constants.Version)
	if err == update.ErrNoUpdate {
		return updateAppliedMsg{version: constants.Version}
	}
	if err != nil {
		return updateAppliedMsg{err: err}
	}
	if err := update.Apply(ctx, rel); err != nil {
		return updateAppliedMsg{err: err}
	}
	return updateAppliedMsg{version: rel.Version}
}

func refreshStatus() tea.Msg {
	st, err := fetchStatus()
	return statusMsg{st: st, err: err}
}

func refreshProfiles() tea.Msg {
	names, err := profile.List()
	return profilesMsg{names: names, err: err}
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
		listH := max(5, msg.Height-8)
		m.list.SetSize(max(20, msg.Width/2-2), listH)
		m.picker.SetHeight(max(8, msg.Height-10))
		m.pasteArea.SetWidth(max(40, msg.Width-4))
		m.pasteArea.SetHeight(max(8, msg.Height-10))
	case tickMsg:
		if m.mode == modeBrowse {
			return m, tea.Batch(refreshStatus, scheduleTick())
		}
		return m, scheduleTick()
	case statusMsg:
		if msg.err != nil {
			m.err = msg.err.Error()
		} else {
			m.err = ""
			m.status = msg.st
			m.syncActiveFlags()
		}
	case profilesMsg:
		if msg.err != nil {
			m.err = msg.err.Error()
		} else {
			m.setProfiles(msg.names)
		}
	case opDoneMsg:
		if msg.err != nil {
			m.err = msg.err.Error()
			m.notice = ""
		} else {
			m.err = ""
			m.notice = msg.message
		}
		m.mode = modeBrowse
		m.addPath = ""
		m.addContent = ""
		m.deleteName = ""
		m.nameInput.Blur()
		m.pasteArea.Blur()
		m.pasteArea.Reset()
		return m, tea.Batch(refreshProfiles, refreshStatus)
	case updateAvailableMsg:
		m.updateVersion = msg.version
	case updateAppliedMsg:
		m.updating = false
		if msg.err != nil {
			m.err = msg.err.Error()
		} else {
			m.err = ""
			m.notice = fmt.Sprintf("updated to %s — restarting", update.FormatVersion(msg.version))
			m.updateVersion = ""
		}
	case tea.KeyMsg:
		switch m.mode {
		case modeAddChooser:
			return m.updateAddChooser(msg)
		case modeAddFile:
			return m.updateAddFile(msg)
		case modeAddPaste:
			return m.updateAddPaste(msg)
		case modeAddName:
			return m.updateAddName(msg)
		case modeConfirmDelete:
			return m.updateConfirmDelete(msg)
		default:
			return m.updateBrowse(msg)
		}
	}

	switch m.mode {
	case modeAddFile:
		var cmd tea.Cmd
		m.picker, cmd = m.picker.Update(msg)
		if didSelect, path := m.picker.DidSelectFile(msg); didSelect {
			return m.beginNameInput(path, "")
		}
		return m, cmd
	case modeAddPaste:
		var cmd tea.Cmd
		m.pasteArea, cmd = m.pasteArea.Update(msg)
		return m, cmd
	case modeAddName:
		var cmd tea.Cmd
		m.nameInput, cmd = m.nameInput.Update(msg)
		return m, cmd
	default:
		var cmd tea.Cmd
		m.list, cmd = m.list.Update(msg)
		return m, cmd
	}
}

func (m model) updateBrowse(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "ctrl+c":
		return m, tea.Quit
	case " ":
		it, ok := m.list.SelectedItem().(item)
		if !ok {
			return m, nil
		}
		m.notice = ""
		return m, toggleProfile(it.name, m.status.Active && m.status.Profile == it.name)
	case "r":
		m.notice = ""
		return m, tea.Batch(refreshStatus, refreshProfiles)
	case "a":
		m.mode = modeAddChooser
		m.err = ""
		m.notice = ""
		m.addPath = ""
		m.addContent = ""
		return m, nil
	case "u":
		if m.updateVersion == "" || m.updating {
			return m, nil
		}
		m.updating = true
		m.notice = "downloading update..."
		m.err = ""
		return m, applyUpdate
	case "d":
		it, ok := m.list.SelectedItem().(item)
		if !ok {
			m.err = "no profile selected"
			return m, nil
		}
		if m.status.Active && m.status.Profile == it.name {
			m.err = "disconnect profile before deleting"
			return m, nil
		}
		m.mode = modeConfirmDelete
		m.deleteName = it.name
		m.err = ""
		m.notice = ""
		return m, nil
	}
	var cmd tea.Cmd
	m.list, cmd = m.list.Update(msg)
	return m, cmd
}

func (m model) updateAddChooser(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc", "q", "ctrl+c":
		m.mode = modeBrowse
		m.err = ""
		return m, nil
	case "f":
		m.mode = modeAddFile
		m.addSource = addFromFile
		m.err = ""
		return m, m.picker.Init()
	case "p":
		m.mode = modeAddPaste
		m.addSource = addFromPaste
		m.pasteArea.Reset()
		m.err = ""
		return m, m.pasteArea.Focus()
	case "e":
		m.addSource = addEmpty
		m.addPath = ""
		m.addContent = ""
		return m.beginNameInput("", "tunnel")
	}
	return m, nil
}

func (m model) updateAddFile(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.mode = modeAddChooser
		m.err = ""
		return m, nil
	case "ctrl+c":
		m.mode = modeBrowse
		m.err = ""
		return m, nil
	case "q":
		// Don't quit the whole app while adding; go back to chooser.
		m.mode = modeAddChooser
		return m, nil
	}
	var cmd tea.Cmd
	m.picker, cmd = m.picker.Update(msg)
	if didSelect, path := m.picker.DidSelectFile(msg); didSelect {
		return m.beginNameInput(path, "")
	}
	if didSelect, path := m.picker.DidSelectDisabledFile(msg); didSelect {
		m.err = path + " is not a .conf or .json profile"
		return m, cmd
	}
	return m, cmd
}

func (m model) updateAddPaste(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.mode = modeAddChooser
		m.pasteArea.Blur()
		m.err = ""
		return m, nil
	case "ctrl+c":
		m.mode = modeBrowse
		m.pasteArea.Blur()
		m.pasteArea.Reset()
		return m, nil
	case "ctrl+s", "ctrl+d":
		content := strings.TrimSpace(m.pasteArea.Value())
		if content == "" {
			m.err = "paste a WireGuard config first"
			return m, nil
		}
		m.addContent = content
		m.pasteArea.Blur()
		return m.beginNameInput("", "pasted")
	}
	var cmd tea.Cmd
	m.pasteArea, cmd = m.pasteArea.Update(msg)
	return m, cmd
}

func (m model) beginNameInput(path, defaultName string) (tea.Model, tea.Cmd) {
	m.addPath = path
	m.mode = modeAddName
	stem := defaultName
	if path != "" {
		stem = strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	}
	if stem == "" {
		stem = "tunnel"
	}
	m.nameInput.SetValue(stem)
	m.nameInput.CursorEnd()
	cmd := m.nameInput.Focus()
	m.err = ""
	return m, cmd
}

func (m model) updateAddName(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.nameInput.Blur()
		m.err = ""
		switch m.addSource {
		case addFromPaste:
			m.mode = modeAddPaste
			return m, m.pasteArea.Focus()
		case addFromFile:
			m.mode = modeAddFile
			return m, nil
		default:
			m.mode = modeAddChooser
			return m, nil
		}
	case "ctrl+c":
		m.mode = modeBrowse
		m.nameInput.Blur()
		return m, nil
	case "enter":
		name := strings.TrimSpace(m.nameInput.Value())
		src := m.addSource
		path := m.addPath
		content := m.addContent
		m.nameInput.Blur()
		return m, saveProfile(src, path, content, name)
	}
	var cmd tea.Cmd
	m.nameInput, cmd = m.nameInput.Update(msg)
	return m, cmd
}

func (m model) updateConfirmDelete(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "y", "Y":
		name := m.deleteName
		return m, deleteProfile(name)
	case "n", "N", "esc", "q":
		m.mode = modeBrowse
		m.deleteName = ""
		return m, nil
	}
	return m, nil
}

func saveProfile(src addSource, path, content, name string) tea.Cmd {
	return func() tea.Msg {
		var p *profile.Profile
		var err error
		switch src {
		case addEmpty:
			p, err = profile.NewEmpty(name)
		case addFromPaste:
			p, err = profile.ImportBytes([]byte(content), name)
		default:
			p, err = profile.ImportFile(path, name)
		}
		if err != nil {
			return opDoneMsg{err: err}
		}
		if err := profile.Save(p); err != nil {
			return opDoneMsg{err: fmt.Errorf("save profile: %w (try running as root)", err)}
		}
		msg := fmt.Sprintf("saved profile %q", p.Name)
		if src == addEmpty {
			msg = fmt.Sprintf("created empty tunnel %q — edit %s before connecting", p.Name, profile.Path(p.Name))
		}
		return opDoneMsg{message: msg}
	}
}

func deleteProfile(name string) tea.Cmd {
	return func() tea.Msg {
		if err := profile.Delete(name); err != nil {
			return opDoneMsg{err: fmt.Errorf("delete profile: %w (try running as root)", err)}
		}
		return opDoneMsg{message: fmt.Sprintf("deleted profile %q", name)}
	}
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

func (m *model) setProfiles(names []string) {
	items := make([]list.Item, 0, len(names))
	for _, n := range names {
		items = append(items, item{name: n, active: m.status.Active && m.status.Profile == n})
	}
	m.list.SetItems(items)
}

func (m model) View() string {
	switch m.mode {
	case modeAddChooser:
		return m.viewAddChooser()
	case modeAddFile:
		return m.viewAddFile()
	case modeAddPaste:
		return m.viewAddPaste()
	case modeAddName:
		return m.viewAddName()
	case modeConfirmDelete:
		return m.viewConfirmDelete()
	default:
		return m.viewBrowse()
	}
}

func (m model) viewBrowse() string {
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
	} else if len(m.list.Items()) == 0 {
		detail.WriteString("No profiles yet.\nPress [a] to add a profile (file, paste, or empty tunnel).\n")
	} else {
		detail.WriteString("No active tunnel.\nSelect a profile and press Space to connect.\n")
	}
	if m.updateVersion != "" {
		detail.WriteString(fmt.Sprintf("\nUpdate available: %s (press [u] to install)\n",
			update.FormatVersion(m.updateVersion)))
	}
	if m.notice != "" {
		detail.WriteString("\n" + m.notice + "\n")
	}
	if m.err != "" {
		detail.WriteString("\nError: " + m.err + "\n")
	}

	body := lipgloss.JoinHorizontal(lipgloss.Top, m.list.View(), detailStyle.Render(detail.String()))
	help := helpStyle.Render("[Space] Toggle  [a] Add  [d] Delete  [u] Update  [r] Refresh  [q] Quit")
	return header + "\n\n" + body + "\n\n" + help
}

func (m model) viewAddChooser() string {
	header := titleStyle.Render("Add profile")
	body := `How do you want to add a profile?

  [f]  Import from file (.conf / .json)
  [p]  Paste WireGuard config
  [e]  Create empty tunnel
`
	help := helpStyle.Render("[esc] Cancel")
	return header + "\n\n" + body + "\n" + help
}

func (m model) viewAddFile() string {
	header := titleStyle.Render("Add profile") + " — select a WireGuard .conf or .json file"
	var errLine string
	if m.err != "" {
		errLine = "\n" + m.err + "\n"
	}
	help := helpStyle.Render("[enter] Select  [h] Up dir  [esc] Back")
	return header + "\n\n" + m.picker.View() + errLine + "\n" + help
}

func (m model) viewAddPaste() string {
	header := titleStyle.Render("Add profile") + " — paste WireGuard config"
	var errLine string
	if m.err != "" {
		errLine = "\n" + m.err + "\n"
	}
	help := helpStyle.Render("[ctrl+s] Continue  [esc] Back")
	return header + "\n\n" + m.pasteArea.View() + errLine + "\n" + help
}

func (m model) viewAddName() string {
	header := titleStyle.Render("Add profile")
	var sourceLine string
	switch m.addSource {
	case addEmpty:
		sourceLine = "Creating empty tunnel (generated private key)"
	case addFromPaste:
		sourceLine = "Source: pasted WireGuard config"
	default:
		sourceLine = fmt.Sprintf("File: %s", m.addPath)
	}
	body := fmt.Sprintf("%s\n\n%s\n%s",
		sourceLine,
		promptStyle.Render("Profile name:"),
		m.nameInput.View(),
	)
	var errLine string
	if m.err != "" {
		errLine = "\n" + m.err + "\n"
	}
	help := helpStyle.Render("[enter] Save  [esc] Back  [ctrl+c] Cancel")
	return header + "\n\n" + body + errLine + "\n\n" + help
}

func (m model) viewConfirmDelete() string {
	header := titleStyle.Render("Delete profile")
	body := fmt.Sprintf("Delete profile %q?\nThis cannot be undone.", m.deleteName)
	help := helpStyle.Render("[y] Yes  [n] No")
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
