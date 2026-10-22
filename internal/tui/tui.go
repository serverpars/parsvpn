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
	"github.com/charmbracelet/bubbles/spinner"
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
	titleStyle  = lipgloss.NewStyle().Bold(true).Foreground(accent)
	statusOn    = lipgloss.NewStyle().Foreground(lipgloss.Color("10")).Bold(true)
	statusHeal  = lipgloss.NewStyle().Foreground(lipgloss.Color("11")).Bold(true)
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
	modeEditMenu
	modeEditRoutes
	modeEditRouteAdd
	modeEditHosts
	modeEditHostAdd
	modeEditSplit
	modeEditDNS
	modeTraffic
	modeSettings
	modeSettingsEditInterval
	modePresets
	modePresetEntries
	modePresetNew
	modePresetAddEntry
	modePresetConfirmDelete
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
	desc   string
}

func (i item) Title() string {
	if i.active {
		return okStyle.Render("●") + " " + i.name
	}
	return labelStyle.Render("○") + " " + i.name
}
func (i item) Description() string { return i.desc }
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
	needsReexec   bool
	editProfile   string
	editList      list.Model
	hostAlsoWWW   bool
	trafficLines  []string
	presetName    string
	// busy names a long-running action in progress (connect, apply, resolve);
	// shown with a spinner and blocks repeated toggles.
	busy string
	spin spinner.Model
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

// toggleDoneMsg ends a connect/disconnect started from the profile list.
type toggleDoneMsg struct {
	st      ipc.StatusPayload
	err     error
	message string
}

type trafficMsg struct {
	lines []string
	err   error
}

func Run() error {
	names, err := profile.List()
	if err != nil {
		return err
	}
	st, _ := fetchStatus()
	m := newModel(names, st)
	final, err := tea.NewProgram(m, tea.WithAltScreen()).Run()
	if err != nil {
		return err
	}
	if fm, ok := final.(model); ok && fm.needsReexec {
		return update.ReexecSelf()
	}
	return nil
}

func newModel(names []string, st ipc.StatusPayload) model {
	items := make([]list.Item, 0, len(names))
	for _, n := range names {
		items = append(items, newItem(n, st))
	}
	delegate := list.NewDefaultDelegate()
	delegate.ShowDescription = true
	delegate.SetSpacing(0)
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

	sp := spinner.New()
	sp.Spinner = spinner.Dot
	sp.Style = busyStyle

	return model{list: l, status: st, picker: fp, nameInput: ti, pasteArea: ta, editList: newEditList(), spin: sp}
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
		m.editList.SetSize(max(30, msg.Width-4), max(8, msg.Height-12))
	case tickMsg:
		if m.mode == modeBrowse {
			return m, tea.Batch(refreshStatus, scheduleTick())
		}
		if m.mode == modeTraffic {
			return m, tea.Batch(refreshTraffic, scheduleTick())
		}
		return m, scheduleTick()
	case spinner.TickMsg:
		if m.busy == "" {
			return m, nil
		}
		var cmd tea.Cmd
		m.spin, cmd = m.spin.Update(msg)
		return m, cmd
	case toggleDoneMsg:
		m.busy = ""
		if msg.err != nil {
			m.err = msg.err.Error()
			m.notice = ""
			return m, refreshStatus
		}
		m.err = ""
		m.notice = msg.message
		m.status = msg.st
		m.syncActiveFlags()
		return m, nil
	case statusMsg:
		if msg.err != nil {
			// Only surface status-fetch failures on the browse screen so a
			// background refresh cannot wipe an edit/host-add error.
			if m.mode == modeBrowse {
				m.err = msg.err.Error()
			}
		} else {
			m.status = msg.st
			m.syncActiveFlags()
			if m.mode == modeBrowse && isDaemonStatusError(m.err) {
				m.err = ""
			}
			if m.mode == modeSettings {
				m.refreshSettingsList()
			}
		}
	case trafficMsg:
		if msg.err != nil {
			m.err = msg.err.Error()
		} else {
			m.err = ""
			m.trafficLines = msg.lines
		}
	case profilesMsg:
		if msg.err != nil {
			m.err = msg.err.Error()
		} else {
			m.setProfiles(msg.names)
		}
	case opDoneMsg:
		m.busy = ""
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
	case editDoneMsg:
		m.busy = ""
		if msg.err != nil {
			m.err = msg.err.Error()
			m.notice = ""
		} else {
			m.err = ""
			m.notice = msg.message
		}
		m.nameInput.Blur()
		m.nameInput.Placeholder = "profile-name"
		var cmd tea.Cmd
		var next tea.Model
		switch msg.reopen {
		case "routes":
			next, cmd = m.openEditRoutes()
			m = next.(model)
		case "hosts":
			next, cmd = m.openEditHosts()
			m = next.(model)
		case "split":
			next, cmd = m.openEditSplit()
			m = next.(model)
		case "dns":
			m.mode = modeEditDNS
		default:
			m.mode = modeEditMenu
		}
		// Refresh status in the background, but never as the only signal that
		// could clear the edit error (statusMsg must not wipe m.err here).
		return m, tea.Batch(cmd, refreshStatus)
	case editPresetSavedMsg:
		// Profile JSON already has the new preset — refresh the Split list now,
		// then apply routes asynchronously so a slow reload can't hide the change.
		m.err = ""
		m.notice = ""
		m.busy = msg.message
		m.nameInput.Blur()
		m.nameInput.Placeholder = "profile-name"
		next, cmd := m.openEditSplit()
		m = next.(model)
		return m, tea.Batch(cmd, applyPresetReload(msg.profile), refreshStatus, m.spin.Tick)
	case presetDoneMsg:
		m.busy = ""
		if msg.err != nil {
			m.err = msg.err.Error()
			m.notice = ""
		} else {
			m.err = ""
			m.notice = msg.message
		}
		m.nameInput.Blur()
		m.nameInput.Placeholder = "profile-name"
		switch msg.reopen {
		case "entries":
			name := msg.name
			if name == "" {
				name = m.presetName
			}
			next, cmd := m.openPresetEntries(name)
			m = next.(model)
			return m, cmd
		case "list":
			m.mode = modePresets
			m.presetName = ""
			m.refreshPresetsList()
			return m, nil
		default:
			m.mode = modeBrowse
			return m, refreshStatus
		}
	case settingsDoneMsg:
		m.busy = ""
		if msg.err != nil {
			m.err = msg.err.Error()
			m.notice = ""
			m.nameInput.Blur()
			m.nameInput.Placeholder = "profile-name"
			if msg.reopen {
				m.mode = modeSettings
				m.refreshSettingsList()
			}
			return m, nil
		}
		m.err = ""
		m.notice = msg.message
		m.nameInput.Blur()
		m.nameInput.Placeholder = "profile-name"
		if msg.reopen {
			m.mode = modeSettings
			return m, refreshStatus
		}
		m.mode = modeBrowse
		return m, refreshStatus
	case updateAvailableMsg:
		m.updateVersion = msg.version
	case updateAppliedMsg:
		m.updating = false
		m.busy = ""
		if msg.err != nil {
			m.err = msg.err.Error()
		} else {
			m.err = ""
			m.notice = fmt.Sprintf("updated to %s — restarting", update.FormatVersion(msg.version))
			m.updateVersion = ""
			m.needsReexec = true
			return m, tea.Quit
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
		case modeEditMenu:
			return m.updateEditMenu(msg)
		case modeEditRoutes:
			return m.updateEditRoutes(msg)
		case modeEditRouteAdd:
			return m.updateEditRouteAdd(msg)
		case modeEditHosts:
			return m.updateEditHosts(msg)
		case modeEditHostAdd:
			return m.updateEditHostAdd(msg)
		case modeEditSplit:
			return m.updateEditSplit(msg)
		case modeEditDNS:
			return m.updateEditDNS(msg)
		case modeTraffic:
			return m.updateTraffic(msg)
		case modeSettings:
			return m.updateSettings(msg)
		case modeSettingsEditInterval:
			return m.updateSettingsEditInterval(msg)
		case modePresets:
			return m.updatePresets(msg)
		case modePresetEntries:
			return m.updatePresetEntries(msg)
		case modePresetNew:
			return m.updatePresetNew(msg)
		case modePresetAddEntry:
			return m.updatePresetAddEntry(msg)
		case modePresetConfirmDelete:
			return m.updatePresetConfirmDelete(msg)
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
	case modeAddName, modeEditRouteAdd, modeEditHostAdd, modeSettingsEditInterval, modePresetNew, modePresetAddEntry:
		var cmd tea.Cmd
		m.nameInput, cmd = m.nameInput.Update(msg)
		return m, cmd
	case modeEditDNS:
		if m.nameInput.Focused() {
			var cmd tea.Cmd
			m.nameInput, cmd = m.nameInput.Update(msg)
			return m, cmd
		}
		return m, nil
	case modeEditRoutes, modeEditHosts, modeSettings, modeEditSplit, modePresets, modePresetEntries:
		var cmd tea.Cmd
		m.editList, cmd = m.editList.Update(msg)
		return m, cmd
	default:
		var cmd tea.Cmd
		m.list, cmd = m.list.Update(msg)
		return m, cmd
	}
}

func (m model) updateBrowse(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	// While typing a list filter (/), keys are filter text, not shortcuts:
	// otherwise "q" quit and "d" opened delete mid-search.
	if m.list.FilterState() == list.Filtering {
		var cmd tea.Cmd
		m.list, cmd = m.list.Update(msg)
		return m, cmd
	}
	switch msg.String() {
	case "q", "ctrl+c":
		return m, tea.Quit
	case " ", "enter":
		it, ok := m.list.SelectedItem().(item)
		if !ok {
			return m, nil
		}
		if m.busy != "" {
			return m, nil // one connect/disconnect at a time
		}
		isActive := m.status.Active && m.status.Profile == it.name
		m.notice = ""
		m.err = ""
		switch {
		case isActive:
			m.busy = fmt.Sprintf("Disconnecting %s…", it.name)
		case m.status.Active:
			m.busy = fmt.Sprintf("Switching %s → %s…", m.status.Profile, it.name)
		default:
			m.busy = fmt.Sprintf("Connecting %s…", it.name)
		}
		return m, tea.Batch(toggleProfile(it.name, isActive), m.spin.Tick)
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
		m.busy = "Downloading " + update.FormatVersion(m.updateVersion) + "…"
		m.notice = ""
		m.err = ""
		return m, tea.Batch(applyUpdate, m.spin.Tick)
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
	case "e":
		next, cmd := m.beginEdit()
		return next, cmd
	case "s":
		next, cmd := m.openSettings()
		return next, cmd
	case "p":
		next, cmd := m.openPresets()
		return next, cmd
	case "t":
		m.mode = modeTraffic
		m.err = ""
		m.notice = ""
		return m, refreshTraffic
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
			if err == nil && name != "" {
				p.Name = name // the typed name wins over a pasted JSON "name"
			}
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
		if err := profile.EnsureNotActive(name); err != nil {
			return opDoneMsg{err: err}
		}
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
			return toggleDoneMsg{err: err}
		}
		if !resp.OK {
			return toggleDoneMsg{err: fmt.Errorf("%s", resp.Error)}
		}
		st := ipc.StatusPayload{}
		if resp.Status != nil {
			st = *resp.Status
		} else if fresh, err := fetchStatus(); err == nil {
			st = fresh
		}
		msg := "Disconnected"
		if !isActive {
			msg = "Connected to " + name
		}
		return toggleDoneMsg{st: st, message: msg}
	}
}

// newItem builds a profile list row: connection dot plus a one-line summary.
func newItem(name string, st ipc.StatusPayload) item {
	it := item{name: name, active: (st.Active || st.Healing) && st.Profile == name}
	p, err := profile.Load(name)
	switch {
	case err != nil:
		it.desc = "  (cannot load)"
	case it.active && st.Healing:
		it.desc = "  reconnecting…"
	case it.active:
		it.desc = "  connected · " + p.EffectiveMode()
	default:
		it.desc = "  " + p.EffectiveMode()
	}
	return it
}

func (m *model) syncActiveFlags() {
	items := m.list.Items()
	for i, it := range items {
		if ii, ok := it.(item); ok {
			items[i] = newItem(ii.name, m.status)
		}
	}
	m.list.SetItems(items)
}

func (m *model) setProfiles(names []string) {
	items := make([]list.Item, 0, len(names))
	for _, n := range names {
		items = append(items, newItem(n, m.status))
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
	case modeEditMenu:
		return m.viewEditMenu()
	case modeEditRoutes:
		return m.viewEditRoutes()
	case modeEditRouteAdd:
		return m.viewEditRouteAdd()
	case modeEditHosts:
		return m.viewEditHosts()
	case modeEditHostAdd:
		return m.viewEditHostAdd()
	case modeEditSplit:
		return m.viewEditSplit()
	case modeEditDNS:
		return m.viewEditDNS()
	case modeTraffic:
		return m.viewTraffic()
	case modeSettings:
		return m.viewSettings()
	case modeSettingsEditInterval:
		return m.viewSettingsEditInterval()
	case modePresets:
		return m.viewPresets()
	case modePresetEntries:
		return m.viewPresetEntries()
	case modePresetNew:
		return m.viewPresetNew()
	case modePresetAddEntry:
		return m.viewPresetAddEntry()
	case modePresetConfirmDelete:
		return m.viewPresetConfirmDelete()
	default:
		return m.viewBrowse()
	}
}

func (m model) updateTraffic(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc", "q":
		m.mode = modeBrowse
		m.err = ""
		return m, refreshStatus
	case "ctrl+c":
		return m, tea.Quit
	case "c":
		return m, clearTraffic
	case "r":
		return m, refreshTraffic
	}
	return m, nil
}

func (m model) viewTraffic() string {
	header := titleStyle.Render("Traffic debug — pv-tun0 / DNS")
	body := strings.Join(m.trafficLines, "\n")
	if body == "" {
		body = "(no samples yet — browse through the tunnel or enable DNS override)"
	}
	errLine := m.messages()
	help := m.help("[r] Refresh  [c] Clear  [esc] Back")
	return header + "\n\n" + body + errLine + "\n\n" + help
}

func refreshTraffic() tea.Msg {
	resp, err := ipc.Call(ipc.Request{Cmd: "traffic", Limit: 40})
	if err != nil {
		return trafficMsg{err: err}
	}
	if !resp.OK {
		return trafficMsg{err: fmt.Errorf("%s", resp.Error)}
	}
	lines := make([]string, 0, len(resp.Flows))
	for _, f := range resp.Flows {
		ts := f.Time.Local().Format("15:04:05")
		switch f.Kind {
		case "dns":
			lines = append(lines, fmt.Sprintf("%s  DNS  %-22s → %-15s %s", ts, f.Domain, f.Dst, f.Detail))
		default:
			dom := f.Domain
			if dom == "" {
				dom = "-"
			}
			lines = append(lines, fmt.Sprintf("%s  %-4s %-16s → %-16s %-20s %dB", ts, f.Proto, f.Src, f.Dst, dom, f.Bytes))
		}
	}
	return trafficMsg{lines: lines}
}

func clearTraffic() tea.Msg {
	resp, err := ipc.Call(ipc.Request{Cmd: "traffic-clear"})
	if err != nil {
		return trafficMsg{err: err}
	}
	if !resp.OK {
		return trafficMsg{err: fmt.Errorf("%s", resp.Error)}
	}
	return trafficMsg{lines: nil}
}

func (m model) viewBrowse() string {
	var statusLine string
	switch {
	case m.status.Healing:
		prof := m.status.Profile
		if prof == "" {
			prof = m.status.AutostartProfile
		}
		statusLine = statusHeal.Render("◐ RECONNECTING " + orDash(prof))
	case m.status.Active:
		statusLine = statusOn.Render("● CONNECTED " + m.status.Profile)
	default:
		statusLine = statusOff.Render("○ DISCONNECTED")
	}
	header := titleStyle.Render("ParsVPN "+constants.Version) + "   " + statusLine

	sel := ""
	if it, ok := m.list.SelectedItem().(item); ok {
		sel = it.name
	}

	var detail strings.Builder
	switch {
	case m.status.Healing:
		detail.WriteString(sectionHead.Render("Reconnecting") + "\n")
		detail.WriteString("The tunnel interface was lost; ParsVPN is\nbringing it back. This takes a few seconds.\n\n")
	case m.status.Active:
		detail.WriteString(sectionHead.Render("Connection") + "\n")
		detail.WriteString(kv("Profile", m.status.Profile))
		detail.WriteString(kv("Endpoint", orDash(m.status.Endpoint)))
		detail.WriteString(kv("Tunnel IP", orDash(m.status.Address)))
		hs := orDash(m.status.Handshake)
		if hs == "never" {
			hs = busyStyle.Render("never — check the endpoint and keys")
		}
		detail.WriteString(kv("Handshake", hs))
		detail.WriteString(kv("Traffic", fmt.Sprintf("↓ %s  ↑ %s", humanBytes(m.status.RxBytes), humanBytes(m.status.TxBytes))))
		if m.status.DynamicRoutes > 0 {
			detail.WriteString(kv("Wildcards", fmt.Sprintf("%d IPs routed", m.status.DynamicRoutes)))
		}
		detail.WriteString("\n")
	case len(m.list.Items()) == 0:
		detail.WriteString(sectionHead.Render("Welcome") + "\n")
		detail.WriteString("No profiles yet. Press " + keyStyle.Render("a") + " to import a\nWireGuard .conf, paste one, or create an empty tunnel.\n\n")
	}

	// Always show the selected profile's config from disk so edits appear
	// immediately on return to this screen.
	if sel != "" {
		title := "Profile " + sel
		if !(m.status.Active && m.status.Profile == sel) {
			title += labelStyle.Render("  (press enter to connect)")
		}
		detail.WriteString(sectionHead.Render(title) + "\n")
		writeProfileDiskDetail(&detail, sel)
	}

	detail.WriteString("\n")
	wanted := orDash(m.status.AutostartProfile)
	detail.WriteString(kv("Autostart", fmt.Sprintf("%s (reconnects %s)", onOff(m.status.AutoConnect), wanted)))
	detail.WriteString(kv("Autoupdate", onOff(m.status.AutoUpdate)))
	if m.updateVersion != "" {
		detail.WriteString("\n" + busyStyle.Render(fmt.Sprintf("Update %s available — press u to install",
			update.FormatVersion(m.updateVersion))) + "\n")
	}

	panelWidth := 0
	if m.width > 0 {
		panelWidth = max(30, m.width-m.list.Width()-6)
	}
	panel := panelStyle.Width(panelWidth).Render(strings.TrimRight(detail.String(), "\n"))
	body := lipgloss.JoinHorizontal(lipgloss.Top, m.list.View(), " ", panel)

	help := m.help("[enter] Connect/disconnect  [a] Add  [e] Edit  [p] Presets  [s] Settings  [t] Traffic  [d] Delete  [/] Search  [q] Quit")
	if m.updateVersion != "" {
		help = m.help("[u] Install update") + "\n" + help
	}
	return header + "\n\n" + body + "\n" + m.messages() + "\n" + help
}

// writeProfileDiskDetail appends split/DNS/hosts/routes from the profile file.
func writeProfileDiskDetail(detail *strings.Builder, name string) {
	p, err := profile.Load(name)
	if err != nil {
		detail.WriteString(errStyle.Render("cannot load: "+err.Error()) + "\n")
		return
	}
	switch p.EffectiveMode() {
	case profile.SplitModeExclude:
		bypass := "nothing extra"
		if p.SplitTunnel.BypassPreset != "" {
			bypass = "preset " + p.SplitTunnel.BypassPreset
		}
		if n := len(p.SplitTunnel.IPRanges); n > 0 {
			bypass += fmt.Sprintf(" + %d range(s)", n)
		}
		detail.WriteString(kv("Mode", "exclude — everything via VPN except "+bypass))
	default:
		detail.WriteString(kv("Mode", fmt.Sprintf("include — only %d listed range(s) via VPN", len(p.SplitTunnel.IPRanges))))
	}
	if len(p.SplitTunnel.IPRanges) > 0 {
		shown := p.SplitTunnel.IPRanges
		more := 0
		if len(shown) > 6 {
			more = len(shown) - 6
			shown = shown[:6]
		}
		line := strings.Join(shown, ", ")
		if more > 0 {
			line += fmt.Sprintf(" … +%d", more)
		}
		detail.WriteString(kv("Ranges", line))
	}
	detail.WriteString(kv("DNS", p.DNSBehavior()))
	if len(p.SplitTunnel.HostOverrides) > 0 {
		detail.WriteString(labelStyle.Render("Hosts") + "\n")
		for i, o := range p.SplitTunnel.HostOverrides {
			if i >= 8 {
				detail.WriteString(labelStyle.Render(fmt.Sprintf("  … +%d more", len(p.SplitTunnel.HostOverrides)-8)) + "\n")
				break
			}
			detail.WriteString(fmt.Sprintf("  %s → %s\n", o.Domain, o.DisplayIP()))
		}
	}
}

func (m model) viewAddChooser() string {
	header := titleStyle.Render("Add profile")
	body := `How do you want to add a profile?

  [f]  Import from file (.conf / .json)
  [p]  Paste WireGuard config
  [e]  Create empty tunnel
`
	help := m.help("[esc] Cancel")
	return header + "\n\n" + body + "\n" + help
}

func (m model) viewAddFile() string {
	header := titleStyle.Render("Add profile") + " — select a WireGuard .conf or .json file"
	errLine := m.messages()
	help := m.help("[enter] Select  [h] Up dir  [esc] Back")
	return header + "\n\n" + m.picker.View() + errLine + "\n" + help
}

func (m model) viewAddPaste() string {
	header := titleStyle.Render("Add profile") + " — paste WireGuard config"
	errLine := m.messages()
	help := m.help("[ctrl+s] Continue  [esc] Back")
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
	errLine := m.messages()
	help := m.help("[enter] Save  [esc] Back  [ctrl+c] Cancel")
	return header + "\n\n" + body + errLine + "\n\n" + help
}

func (m model) viewConfirmDelete() string {
	header := titleStyle.Render("Delete profile")
	body := fmt.Sprintf("Delete profile %q?\nThis cannot be undone.", m.deleteName)
	help := m.help("[y] Yes  [n] No")
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

func isDaemonStatusError(err string) bool {
	if err == "" {
		return false
	}
	return strings.Contains(err, "daemon not running") ||
		strings.Contains(err, "daemon unreachable") ||
		strings.Contains(err, "connection refused")
}
