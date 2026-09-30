package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/serverpars/parsvpn/internal/hostpin"
	"github.com/serverpars/parsvpn/internal/ipc"
	"github.com/serverpars/parsvpn/internal/profile"
)

type editItem struct {
	label string
}

func (e editItem) Title() string       { return e.label }
func (e editItem) Description() string { return "" }
func (e editItem) FilterValue() string { return e.label }

func (m *model) beginEdit() (tea.Model, tea.Cmd) {
	it, ok := m.list.SelectedItem().(item)
	if !ok {
		m.err = "no profile selected"
		return m, nil
	}
	m.editProfile = it.name
	m.mode = modeEditMenu
	m.err = ""
	m.notice = ""
	return m, nil
}

func (m model) updateEditMenu(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc", "q":
		m.mode = modeBrowse
		m.editProfile = ""
		m.err = ""
		return m, nil
	case "ctrl+c":
		return m, tea.Quit
	case "r":
		return m.openEditRoutes()
	case "h":
		return m.openEditHosts()
	case "s":
		m.mode = modeEditSplit
		m.err = ""
		return m, nil
	}
	return m, nil
}

func (m model) openEditRoutes() (tea.Model, tea.Cmd) {
	p, err := profile.Load(m.editProfile)
	if err != nil {
		m.err = err.Error()
		return m, nil
	}
	items := make([]list.Item, 0, len(p.SplitTunnel.IPRanges))
	for _, c := range p.SplitTunnel.IPRanges {
		items = append(items, editItem{label: c})
	}
	m.editList.SetItems(items)
	m.editList.Title = fmt.Sprintf("Routes — %s (%s)", p.Name, p.EffectiveMode())
	m.mode = modeEditRoutes
	m.err = ""
	return m, nil
}

func (m model) openEditHosts() (tea.Model, tea.Cmd) {
	p, err := profile.Load(m.editProfile)
	if err != nil {
		m.err = err.Error()
		return m, nil
	}
	items := make([]list.Item, 0, len(p.SplitTunnel.HostOverrides))
	for _, o := range p.SplitTunnel.HostOverrides {
		items = append(items, editItem{label: o.Domain + " " + o.IP})
	}
	m.editList.SetItems(items)
	m.editList.Title = fmt.Sprintf("Hosts — %s", p.Name)
	m.mode = modeEditHosts
	m.err = ""
	return m, nil
}

func (m model) updateEditRoutes(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.mode = modeEditMenu
		m.err = ""
		return m, nil
	case "ctrl+c":
		return m, tea.Quit
	case "a":
		m.mode = modeEditRouteAdd
		m.nameInput.SetValue("")
		m.nameInput.Placeholder = "10.10.0.0/16"
		cmd := m.nameInput.Focus()
		m.err = ""
		return m, cmd
	case "d", "x", "backspace", "delete":
		it, ok := m.editList.SelectedItem().(editItem)
		if !ok {
			m.err = "no route selected"
			return m, nil
		}
		return m, editRemoveRoute(m.editProfile, it.label)
	}
	var cmd tea.Cmd
	m.editList, cmd = m.editList.Update(msg)
	return m, cmd
}

func (m model) updateEditRouteAdd(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.nameInput.Blur()
		m.mode = modeEditRoutes
		m.err = ""
		return m, nil
	case "ctrl+c":
		return m, tea.Quit
	case "enter":
		cidr := strings.TrimSpace(m.nameInput.Value())
		m.nameInput.Blur()
		if cidr == "" {
			m.err = "CIDR required"
			return m, nil
		}
		return m, editAddRoute(m.editProfile, cidr)
	}
	var cmd tea.Cmd
	m.nameInput, cmd = m.nameInput.Update(msg)
	return m, cmd
}

func (m model) updateEditHosts(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.mode = modeEditMenu
		m.err = ""
		return m, nil
	case "ctrl+c":
		return m, tea.Quit
	case "a":
		m.mode = modeEditHostAdd
		m.nameInput.SetValue("")
		m.nameInput.Placeholder = "example.com"
		cmd := m.nameInput.Focus()
		m.err = ""
		return m, cmd
	case "d", "x", "backspace", "delete":
		it, ok := m.editList.SelectedItem().(editItem)
		if !ok {
			m.err = "no host selected"
			return m, nil
		}
		domain := strings.Fields(it.label)
		if len(domain) == 0 {
			return m, nil
		}
		return m, editRemoveHost(m.editProfile, domain[0])
	}
	var cmd tea.Cmd
	m.editList, cmd = m.editList.Update(msg)
	return m, cmd
}

func (m model) updateEditHostAdd(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.nameInput.Blur()
		m.mode = modeEditHosts
		m.err = ""
		return m, nil
	case "ctrl+c":
		return m, tea.Quit
	case "enter":
		domain := strings.TrimSpace(m.nameInput.Value())
		m.nameInput.Blur()
		if domain == "" {
			m.err = "domain required"
			return m, nil
		}
		if strings.ContainsAny(domain, " \t") {
			m.err = "enter domain only (IP is resolved via tunnel DNS)"
			return m, nil
		}
		return m, editAddHost(m.editProfile, domain)
	}
	var cmd tea.Cmd
	m.nameInput, cmd = m.nameInput.Update(msg)
	return m, cmd
}

func (m model) updateEditSplit(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.mode = modeEditMenu
		m.err = ""
		return m, nil
	case "ctrl+c":
		return m, tea.Quit
	case "i":
		return m, editSetMode(m.editProfile, profile.SplitModeInclude)
	case "x":
		return m, editSetMode(m.editProfile, profile.SplitModeExclude)
	case "p":
		return m, editSetPreset(m.editProfile, "ir")
	case "n":
		return m, editSetPreset(m.editProfile, "none")
	}
	return m, nil
}

func saveAndReload(p *profile.Profile) error {
	if err := profile.Save(p); err != nil {
		return fmt.Errorf("save: %w (try running as root)", err)
	}
	resp, err := ipc.Call(ipc.Request{Cmd: "status"})
	if err != nil || resp.Status == nil || !resp.Status.Active || resp.Status.Profile != p.Name {
		return nil
	}
	reload, err := ipc.Call(ipc.Request{Cmd: "reload"})
	if err != nil {
		return fmt.Errorf("saved, but reload failed: %w", err)
	}
	if !reload.OK {
		return fmt.Errorf("saved, but reload failed: %s", reload.Error)
	}
	return nil
}

type editDoneMsg struct {
	err     error
	message string
	reopen  string // "routes" | "hosts" | "split" | ""
}

func editAddRoute(profileName, cidr string) tea.Cmd {
	return func() tea.Msg {
		p, err := profile.Load(profileName)
		if err != nil {
			return editDoneMsg{err: err, reopen: "routes"}
		}
		if err := p.AddRoutes(cidr); err != nil {
			return editDoneMsg{err: err, reopen: "routes"}
		}
		if err := saveAndReload(p); err != nil {
			return editDoneMsg{err: err, reopen: "routes"}
		}
		return editDoneMsg{message: "added " + cidr, reopen: "routes"}
	}
}

func editRemoveRoute(profileName, cidr string) tea.Cmd {
	return func() tea.Msg {
		p, err := profile.Load(profileName)
		if err != nil {
			return editDoneMsg{err: err, reopen: "routes"}
		}
		if err := p.RemoveRoutes(cidr); err != nil {
			return editDoneMsg{err: err, reopen: "routes"}
		}
		if err := saveAndReload(p); err != nil {
			return editDoneMsg{err: err, reopen: "routes"}
		}
		return editDoneMsg{message: "removed " + cidr, reopen: "routes"}
	}
}

func editAddHost(profileName, domain string) tea.Cmd {
	return func() tea.Msg {
		ip, err := hostpin.Add(profileName, domain)
		if err != nil {
			return editDoneMsg{err: err, reopen: "hosts"}
		}
		return editDoneMsg{
			message: fmt.Sprintf("pinned %s -> %s (+ route, via tunnel DNS)", domain, ip),
			reopen:  "hosts",
		}
	}
}

func editRemoveHost(profileName, domain string) tea.Cmd {
	return func() tea.Msg {
		if err := hostpin.Remove(profileName, domain); err != nil {
			return editDoneMsg{err: err, reopen: "hosts"}
		}
		return editDoneMsg{message: "removed host " + domain, reopen: "hosts"}
	}
}

func editSetMode(profileName, mode string) tea.Cmd {
	return func() tea.Msg {
		p, err := profile.Load(profileName)
		if err != nil {
			return editDoneMsg{err: err, reopen: "split"}
		}
		if err := p.SetSplitMode(mode); err != nil {
			return editDoneMsg{err: err, reopen: "split"}
		}
		if err := saveAndReload(p); err != nil {
			return editDoneMsg{err: err, reopen: "split"}
		}
		return editDoneMsg{message: "mode=" + mode, reopen: "split"}
	}
}

func editSetPreset(profileName, preset string) tea.Cmd {
	return func() tea.Msg {
		p, err := profile.Load(profileName)
		if err != nil {
			return editDoneMsg{err: err, reopen: "split"}
		}
		if err := p.SetBypassPreset(preset); err != nil {
			return editDoneMsg{err: err, reopen: "split"}
		}
		if err := saveAndReload(p); err != nil {
			return editDoneMsg{err: err, reopen: "split"}
		}
		msg := "preset=none"
		if p.SplitTunnel.BypassPreset != "" {
			msg = fmt.Sprintf("mode=exclude preset=%s (Iran bypass active after reload)", p.SplitTunnel.BypassPreset)
		}
		return editDoneMsg{message: msg, reopen: "split"}
	}
}

func newEditList() list.Model {
	delegate := list.NewDefaultDelegate()
	delegate.ShowDescription = false
	l := list.New(nil, delegate, 40, 12)
	l.SetShowHelp(false)
	l.SetShowStatusBar(false)
	l.SetFilteringEnabled(false)
	return l
}

func (m model) viewEditMenu() string {
	header := titleStyle.Render(fmt.Sprintf("Edit profile — %s", m.editProfile))
	body := `What do you want to manage?

  [r]  Routes (split IP ranges / bypass CIDRs)
  [h]  Host overrides (DNS)
  [s]  Split mode & country preset
`
	var errLine string
	if m.err != "" {
		errLine = "\nError: " + m.err + "\n"
	}
	if m.notice != "" {
		errLine += "\n" + m.notice + "\n"
	}
	help := helpStyle.Render("[esc] Back")
	return header + "\n\n" + body + errLine + "\n" + help
}

func (m model) viewEditRoutes() string {
	header := titleStyle.Render(m.editList.Title)
	hint := "Include mode: these CIDRs go via tunnel.\nExclude mode: these CIDRs bypass the tunnel (plus preset)."
	var errLine string
	if m.err != "" {
		errLine = "\nError: " + m.err + "\n"
	}
	if m.notice != "" {
		errLine += "\n" + m.notice + "\n"
	}
	help := helpStyle.Render("[a] Add  [d] Delete  [esc] Back")
	return header + "\n" + hint + "\n\n" + m.editList.View() + errLine + "\n" + help
}

func (m model) viewEditRouteAdd() string {
	header := titleStyle.Render(fmt.Sprintf("Add route — %s", m.editProfile))
	body := promptStyle.Render("CIDR:") + "\n" + m.nameInput.View()
	var errLine string
	if m.err != "" {
		errLine = "\nError: " + m.err + "\n"
	}
	help := helpStyle.Render("[enter] Save  [esc] Back")
	return header + "\n\n" + body + errLine + "\n\n" + help
}

func (m model) viewEditHosts() string {
	header := titleStyle.Render(m.editList.Title)
	var errLine string
	if m.err != "" {
		errLine = "\nError: " + m.err + "\n"
	}
	if m.notice != "" {
		errLine += "\n" + m.notice + "\n"
	}
	help := helpStyle.Render("[a] Add  [d] Delete  [esc] Back")
	return header + "\n\n" + m.editList.View() + errLine + "\n" + help
}

func (m model) viewEditHostAdd() string {
	header := titleStyle.Render(fmt.Sprintf("Add host — %s", m.editProfile))
	body := "Resolves via tunnel DNS, then pins domain→IP and adds a /32 route.\nProfile must be connected.\n\n" +
		promptStyle.Render("domain:") + "\n" + m.nameInput.View()
	var errLine string
	if m.err != "" {
		errLine = "\nError: " + m.err + "\n"
	}
	help := helpStyle.Render("[enter] Resolve & pin  [esc] Back")
	return header + "\n\n" + body + errLine + "\n\n" + help
}

func (m model) viewEditSplit() string {
	header := titleStyle.Render(fmt.Sprintf("Split settings — %s", m.editProfile))
	mode, preset := "include", "none"
	if p, err := profile.Load(m.editProfile); err == nil {
		mode = p.EffectiveMode()
		if p.SplitTunnel.BypassPreset != "" {
			preset = p.SplitTunnel.BypassPreset
		}
	}
	body := fmt.Sprintf(`Current: mode=%s  preset=%s

  [i]  Include — only listed routes via tunnel
  [x]  Exclude — tunnel everything except bypass
  [p]  Iran preset (sets mode=exclude + bypass Iranian IPs)
  [n]  Clear preset (none)

Note: preset only works in exclude mode (choosing [p] enables exclude).
`, mode, preset)
	var errLine string
	if m.err != "" {
		errLine = "\nError: " + m.err + "\n"
	}
	if m.notice != "" {
		errLine += "\n" + m.notice + "\n"
	}
	help := helpStyle.Render("[esc] Back")
	return header + "\n\n" + body + errLine + "\n" + help
}
