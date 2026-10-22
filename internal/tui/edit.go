package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/serverpars/parsvpn/internal/hostpin"
	"github.com/serverpars/parsvpn/internal/ipc"
	"github.com/serverpars/parsvpn/internal/preset"
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
		return m, refreshStatus
	case "ctrl+c":
		return m, tea.Quit
	case "r":
		m.err = ""
		m.notice = ""
		return m.openEditRoutes()
	case "h":
		m.err = ""
		m.notice = ""
		return m.openEditHosts()
	case "s":
		m.err = ""
		m.notice = ""
		return m.openEditSplit()
	case "d":
		m.mode = modeEditDNS
		m.nameInput.Blur()
		m.nameInput.SetValue("")
		m.err = ""
		m.notice = ""
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
	delegate := list.NewDefaultDelegate()
	delegate.ShowDescription = false
	m.editList.SetDelegate(delegate)
	m.editList.SetShowHelp(false)
	m.editList.SetShowStatusBar(false)
	m.editList.SetFilteringEnabled(false)
	m.editList.SetItems(items)
	if len(items) > 0 {
		m.editList.Select(0)
	}
	m.editList.Title = fmt.Sprintf("Routes — %s (%s)", p.Name, p.EffectiveMode())
	m.mode = modeEditRoutes
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
		// Domain must stay the first field: delete parses it back out.
		items = append(items, editItem{label: o.Domain + "  →  " + o.DisplayIP()})
	}
	delegate := list.NewDefaultDelegate()
	delegate.ShowDescription = false
	m.editList.SetDelegate(delegate)
	m.editList.SetShowHelp(false)
	m.editList.SetShowStatusBar(false)
	m.editList.SetFilteringEnabled(false)
	m.editList.SetItems(items)
	if len(items) > 0 {
		m.editList.Select(0)
	}
	m.editList.Title = fmt.Sprintf("Hosts — %s", p.Name)
	m.mode = modeEditHosts
	// Keep m.err / m.notice from the caller (e.g. failed host add).
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
		m.hostAlsoWWW = false
		m.nameInput.SetValue("")
		m.nameInput.Placeholder = "example.com or *.example.com"
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
		m.hostAlsoWWW = false
		m.err = ""
		return m, nil
	case "ctrl+c":
		return m, tea.Quit
	case "ctrl+w":
		m.hostAlsoWWW = !m.hostAlsoWWW
		m.err = ""
		return m, nil
	case "enter":
		domain := strings.TrimSpace(m.nameInput.Value())
		m.nameInput.Blur()
		if domain == "" {
			m.err = "domain required"
			return m, nil
		}
		if strings.ContainsAny(domain, " \t") {
			m.err = "enter the domain only (its IP is resolved via tunnel DNS)"
			return m, nil
		}
		norm, err := profile.NormalizeHostDomain(domain)
		if err != nil {
			m.err = err.Error()
			return m, nil
		}
		alsoWWW := m.hostAlsoWWW
		m.hostAlsoWWW = false
		m.err = ""
		m.notice = ""
		if strings.HasPrefix(norm, "*.") {
			m.busy = "Adding wildcard " + norm + "…"
		} else {
			m.busy = "Resolving " + norm + " through the tunnel…"
		}
		return m, tea.Batch(editAddHost(m.editProfile, domain, alsoWWW), m.spin.Tick)
	}
	var cmd tea.Cmd
	m.nameInput, cmd = m.nameInput.Update(msg)
	return m, cmd
}

func (m model) openEditSplit() (tea.Model, tea.Cmd) {
	m.refreshSplitPresetList()
	m.mode = modeEditSplit
	// Do not clear m.err / m.notice — editDoneMsg sets them and reopens this view.
	return m, nil
}

func (m *model) refreshSplitPresetList() {
	mode := profile.SplitModeInclude
	curPreset := "none"
	if p, err := profile.Load(m.editProfile); err == nil {
		mode = p.EffectiveMode()
		if p.SplitTunnel.BypassPreset != "" {
			curPreset = p.SplitTunnel.BypassPreset
		}
	}
	markMode := func(id string) string {
		if id == mode {
			return "* "
		}
		return "  "
	}
	markPreset := func(id string) string {
		if id == curPreset {
			return "* "
		}
		return "  "
	}
	items := []list.Item{
		presetListItem{
			id:    "mode:include",
			title: markMode(profile.SplitModeInclude) + "Mode: include",
			desc:  "Only listed routes go via the tunnel (clears country preset)",
		},
		presetListItem{
			id:    "mode:exclude",
			title: markMode(profile.SplitModeExclude) + "Mode: exclude",
			desc:  "Tunnel everything except bypass preset / routes",
		},
		presetListItem{
			id:    "none",
			title: markPreset("none") + "Preset: none",
			desc:  "No country bypass — switches to include if no manual bypass routes",
		},
		presetListItem{
			id:    "ir",
			title: markPreset("ir") + "Preset: ir",
			desc:  "Exclude mode + bypass Iranian IPv4 ranges",
		},
	}
	if names, err := preset.List(); err == nil {
		for _, n := range names {
			desc := "Custom bypass preset (sets exclude mode)"
			if p, err := preset.Load(n); err == nil {
				desc = fmt.Sprintf("Custom — %d entries (sets exclude mode)", len(p.Entries))
			}
			items = append(items, presetListItem{id: n, title: markPreset(n) + "Preset: " + n, desc: desc})
		}
	}
	m.editList.SetItems(items)
	// Cursor on the active preset (or exclude mode) so Enter applies the obvious choice.
	selectID := "none"
	if curPreset != "none" {
		selectID = curPreset
	} else if mode == profile.SplitModeExclude {
		selectID = "mode:exclude"
	} else {
		selectID = "mode:include"
	}
	for i, it := range items {
		if pi, ok := it.(presetListItem); ok && pi.id == selectID {
			m.editList.Select(i)
			break
		}
	}
	m.editList.Title = fmt.Sprintf("Split — %s", m.editProfile)
	delegate := list.NewDefaultDelegate()
	delegate.ShowDescription = true
	m.editList.SetDelegate(delegate)
	m.editList.SetShowHelp(false)
	m.editList.SetShowStatusBar(false)
	m.editList.SetFilteringEnabled(false)
}

func (m model) updateEditSplit(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc", "q":
		m.mode = modeEditMenu
		m.err = ""
		delegate := list.NewDefaultDelegate()
		delegate.ShowDescription = false
		m.editList.SetDelegate(delegate)
		return m, nil
	case "ctrl+c":
		return m, tea.Quit
	case "i":
		return m.withBusy("Switching to include mode…", editSetMode(m.editProfile, profile.SplitModeInclude))
	case "x":
		return m.withBusy("Switching to exclude mode…", editSetMode(m.editProfile, profile.SplitModeExclude))
	case "1":
		return m.withBusy("Applying preset ir…", editSetPreset(m.editProfile, "ir"))
	case "0":
		return m.withBusy("Clearing preset…", editSetPreset(m.editProfile, "none"))
	case "m":
		next, cmd := m.openPresets()
		return next, cmd
	case "enter", " ":
		items := m.editList.Items()
		idx := m.editList.Index()
		if idx < 0 || idx >= len(items) {
			m.err = "no item selected"
			return m, nil
		}
		it, ok := items[idx].(presetListItem)
		if !ok {
			m.err = "no item selected"
			return m, nil
		}
		switch it.id {
		case "mode:include":
			return m.withBusy("Switching to include mode…", editSetMode(m.editProfile, profile.SplitModeInclude))
		case "mode:exclude":
			return m.withBusy("Switching to exclude mode…", editSetMode(m.editProfile, profile.SplitModeExclude))
		default:
			return m.withBusy("Applying preset "+it.id+"…", editSetPreset(m.editProfile, it.id))
		}
	}
	var cmd tea.Cmd
	m.editList, cmd = m.editList.Update(msg)
	return m, cmd
}

func (m model) updateEditDNS(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if m.nameInput.Focused() {
		switch msg.String() {
		case "esc":
			m.nameInput.Blur()
			m.nameInput.SetValue("")
			m.err = ""
			return m, nil
		case "ctrl+c":
			return m, tea.Quit
		case "enter":
			raw := strings.TrimSpace(m.nameInput.Value())
			m.nameInput.Blur()
			m.nameInput.SetValue("")
			if raw == "" {
				m.err = "enter one or more DNS IPs"
				return m, nil
			}
			parts := strings.FieldsFunc(raw, func(r rune) bool {
				return r == ',' || r == ' ' || r == '\t'
			})
			return m, editSetDNSServers(m.editProfile, parts...)
		}
		return m, nil
	}
	switch msg.String() {
	case "esc":
		m.mode = modeEditMenu
		m.err = ""
		m.notice = ""
		return m, nil
	case "ctrl+c":
		return m, tea.Quit
	case "o":
		return m, editSetDNSOverride(m.editProfile, true)
	case "f":
		return m, editSetDNSOverride(m.editProfile, false)
	case "s":
		m.nameInput.SetValue("")
		m.nameInput.Placeholder = "1.1.1.1 8.8.8.8"
		cmd := m.nameInput.Focus()
		m.err = ""
		return m, cmd
	case "c":
		return m, editClearDNSServers(m.editProfile)
	}
	return m, nil
}

func saveAndReload(p *profile.Profile) (applied bool, err error) {
	if err := profile.Save(p); err != nil {
		return false, fmt.Errorf("save: %w (try running as root)", err)
	}
	resp, err := ipc.Call(ipc.Request{Cmd: "status"})
	if err != nil || resp.Status == nil || !resp.Status.Active || resp.Status.Profile != p.Name {
		return false, nil
	}
	reload, err := ipc.Call(ipc.Request{Cmd: "reload"})
	if err != nil {
		return false, fmt.Errorf("saved, but reload failed: %w", err)
	}
	if !reload.OK {
		return false, fmt.Errorf("saved, but reload failed: %s", reload.Error)
	}
	return true, nil
}

func applyNote(applied bool) string {
	if applied {
		return " — applied to active tunnel"
	}
	return " — saved (connect to apply)"
}

type editDoneMsg struct {
	err     error
	message string
	reopen  string // "routes" | "hosts" | "split" | "dns" | ""
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
		applied, err := saveAndReload(p)
		if err != nil {
			return editDoneMsg{err: err, reopen: "routes"}
		}
		return editDoneMsg{message: "added " + cidr + applyNote(applied), reopen: "routes"}
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
		applied, err := saveAndReload(p)
		if err != nil {
			return editDoneMsg{err: err, reopen: "routes"}
		}
		return editDoneMsg{message: "removed " + cidr + applyNote(applied), reopen: "routes"}
	}
}

func editAddHost(profileName, domain string, alsoWWW bool) tea.Cmd {
	return func() tea.Msg {
		ip, err := hostpin.Add(profileName, domain, hostpin.AddOptions{AlsoWWW: alsoWWW})
		if err != nil {
			return editDoneMsg{err: err, reopen: "hosts"}
		}
		if ip == "" {
			return editDoneMsg{
				message: fmt.Sprintf("added %s — each subdomain resolves via tunnel DNS and its own IP is routed", domain),
				reopen:  "hosts",
			}
		}
		extra := ""
		if alsoWWW {
			if _, ok := profile.WWWCompanion(domain); ok {
				extra = " +www"
			}
		}
		return editDoneMsg{
			message: fmt.Sprintf("pinned %s%s -> %s (+ route, via tunnel DNS)", domain, extra, ip),
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
		clearedPreset := mode == profile.SplitModeInclude && p.SplitTunnel.BypassPreset != ""
		before := append([]string(nil), p.SplitTunnel.IPRanges...)
		if err := p.SetSplitMode(mode); err != nil {
			return editDoneMsg{err: err, reopen: "split"}
		}
		applied, err := saveAndReload(p)
		if err != nil {
			return editDoneMsg{err: err, reopen: "split"}
		}
		msg := "mode=" + mode
		if clearedPreset {
			msg += " (cleared bypass preset)"
		}
		if note := profile.DNSRoutesChangeNote(before, p.SplitTunnel.IPRanges, p.DNS...); note != "" {
			msg += " (" + note + ")"
		}
		return editDoneMsg{message: msg + applyNote(applied), reopen: "split"}
	}
}

func editSetPreset(profileName, presetName string) tea.Cmd {
	return func() tea.Msg {
		p, err := profile.Load(profileName)
		if err != nil {
			return editDoneMsg{err: err, reopen: "split"}
		}
		if err := p.SetBypassPreset(presetName); err != nil {
			return editDoneMsg{err: err, reopen: "split"}
		}
		// Persist first so the Split UI can show the new preset immediately.
		if err := profile.Save(p); err != nil {
			return editDoneMsg{err: fmt.Errorf("save: %w (try running as root)", err), reopen: "split"}
		}
		check, err := profile.Load(profileName)
		if err != nil {
			return editDoneMsg{err: err, reopen: "split"}
		}
		if check.SplitTunnel.BypassPreset != p.SplitTunnel.BypassPreset {
			return editDoneMsg{
				err:    fmt.Errorf("preset did not persist (disk has %q)", check.SplitTunnel.BypassPreset),
				reopen: "split",
			}
		}
		label := "none"
		if p.SplitTunnel.BypassPreset != "" {
			label = p.SplitTunnel.BypassPreset
		}
		return editPresetSavedMsg{
			profile: profileName,
			message: fmt.Sprintf("Saved mode=%s preset=%s — applying to tunnel…", p.EffectiveMode(), label),
		}
	}
}

// editPresetSavedMsg means the profile JSON is updated; routes still need reload.
type editPresetSavedMsg struct {
	profile string
	message string
}

func applyPresetReload(profileName string) tea.Cmd {
	return func() tea.Msg {
		resp, err := ipc.Call(ipc.Request{Cmd: "status"})
		if err != nil || resp.Status == nil || !resp.Status.Active || resp.Status.Profile != profileName {
			return editDoneMsg{message: "preset saved (connect to apply)", reopen: "split"}
		}
		reload, err := ipc.Call(ipc.Request{Cmd: "reload"})
		if err != nil {
			return editDoneMsg{err: fmt.Errorf("preset saved, but apply failed: %w", err), reopen: "split"}
		}
		if !reload.OK {
			return editDoneMsg{err: fmt.Errorf("preset saved, but apply failed: %s", reload.Error), reopen: "split"}
		}
		return editDoneMsg{message: "preset applied to active tunnel", reopen: "split"}
	}
}

func editSetDNSOverride(profileName string, on bool) tea.Cmd {
	return func() tea.Msg {
		p, err := profile.Load(profileName)
		if err != nil {
			return editDoneMsg{err: err, reopen: "dns"}
		}
		p.SetOverrideSystemDNS(on)
		applied, err := saveAndReload(p)
		if err != nil {
			return editDoneMsg{err: err, reopen: "dns"}
		}
		state := "off"
		if on {
			state = "on"
		}
		return editDoneMsg{message: "dns override=" + state + applyNote(applied), reopen: "dns"}
	}
}

func editSetDNSServers(profileName string, servers ...string) tea.Cmd {
	return func() tea.Msg {
		p, err := profile.Load(profileName)
		if err != nil {
			return editDoneMsg{err: err, reopen: "dns"}
		}
		if err := p.SetDNSServers(servers...); err != nil {
			return editDoneMsg{err: err, reopen: "dns"}
		}
		// Servers only: the override switch is separate ([o]/[f]).
		applied, err := saveAndReload(p)
		if err != nil {
			return editDoneMsg{err: err, reopen: "dns"}
		}
		return editDoneMsg{
			message: fmt.Sprintf("tunnel DNS servers = %s%s", strings.Join(p.DNS, ", "), applyNote(applied)),
			reopen:  "dns",
		}
	}
}

func editClearDNSServers(profileName string) tea.Cmd {
	return func() tea.Msg {
		p, err := profile.Load(profileName)
		if err != nil {
			return editDoneMsg{err: err, reopen: "dns"}
		}
		if err := p.SetDNSServers(); err != nil {
			return editDoneMsg{err: err, reopen: "dns"}
		}
		applied, err := saveAndReload(p)
		if err != nil {
			return editDoneMsg{err: err, reopen: "dns"}
		}
		return editDoneMsg{
			message: fmt.Sprintf("dns servers cleared (default %s)%s", p.UpstreamDNSHost(), applyNote(applied)),
			reopen:  "dns",
		}
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
	header := titleStyle.Render("Edit profile — " + m.editProfile)
	routes, hosts, dnsLine, split := "-", "-", "-", "-"
	if p, err := profile.Load(m.editProfile); err == nil {
		routes = fmt.Sprintf("%d range(s)", len(p.SplitTunnel.IPRanges))
		hosts = fmt.Sprintf("%d pinned", len(p.SplitTunnel.HostOverrides))
		dnsLine = "override " + onOff(p.OverrideSystemDNS)
		split = p.EffectiveMode()
		if p.SplitTunnel.BypassPreset != "" {
			split += ", preset " + p.SplitTunnel.BypassPreset
		}
	}
	row := func(k, title, state string) string {
		return "  " + keyStyle.Render(k) + "  " + padRight(title, 24) + labelStyle.Render(state) + "\n"
	}
	body := "What do you want to change?\n\n" +
		row("s", "Split mode & preset", split) +
		row("r", "IP ranges", routes) +
		row("h", "Hosts & wildcards", hosts) +
		row("d", "DNS", dnsLine)
	help := m.help("[s] Split  [r] Ranges  [h] Hosts  [d] DNS  [esc] Back")
	return header + "\n\n" + body + m.messages() + "\n" + help
}

func (m model) viewEditRoutes() string {
	header := titleStyle.Render(m.editList.Title)
	hint := "Include mode: these CIDRs go via tunnel.\nExclude mode: these CIDRs bypass the tunnel (plus preset)."
	errLine := m.messages()
	help := m.help("[a] Add  [d] Delete  [esc] Back")
	return header + "\n" + hint + "\n\n" + m.editList.View() + errLine + "\n" + help
}

func (m model) viewEditRouteAdd() string {
	header := titleStyle.Render(fmt.Sprintf("Add route — %s", m.editProfile))
	body := promptStyle.Render("CIDR:") + "\n" + m.nameInput.View()
	errLine := m.messages()
	help := m.help("[enter] Save  [esc] Back")
	return header + "\n\n" + body + errLine + "\n\n" + help
}

func (m model) viewEditHosts() string {
	header := titleStyle.Render(m.editList.Title)
	errLine := m.messages()
	help := m.help("[a] Add  [d] Delete  [esc] Back")
	return header + "\n\n" + m.editList.View() + errLine + "\n" + help
}

func (m model) viewEditHostAdd() string {
	header := titleStyle.Render(fmt.Sprintf("Add host — %s", m.editProfile))
	wwwState := "off"
	if m.hostAlsoWWW {
		wwwState = "on"
	}
	indent := strings.Repeat(" ", 16)
	body := "Send a host's traffic through the tunnel.\n\n" +
		keyStyle.Render(padRight("example.com", 16)) + "resolved now via tunnel DNS and pinned to that IP\n" +
		indent + "(profile must be connected)\n" +
		keyStyle.Render(padRight("*.example.com", 16)) + "every subdomain resolves via tunnel DNS when used,\n" +
		indent + "and each one's own IP is routed (apex not included)\n\n" +
		promptStyle.Render("Domain:") + "\n" + m.nameInput.View() + "\n\n" +
		labelStyle.Render("also pin www.<domain>: ") + wwwState
	errLine := m.messages()
	help := m.help("[enter] Add  [ctrl+w] Toggle www  [esc] Back")
	return header + "\n\n" + body + errLine + "\n\n" + help
}

func (m model) viewEditSplit() string {
	header := titleStyle.Render(fmt.Sprintf("Split settings — %s", m.editProfile))
	mode, presetName := "include", "none"
	if p, err := profile.Load(m.editProfile); err == nil {
		mode = p.EffectiveMode()
		if p.SplitTunnel.BypassPreset != "" {
			presetName = p.SplitTunnel.BypassPreset
		}
	}
	hint := fmt.Sprintf("Current: mode=%s  preset=%s\n", mode, presetName) +
		"Select Mode: include / Mode: exclude, or a bypass preset, then press enter.\n" +
		"Shortcuts: [i] include  [x] exclude  [1] ir  [0] none  [m] manage custom presets"
	errLine := m.messages()
	help := m.help("[enter] Apply  [i]/[x] Mode  [m] Presets  [esc] Back")
	return header + "\n" + hint + "\n\n" + m.editList.View() + errLine + "\n" + help
}

func (m model) viewEditDNS() string {
	header := titleStyle.Render("DNS — " + m.editProfile)
	override, servers, effect := "off", "1.1.1.1 (default)", ""
	if p, err := profile.Load(m.editProfile); err == nil {
		override = onOff(p.OverrideSystemDNS)
		if len(p.DNS) > 0 {
			servers = strings.Join(p.DNS, ", ")
		} else {
			servers = p.UpstreamDNSHost() + " (default)"
		}
		effect = p.DNSBehavior()
	}
	body := kv("Override", override) + kv("Tunnel DNS", servers) + kv("Effect", effect) + "\n" +
		labelStyle.Render("on:  all system DNS goes through the tunnel (beats ISP filtering).") + "\n" +
		labelStyle.Render("off: your normal DNS is untouched; tunnel DNS only resolves pinned hosts.") + "\n\n"
	if m.nameInput.Focused() {
		body += promptStyle.Render("Tunnel DNS servers (space or comma separated):") + "\n" + m.nameInput.View() + "\n"
		return header + "\n\n" + body + m.messages() + "\n" + m.help("[enter] Save  [esc] Cancel")
	}
	help := m.help("[o] Override on  [f] Override off  [s] Set tunnel DNS servers  [c] Reset servers to 1.1.1.1  [esc] Back")
	return header + "\n\n" + body + m.messages() + "\n" + help
}
