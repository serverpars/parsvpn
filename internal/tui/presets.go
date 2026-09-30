package tui

import (
	"fmt"
	"os"
	"strings"

	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/serverpars/parsvpn/internal/preset"
)

type presetListItem struct {
	id    string
	title string
	desc  string
}

func (p presetListItem) Title() string       { return p.title }
func (p presetListItem) Description() string { return p.desc }
func (p presetListItem) FilterValue() string { return p.id }

type presetDoneMsg struct {
	err     error
	message string
	reopen  string // "" | "list" | "entries"
	name    string
}

func (m model) openPresets() (tea.Model, tea.Cmd) {
	m.mode = modePresets
	m.err = ""
	m.notice = ""
	m.presetName = ""
	m.refreshPresetsList()
	return m, nil
}

func (m *model) refreshPresetsList() {
	items := []list.Item{
		presetListItem{id: "ir", title: "ir", desc: "builtin — Iran IPv4 bypass (apply via Edit → Split)"},
		presetListItem{id: "none", title: "none", desc: "builtin — empty list (apply via Edit → Split)"},
	}
	names, err := preset.List()
	if err != nil {
		m.err = err.Error()
	} else {
		for _, n := range names {
			desc := "custom"
			if p, err := preset.Load(n); err == nil {
				desc = fmt.Sprintf("custom — %d entries", len(p.Entries))
				if p.Description != "" {
					desc += " — " + p.Description
				}
			}
			items = append(items, presetListItem{id: n, title: n, desc: desc})
		}
	}
	m.editList.SetItems(items)
	m.editList.Title = "Bypass presets"
	delegate := list.NewDefaultDelegate()
	delegate.ShowDescription = true
	m.editList.SetDelegate(delegate)
	m.editList.SetShowHelp(false)
	m.editList.SetShowStatusBar(false)
	m.editList.SetFilteringEnabled(false)
}

func (m *model) openPresetEntries(name string) (tea.Model, tea.Cmd) {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "ir" || name == "none" {
		cidrs, err := preset.ExpandCIDRs(name, nil)
		if err != nil {
			m.err = err.Error()
			return m, nil
		}
		items := make([]list.Item, 0, 1)
		items = append(items, presetListItem{
			id:    "_info",
			title: fmt.Sprintf("%s (builtin, read-only)", name),
			desc:  fmt.Sprintf("%d CIDRs — cannot edit builtins", len(cidrs)),
		})
		m.editList.SetItems(items)
		m.editList.Title = "Preset — " + name
		m.mode = modePresetEntries
		m.presetName = name
		m.err = ""
		return m, nil
	}
	p, err := preset.Load(name)
	if err != nil {
		m.err = err.Error()
		return m, nil
	}
	items := make([]list.Item, 0, len(p.Entries))
	for _, e := range p.Entries {
		items = append(items, presetListItem{id: e, title: e, desc: "CIDR / IP / host"})
	}
	if len(items) == 0 {
		items = append(items, presetListItem{id: "_empty", title: "(empty)", desc: "press [a] to add IPs, CIDRs, or hosts"})
	}
	m.editList.SetItems(items)
	m.editList.Title = fmt.Sprintf("Preset — %s (%d)", p.Name, len(p.Entries))
	delegate := list.NewDefaultDelegate()
	delegate.ShowDescription = true
	m.editList.SetDelegate(delegate)
	m.mode = modePresetEntries
	m.presetName = p.Name
	m.err = ""
	return m, nil
}

func (m model) updatePresets(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc", "q":
		m.presetName = ""
		m.err = ""
		delegate := list.NewDefaultDelegate()
		delegate.ShowDescription = false
		m.editList.SetDelegate(delegate)
		if m.editProfile != "" {
			return m.openEditSplit()
		}
		m.mode = modeBrowse
		return m, refreshStatus
	case "ctrl+c":
		return m, tea.Quit
	case "a":
		m.mode = modePresetNew
		m.nameInput.Placeholder = "preset-name"
		m.nameInput.SetValue("")
		m.nameInput.Focus()
		m.err = ""
		m.notice = ""
		return m, nil
	case "enter", " ":
		it, ok := m.editList.SelectedItem().(presetListItem)
		if !ok {
			return m, nil
		}
		return m.openPresetEntries(it.id)
	case "d", "x", "backspace", "delete":
		it, ok := m.editList.SelectedItem().(presetListItem)
		if !ok {
			return m, nil
		}
		if it.id == "ir" || it.id == "none" {
			m.err = "cannot delete builtin preset"
			return m, nil
		}
		m.mode = modePresetConfirmDelete
		m.presetName = it.id
		m.err = ""
		return m, nil
	}
	var cmd tea.Cmd
	m.editList, cmd = m.editList.Update(msg)
	return m, cmd
}

func (m model) updatePresetEntries(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc", "q":
		m.mode = modePresets
		m.presetName = ""
		m.err = ""
		m.refreshPresetsList()
		return m, nil
	case "ctrl+c":
		return m, tea.Quit
	case "a":
		if m.presetName == "ir" || m.presetName == "none" {
			m.err = "cannot edit builtin preset"
			return m, nil
		}
		m.mode = modePresetAddEntry
		m.nameInput.Placeholder = "1.2.3.4 or 10.0.0.0/8 or host"
		m.nameInput.SetValue("")
		m.nameInput.Focus()
		m.err = ""
		return m, nil
	case "d", "x", "backspace", "delete":
		if m.presetName == "ir" || m.presetName == "none" {
			m.err = "cannot edit builtin preset"
			return m, nil
		}
		it, ok := m.editList.SelectedItem().(presetListItem)
		if !ok || it.id == "_empty" || it.id == "_info" {
			m.err = "no entry selected"
			return m, nil
		}
		return m, presetRemoveEntry(m.presetName, it.id)
	}
	var cmd tea.Cmd
	m.editList, cmd = m.editList.Update(msg)
	return m, cmd
}

func (m model) updatePresetNew(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.nameInput.Blur()
		m.nameInput.Placeholder = "profile-name"
		m.mode = modePresets
		m.err = ""
		m.refreshPresetsList()
		return m, nil
	case "ctrl+c":
		return m, tea.Quit
	case "enter":
		name := strings.TrimSpace(m.nameInput.Value())
		m.nameInput.Blur()
		if name == "" {
			m.err = "name required"
			return m, nil
		}
		return m, presetCreate(name)
	}
	var cmd tea.Cmd
	m.nameInput, cmd = m.nameInput.Update(msg)
	return m, cmd
}

func (m model) updatePresetAddEntry(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.nameInput.Blur()
		m.nameInput.Placeholder = "profile-name"
		next, cmd := m.openPresetEntries(m.presetName)
		return next, cmd
	case "ctrl+c":
		return m, tea.Quit
	case "enter":
		raw := strings.TrimSpace(m.nameInput.Value())
		m.nameInput.Blur()
		if raw == "" {
			m.err = "entry required"
			return m, nil
		}
		return m, presetAddEntry(m.presetName, raw)
	}
	var cmd tea.Cmd
	m.nameInput, cmd = m.nameInput.Update(msg)
	return m, cmd
}

func (m model) updatePresetConfirmDelete(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "y", "Y":
		name := m.presetName
		return m, presetDelete(name)
	case "n", "N", "esc", "q":
		m.mode = modePresets
		m.presetName = ""
		m.refreshPresetsList()
		return m, nil
	}
	return m, nil
}

func presetCreate(name string) tea.Cmd {
	return func() tea.Msg {
		p, err := preset.NewEmpty(name, "")
		if err != nil {
			return presetDoneMsg{err: err, reopen: "list"}
		}
		if _, err := os.Stat(preset.Path(p.Name)); err == nil {
			return presetDoneMsg{err: fmt.Errorf("preset %q already exists", p.Name), reopen: "list"}
		}
		if err := preset.Save(p); err != nil {
			return presetDoneMsg{err: fmt.Errorf("save: %w (try running as root)", err), reopen: "list"}
		}
		return presetDoneMsg{message: "created preset " + p.Name, reopen: "entries", name: p.Name}
	}
}

func presetAddEntry(name, entry string) tea.Cmd {
	return func() tea.Msg {
		p, err := preset.Load(name)
		if err != nil {
			return presetDoneMsg{err: err, reopen: "entries"}
		}
		if err := p.Add(entry); err != nil {
			return presetDoneMsg{err: err, reopen: "entries"}
		}
		if err := preset.Save(p); err != nil {
			return presetDoneMsg{err: fmt.Errorf("save: %w (try running as root)", err), reopen: "entries"}
		}
		return presetDoneMsg{message: "added " + entry, reopen: "entries", name: name}
	}
}

func presetRemoveEntry(name, entry string) tea.Cmd {
	return func() tea.Msg {
		p, err := preset.Load(name)
		if err != nil {
			return presetDoneMsg{err: err, reopen: "entries"}
		}
		if err := p.Remove(entry); err != nil {
			return presetDoneMsg{err: err, reopen: "entries"}
		}
		if err := preset.Save(p); err != nil {
			return presetDoneMsg{err: fmt.Errorf("save: %w (try running as root)", err), reopen: "entries"}
		}
		return presetDoneMsg{message: "removed " + entry, reopen: "entries", name: name}
	}
}

func presetDelete(name string) tea.Cmd {
	return func() tea.Msg {
		if err := preset.Delete(name); err != nil {
			return presetDoneMsg{err: fmt.Errorf("delete: %w (try running as root)", err), reopen: "list"}
		}
		return presetDoneMsg{message: "deleted preset " + name, reopen: "list"}
	}
}

func (m model) viewPresets() string {
	header := titleStyle.Render("Bypass presets")
	hint := "Builtins: ir, none. Custom presets apply via Edit → Split on a profile.\nCLI: parsvpn preset list|show|new|add|rm|delete"
	var errLine string
	if m.err != "" {
		errLine = "\nError: " + m.err + "\n"
	}
	if m.notice != "" {
		errLine += "\n" + m.notice + "\n"
	}
	help := helpStyle.Render("[enter] Open  [a] New  [d] Delete custom  [esc] Back")
	return header + "\n" + hint + "\n\n" + m.editList.View() + errLine + "\n" + help
}

func (m model) viewPresetEntries() string {
	header := titleStyle.Render(m.editList.Title)
	var errLine string
	if m.err != "" {
		errLine = "\nError: " + m.err + "\n"
	}
	if m.notice != "" {
		errLine += "\n" + m.notice + "\n"
	}
	help := helpStyle.Render("[a] Add entry  [d] Remove  [esc] Back")
	if m.presetName == "ir" || m.presetName == "none" {
		help = helpStyle.Render("[esc] Back")
	}
	return header + "\n\n" + m.editList.View() + errLine + "\n" + help
}

func (m model) viewPresetNew() string {
	header := titleStyle.Render("New custom preset")
	body := promptStyle.Render("name:") + "\n" + m.nameInput.View()
	var errLine string
	if m.err != "" {
		errLine = "\nError: " + m.err + "\n"
	}
	help := helpStyle.Render("[enter] Create  [esc] Back")
	return header + "\n\n" + body + errLine + "\n\n" + help
}

func (m model) viewPresetAddEntry() string {
	header := titleStyle.Render(fmt.Sprintf("Add to preset — %s", m.presetName))
	body := "IP, CIDR, hostname, or *.wildcard.com\n\n" +
		promptStyle.Render("entry:") + "\n" + m.nameInput.View()
	var errLine string
	if m.err != "" {
		errLine = "\nError: " + m.err + "\n"
	}
	help := helpStyle.Render("[enter] Add  [esc] Back")
	return header + "\n\n" + body + errLine + "\n\n" + help
}

func (m model) viewPresetConfirmDelete() string {
	header := titleStyle.Render("Delete preset")
	body := fmt.Sprintf("Delete custom preset %q?\nThis cannot be undone.", m.presetName)
	help := helpStyle.Render("[y] Yes  [n] No")
	return header + "\n\n" + body + "\n\n" + help
}
