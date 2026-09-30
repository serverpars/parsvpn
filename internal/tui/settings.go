package tui

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/serverpars/parsvpn/internal/constants"
	"github.com/serverpars/parsvpn/internal/update"
)

type settingsItem struct {
	id    string
	title string
	desc  string
}

func (s settingsItem) Title() string       { return s.title }
func (s settingsItem) Description() string { return s.desc }
func (s settingsItem) FilterValue() string { return s.id }

type settingsDoneMsg struct {
	err     error
	message string
	reopen  bool
}

func (m model) openSettings() (tea.Model, tea.Cmd) {
	m.mode = modeSettings
	m.err = ""
	m.notice = ""
	m.refreshSettingsList()
	return m, nil
}

func (m *model) refreshSettingsList() {
	cfg := update.LoadConfig()
	autoUpdate := "off"
	if cfg.AutoUpdate {
		autoUpdate = "on"
	}
	autoStart := "off"
	if cfg.AutoConnect {
		autoStart = "on"
	}
	wanted := strings.TrimSpace(m.status.AutostartProfile)
	if wanted == "" {
		wanted = "(none — connect once to set)"
	}
	interval := cfg.CheckInterval().String()
	if cfg.CheckIntervalSec > 0 {
		interval = fmt.Sprintf("%s (%ds)", interval, cfg.CheckIntervalSec)
	} else {
		interval = fmt.Sprintf("%s (default)", interval)
	}

	items := []list.Item{
		settingsItem{
			id:    "auto_update",
			title: fmt.Sprintf("Auto-update          [%s]", autoUpdate),
			desc:  "Install newer GitHub releases unattended",
		},
		settingsItem{
			id:    "auto_connect",
			title: fmt.Sprintf("Auto-start           [%s]", autoStart),
			desc:  "Reconnect last profile after reboot / daemon start",
		},
		settingsItem{
			id:    "check_interval",
			title: fmt.Sprintf("Update check interval %s", interval),
			desc:  "How often the daemon polls for new releases",
		},
		settingsItem{
			id:    "reconnects",
			title: fmt.Sprintf("Reconnects as        %s", wanted),
			desc:  "Profile restored when auto-start is on (press c to clear)",
		},
	}
	m.editList.SetItems(items)
	m.editList.Title = "Settings"
	delegate := list.NewDefaultDelegate()
	delegate.ShowDescription = true
	m.editList.SetDelegate(delegate)
	m.editList.SetShowStatusBar(false)
	m.editList.SetFilteringEnabled(false)
	m.editList.SetShowHelp(false)
}

func (m model) updateSettings(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc", "q":
		m.mode = modeBrowse
		m.err = ""
		m.notice = ""
		// Restore edit-list delegate without descriptions for profile edit screens.
		delegate := list.NewDefaultDelegate()
		delegate.ShowDescription = false
		m.editList.SetDelegate(delegate)
		return m, refreshStatus
	case "ctrl+c":
		return m, tea.Quit
	case " ", "enter":
		it, ok := m.editList.SelectedItem().(settingsItem)
		if !ok {
			return m, nil
		}
		switch it.id {
		case "auto_update", "auto_connect":
			return m, toggleSetting(it.id)
		case "check_interval":
			cfg := update.LoadConfig()
			sec := int(cfg.CheckInterval() / time.Second)
			m.mode = modeSettingsEditInterval
			m.nameInput.Placeholder = "seconds (e.g. 3600)"
			m.nameInput.SetValue(strconv.Itoa(sec))
			m.nameInput.Focus()
			m.err = ""
			m.notice = ""
			return m, nil
		case "reconnects":
			m.notice = "press [c] to clear the reconnect profile"
			return m, nil
		}
		return m, nil
	case "c":
		it, ok := m.editList.SelectedItem().(settingsItem)
		if !ok || it.id != "reconnects" {
			return m, nil
		}
		return m, clearReconnectProfile
	case "0":
		// Reset check interval to default.
		it, ok := m.editList.SelectedItem().(settingsItem)
		if !ok || it.id != "check_interval" {
			return m, nil
		}
		return m, setCheckInterval(0)
	}
	var cmd tea.Cmd
	m.editList, cmd = m.editList.Update(msg)
	return m, cmd
}

func (m model) updateSettingsEditInterval(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.nameInput.Blur()
		m.nameInput.Placeholder = "profile-name"
		m.mode = modeSettings
		m.err = ""
		m.refreshSettingsList()
		return m, nil
	case "ctrl+c":
		return m, tea.Quit
	case "enter":
		raw := strings.TrimSpace(m.nameInput.Value())
		if raw == "" || raw == "0" || strings.EqualFold(raw, "default") {
			m.nameInput.Blur()
			return m, setCheckInterval(0)
		}
		sec, err := strconv.Atoi(raw)
		if err != nil || sec < 60 {
			m.err = "enter seconds (>= 60), or 0 for default"
			return m, nil
		}
		m.nameInput.Blur()
		return m, setCheckInterval(sec)
	}
	var cmd tea.Cmd
	m.nameInput, cmd = m.nameInput.Update(msg)
	return m, cmd
}

func toggleSetting(id string) tea.Cmd {
	return func() tea.Msg {
		cfg := update.LoadConfig()
		var label string
		switch id {
		case "auto_update":
			cfg.AutoUpdate = !cfg.AutoUpdate
			label = "auto-update " + onOff(cfg.AutoUpdate)
		case "auto_connect":
			cfg.AutoConnect = !cfg.AutoConnect
			label = "auto-start " + onOff(cfg.AutoConnect)
		default:
			return settingsDoneMsg{err: fmt.Errorf("unknown setting"), reopen: true}
		}
		if err := update.SaveConfig(cfg); err != nil {
			return settingsDoneMsg{err: err, reopen: true}
		}
		return settingsDoneMsg{message: label, reopen: true}
	}
}

func setCheckInterval(sec int) tea.Cmd {
	return func() tea.Msg {
		cfg := update.LoadConfig()
		cfg.CheckIntervalSec = sec
		if err := update.SaveConfig(cfg); err != nil {
			return settingsDoneMsg{err: err, reopen: true}
		}
		msg := "update check interval reset to default"
		if sec > 0 {
			msg = fmt.Sprintf("update check interval set to %s", time.Duration(sec)*time.Second)
		}
		return settingsDoneMsg{message: msg, reopen: true}
	}
}

func clearReconnectProfile() tea.Msg {
	_ = os.Remove(constants.WantedPath)
	_ = os.Remove(constants.LegacyWantedPath)
	return settingsDoneMsg{message: "cleared reconnect profile", reopen: true}
}

func onOff(v bool) string {
	if v {
		return "on"
	}
	return "off"
}

func (m model) viewSettings() string {
	header := titleStyle.Render("Settings")
	hint := "Global daemon options (saved to /etc/parsvpn/config.json)."
	var errLine string
	if m.err != "" {
		errLine = "\nError: " + m.err + "\n"
	}
	if m.notice != "" {
		errLine += "\n" + m.notice + "\n"
	}
	help := helpStyle.Render("[enter/space] Toggle or edit  [c] Clear reconnect  [0] Default interval  [esc] Back")
	return header + "\n" + hint + "\n\n" + m.editList.View() + errLine + "\n" + help
}

func (m model) viewSettingsEditInterval() string {
	header := titleStyle.Render("Update check interval")
	body := "How often the daemon polls GitHub for releases.\n" +
		fmt.Sprintf("Default is %s. Minimum 60 seconds; enter 0 for default.\n\n",
			constants.DefaultUpdateCheckInterval) +
		promptStyle.Render("seconds:") + "\n" + m.nameInput.View()
	var errLine string
	if m.err != "" {
		errLine = "\nError: " + m.err + "\n"
	}
	help := helpStyle.Render("[enter] Save  [esc] Back")
	return header + "\n\n" + body + errLine + "\n\n" + help
}
