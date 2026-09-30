package geo

import (
	"bufio"
	"embed"
	"strings"
	"sync"
)

//go:embed ir_ipv4.txt
var irIPv4File embed.FS

var (
	irOnce   sync.Once
	irCIDRs  []string
	irLoadErr error
)

// PresetCIDRs returns destination CIDRs for a named bypass preset.
// Supported: "ir" (Iran IPv4). Empty / "none" returns nil.
func PresetCIDRs(name string) ([]string, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "", "none":
		return nil, nil
	case "ir":
		return iranIPv4()
	default:
		return nil, errUnknownPreset(name)
	}
}

func errUnknownPreset(name string) error {
	return &unknownPresetError{name: name}
}

type unknownPresetError struct{ name string }

func (e *unknownPresetError) Error() string {
	return "unknown bypass preset " + e.name + " (builtins: ir, none)"
}

func iranIPv4() ([]string, error) {
	irOnce.Do(func() {
		f, err := irIPv4File.Open("ir_ipv4.txt")
		if err != nil {
			irLoadErr = err
			return
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		var out []string
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			out = append(out, line)
		}
		if err := sc.Err(); err != nil {
			irLoadErr = err
			return
		}
		irCIDRs = out
	})
	if irLoadErr != nil {
		return nil, irLoadErr
	}
	return append([]string(nil), irCIDRs...), nil
}
