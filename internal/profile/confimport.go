package profile

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

// ImportWireGuardConf parses a standard wg-quick .conf into a Profile.
func ImportWireGuardConf(path, name string) (*Profile, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ImportWireGuardConfReader(f, name)
}

// ImportWireGuardConfContent parses WireGuard conf text (e.g. pasted) into a Profile.
func ImportWireGuardConfContent(content, name string) (*Profile, error) {
	return ImportWireGuardConfReader(strings.NewReader(content), name)
}

// ImportWireGuardConfReader parses a standard wg-quick .conf from r into a Profile.
func ImportWireGuardConfReader(r io.Reader, name string) (*Profile, error) {
	if err := ValidateName(name); err != nil {
		return nil, err
	}

	p := &Profile{Name: name}
	var curPeer *Peer
	section := ""

	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.Trim(line, "[]"))
			if section == "peer" {
				p.Peers = append(p.Peers, Peer{})
				curPeer = &p.Peers[len(p.Peers)-1]
			} else {
				curPeer = nil
			}
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)
		switch section {
		case "interface":
			switch strings.ToLower(key) {
			case "privatekey":
				p.PrivateKey = val
			case "address":
				// wg-quick allows comma-separated; take first for tunnel address.
				parts := splitCSV(val)
				if len(parts) > 0 {
					p.Address = parts[0]
				}
			case "listenport":
				n, err := strconv.Atoi(val)
				if err != nil {
					return nil, fmt.Errorf("ListenPort: %w", err)
				}
				p.ListenPort = n
			case "dns":
				p.DNS = splitCSV(val)
			case "mtu":
				n, err := strconv.Atoi(val)
				if err != nil {
					return nil, fmt.Errorf("MTU: %w", err)
				}
				p.MTU = n
			}
		case "peer":
			if curPeer == nil {
				return nil, fmt.Errorf("peer key outside [Peer] section")
			}
			switch strings.ToLower(key) {
			case "publickey":
				curPeer.PublicKey = val
			case "presharedkey":
				curPeer.PresharedKey = val
			case "endpoint":
				curPeer.Endpoint = val
			case "persistentkeepalive":
				n, err := strconv.Atoi(val)
				if err != nil {
					return nil, fmt.Errorf("PersistentKeepalive: %w", err)
				}
				curPeer.PersistentKeepalive = n
			case "allowedips":
				curPeer.AllowedIPs = splitCSV(val)
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if err := p.Normalize(); err != nil {
		return nil, err
	}
	if err := p.ValidateComplete(); err != nil {
		return nil, err
	}
	return p, nil
}

func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
