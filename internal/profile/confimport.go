package profile

import (
	"bufio"
	"fmt"
	"io"
	"net"
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
				// wg-quick allows comma-separated; only one address is assigned,
				// so prefer IPv4 (routing and exclude mode are IPv4).
				p.Address = preferIPv4Address(splitCSV(val))
			case "listenport":
				n, err := strconv.Atoi(val)
				if err != nil {
					return nil, fmt.Errorf("ListenPort: %w", err)
				}
				p.ListenPort = n
			case "dns":
				// wg-quick treats non-IP DNS= entries as search domains; keep
				// only resolver IPs.
				p.DNS = nil
				for _, d := range splitCSV(val) {
					if net.ParseIP(d) != nil {
						p.DNS = append(p.DNS, d)
					}
				}
				// Match wg-quick: a DNS= line means push resolvers while the tunnel is up.
				if len(p.DNS) > 0 {
					p.OverrideSystemDNS = true
				}
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
				// wg-quick's explicit 0/off means disabled; in a profile 0 means default.
				if strings.EqualFold(val, "off") {
					curPeer.PersistentKeepalive = -1
					break
				}
				n, err := strconv.Atoi(val)
				if err != nil {
					return nil, fmt.Errorf("PersistentKeepalive: %w", err)
				}
				if n == 0 {
					n = -1
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

// preferIPv4Address returns the first IPv4 address/CIDR, else the first entry.
func preferIPv4Address(addrs []string) string {
	for _, a := range addrs {
		host := a
		if ip, _, err := net.ParseCIDR(a); err == nil {
			host = ip.String()
		}
		if ip := net.ParseIP(host); ip != nil && ip.To4() != nil {
			return a
		}
	}
	if len(addrs) > 0 {
		return addrs[0]
	}
	return ""
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
