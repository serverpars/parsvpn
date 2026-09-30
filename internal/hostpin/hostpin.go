package hostpin

import (
	"fmt"
	"time"

	"github.com/serverpars/parsvpn/internal/dnseng"
	"github.com/serverpars/parsvpn/internal/ipc"
	"github.com/serverpars/parsvpn/internal/profile"
)

// Add resolves domain through the active tunnel's DNS path, then pins
// domain→IP as a host override and adds the IP to split routes.
func Add(profileName, domain string) (ip string, err error) {
	p, err := profile.Load(profileName)
	if err != nil {
		return "", err
	}
	st, err := requireActive(profileName)
	if err != nil {
		return "", err
	}
	_ = st

	dnsHost := p.UpstreamDNSHost()
	added, err := p.EnsureResolverRouted(dnsHost)
	if err != nil {
		return "", err
	}
	if added {
		if err := saveReload(p); err != nil {
			return "", fmt.Errorf("route DNS via tunnel: %w", err)
		}
		// Re-load after reload in case Normalize changed fields.
		p, err = profile.Load(profileName)
		if err != nil {
			return "", err
		}
	}

	resolved, err := dnseng.LookupA(domain, dnsHost, 8*time.Second)
	if err != nil {
		return "", fmt.Errorf("%w (is the tunnel up and carrying DNS to %s?)", err, dnsHost)
	}
	ip = resolved.String()

	if err := p.PinHost(domain, ip); err != nil {
		return "", err
	}
	if err := saveReload(p); err != nil {
		return "", err
	}
	return ip, nil
}

// Remove drops a host override and its pinned /32 route.
func Remove(profileName, domain string) error {
	p, err := profile.Load(profileName)
	if err != nil {
		return err
	}
	if err := p.UnpinHost(domain); err != nil {
		return err
	}
	return saveReload(p)
}

func requireActive(profileName string) (*ipc.StatusPayload, error) {
	resp, err := ipc.Call(ipc.Request{Cmd: "status"})
	if err != nil {
		return nil, fmt.Errorf("daemon unreachable: %w (host add needs an active tunnel)", err)
	}
	if resp.Status == nil || !resp.Status.Active {
		return nil, fmt.Errorf("connect profile %q first so DNS can resolve through the tunnel", profileName)
	}
	if resp.Status.Profile != profileName {
		return nil, fmt.Errorf("active profile is %q — connect %q first", resp.Status.Profile, profileName)
	}
	return resp.Status, nil
}

func saveReload(p *profile.Profile) error {
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
