//go:build linux

package wg

import (
	"fmt"
	"net"
	"os"
	"time"

	"github.com/serverpars/parsvpn/internal/constants"
	"github.com/serverpars/parsvpn/internal/profile"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Controller configures WireGuard on pv-tun0 via the kernel module when present,
// otherwise starts a userspace wireguard-go device.
type Controller struct {
	client     *wgctrl.Client
	device     *device.Device
	tunDev     tun.Device
	uapiLn     net.Listener
	uapiStop   chan struct{}
	userspace  bool
}

func New() (*Controller, error) {
	c, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("wgctrl: %w", err)
	}
	return &Controller{client: c}, nil
}

func (c *Controller) Close() {
	if c.uapiStop != nil {
		close(c.uapiStop)
		c.uapiStop = nil
	}
	if c.uapiLn != nil {
		_ = c.uapiLn.Close()
		c.uapiLn = nil
	}
	if c.device != nil {
		c.device.Close()
		c.device = nil
	}
	if c.tunDev != nil {
		_ = c.tunDev.Close()
		c.tunDev = nil
	}
	if c.client != nil {
		_ = c.client.Close()
	}
}

func (c *Controller) Userspace() bool { return c.userspace }

// StartUserspace creates the TUN and runs wireguard-go with a UAPI socket
// so wgctrl can manage / inspect the device (CentOS 7 path).
func (c *Controller) StartUserspace(mtu int) error {
	if mtu <= 0 {
		mtu = 1420
	}
	tdev, err := tun.CreateTUN(constants.IfaceName, mtu)
	if err != nil {
		return fmt.Errorf("CreateTUN(%s): %w", constants.IfaceName, err)
	}
	logger := device.NewLogger(device.LogLevelError, "parsvpn: ")
	dev := device.NewDevice(tdev, conn.NewDefaultBind(), logger)

	_ = os.MkdirAll("/var/run/wireguard", 0o755)
	fileUAPI, err := ipc.UAPIOpen(constants.IfaceName)
	if err != nil {
		dev.Close()
		_ = tdev.Close()
		return fmt.Errorf("uapi open: %w", err)
	}
	uapi, err := ipc.UAPIListen(constants.IfaceName, fileUAPI)
	if err != nil {
		_ = fileUAPI.Close()
		dev.Close()
		_ = tdev.Close()
		return fmt.Errorf("uapi listen: %w", err)
	}
	stop := make(chan struct{})
	go func() {
		for {
			conn, err := uapi.Accept()
			if err != nil {
				select {
				case <-stop:
					return
				default:
					return
				}
			}
			go dev.IpcHandle(conn)
		}
	}()

	c.device = dev
	c.tunDev = tdev
	c.uapiLn = uapi
	c.uapiStop = stop
	c.userspace = true
	return nil
}

// Configure applies the profile. For kernel mode the interface must already exist.
func (c *Controller) Configure(p *profile.Profile) error {
	if c.userspace {
		uapi, err := cfgToUAPI(p)
		if err != nil {
			return err
		}
		if err := c.device.IpcSet(uapi); err != nil {
			return fmt.Errorf("userspace wg ipc: %w", err)
		}
		c.device.Up()
		return nil
	}
	cfg, err := buildConfig(p)
	if err != nil {
		return err
	}
	if err := c.client.ConfigureDevice(constants.IfaceName, cfg); err != nil {
		return fmt.Errorf("configure kernel wg: %w", err)
	}
	return nil
}

// Rekey re-applies peer config to force a fresh handshake cycle.
func (c *Controller) Rekey(p *profile.Profile) error {
	return c.Configure(p)
}

// PeerHandshakeAge returns duration since last handshake for any peer.
func (c *Controller) PeerHandshakeAge() (time.Duration, error) {
	dev, err := c.client.Device(constants.IfaceName)
	if err != nil {
		if c.userspace {
			return 0, nil
		}
		return 0, err
	}
	return ageFromDevice(dev), nil
}

// Stats returns transfer counters and latest handshake time.
func (c *Controller) Stats() (rx, tx int64, handshake time.Time, err error) {
	dev, err := c.client.Device(constants.IfaceName)
	if err != nil {
		return 0, 0, time.Time{}, err
	}
	for _, peer := range dev.Peers {
		rx += peer.ReceiveBytes
		tx += peer.TransmitBytes
		if peer.LastHandshakeTime.After(handshake) {
			handshake = peer.LastHandshakeTime
		}
	}
	return rx, tx, handshake, nil
}

func ageFromDevice(dev *wgtypes.Device) time.Duration {
	var latest time.Time
	for _, peer := range dev.Peers {
		if peer.LastHandshakeTime.After(latest) {
			latest = peer.LastHandshakeTime
		}
	}
	if latest.IsZero() {
		return 24 * time.Hour
	}
	return time.Since(latest)
}

func buildConfig(p *profile.Profile) (wgtypes.Config, error) {
	priv, err := wgtypes.ParseKey(p.PrivateKey)
	if err != nil {
		return wgtypes.Config{}, fmt.Errorf("private key: %w", err)
	}
	var port *int
	if p.ListenPort > 0 {
		port = &p.ListenPort
	}
	peers := make([]wgtypes.PeerConfig, 0, len(p.Peers))
	for _, peer := range p.Peers {
		pub, err := wgtypes.ParseKey(peer.PublicKey)
		if err != nil {
			return wgtypes.Config{}, fmt.Errorf("peer public key: %w", err)
		}
		pc := wgtypes.PeerConfig{
			PublicKey:         pub,
			ReplaceAllowedIPs: true,
		}
		if peer.PresharedKey != "" {
			psk, err := wgtypes.ParseKey(peer.PresharedKey)
			if err != nil {
				return wgtypes.Config{}, err
			}
			pc.PresharedKey = &psk
		}
		if peer.Endpoint != "" {
			udp, err := net.ResolveUDPAddr("udp", peer.Endpoint)
			if err != nil {
				return wgtypes.Config{}, fmt.Errorf("endpoint %s: %w", peer.Endpoint, err)
			}
			pc.Endpoint = udp
		}
		if peer.PersistentKeepalive > 0 {
			ka := time.Duration(peer.PersistentKeepalive) * time.Second
			pc.PersistentKeepaliveInterval = &ka
		}
		for _, cidr := range p.PeerAllowedIPsForConfigure(peer) {
			_, ipnet, err := net.ParseCIDR(cidr)
			if err != nil {
				return wgtypes.Config{}, fmt.Errorf("allowed ip %s: %w", cidr, err)
			}
			pc.AllowedIPs = append(pc.AllowedIPs, *ipnet)
		}
		peers = append(peers, pc)
	}
	return wgtypes.Config{
		PrivateKey:   &priv,
		ListenPort:   port,
		ReplacePeers: true,
		Peers:        peers,
	}, nil
}

func cfgToUAPI(p *profile.Profile) (string, error) {
	priv, err := wgtypes.ParseKey(p.PrivateKey)
	if err != nil {
		return "", err
	}
	out := fmt.Sprintf("private_key=%x\n", priv[:])
	if p.ListenPort > 0 {
		out += fmt.Sprintf("listen_port=%d\n", p.ListenPort)
	}
	out += "replace_peers=true\n"
	for _, peer := range p.Peers {
		pub, err := wgtypes.ParseKey(peer.PublicKey)
		if err != nil {
			return "", err
		}
		out += fmt.Sprintf("public_key=%x\n", pub[:])
		if peer.PresharedKey != "" {
			psk, err := wgtypes.ParseKey(peer.PresharedKey)
			if err != nil {
				return "", err
			}
			out += fmt.Sprintf("preshared_key=%x\n", psk[:])
		}
		if peer.Endpoint != "" {
			out += fmt.Sprintf("endpoint=%s\n", peer.Endpoint)
		}
		if peer.PersistentKeepalive > 0 {
			out += fmt.Sprintf("persistent_keepalive_interval=%d\n", peer.PersistentKeepalive)
		}
		for _, cidr := range p.PeerAllowedIPsForConfigure(peer) {
			out += fmt.Sprintf("allowed_ip=%s\n", cidr)
		}
	}
	return out, nil
}
