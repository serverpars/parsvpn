//go:build linux

package flowlog

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/serverpars/parsvpn/internal/constants"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// Sampler captures samples from the tunnel interface into Default ring.
type Sampler struct {
	stop chan struct{}
}

// StartSampler begins AF_PACKET sampling on pv-tun0. Safe to call when iface is down
// (it retries until available or stop).
func StartSampler(stop <-chan struct{}) *Sampler {
	s := &Sampler{stop: make(chan struct{})}
	go s.loop(stop)
	return s
}

func (s *Sampler) loop(stop <-chan struct{}) {
	backoff := time.Second
	for {
		select {
		case <-stop:
			return
		default:
		}
		err := s.captureOnce(stop)
		if err == nil {
			// stop closed inside captureOnce
			return
		}
		// Interface gone or bind failed — retry (do not treat as fatal).
		select {
		case <-stop:
			return
		case <-time.After(backoff):
			if backoff < 5*time.Second {
				backoff *= 2
			}
		}
	}
}

func (s *Sampler) captureOnce(stop <-chan struct{}) error {
	link, err := netlink.LinkByName(constants.IfaceName)
	if err != nil {
		return err
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return err
	}
	defer unix.Close(fd)

	addr := &unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_ALL),
		Ifindex:  link.Attrs().Index,
	}
	if err := unix.Bind(fd, addr); err != nil {
		return err
	}
	// Non-blocking-ish via deadline using setsockopt is awkward; use select-style Read with short timeout.
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 1})

	buf := make([]byte, 65535)
	for {
		select {
		case <-stop:
			return nil
		default:
		}
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			if err == unix.EAGAIN || err == unix.EWOULDBLOCK || err == unix.EINTR {
				continue
			}
			return err
		}
		if n < 20 {
			continue
		}
		s.handlePacket(buf[:n])
	}
}

func (s *Sampler) handlePacket(b []byte) {
	payload := b
	// Skip Ethernet header when present (dst+src+type = 14).
	if len(b) >= 14 {
		et := binary.BigEndian.Uint16(b[12:14])
		if et == unix.ETH_P_IP || et == unix.ETH_P_IPV6 {
			payload = b[14:]
		}
	}
	if len(payload) < 1 {
		return
	}
	ver := payload[0] >> 4
	now := time.Now()
	switch ver {
	case 4:
		if len(payload) < 20 {
			return
		}
		ihl := int(payload[0]&0x0f) * 4
		if ihl < 20 || len(payload) < ihl {
			return
		}
		total := int(binary.BigEndian.Uint16(payload[2:4]))
		if total <= 0 || total > len(payload) {
			total = len(payload)
		}
		protoNum := payload[9]
		src := net.IP(payload[12:16]).String()
		dst := net.IP(payload[16:20]).String()
		proto := protoName(protoNum)
		domain := Default.DomainForIP(dst)
		if domain == "" {
			domain = Default.DomainForIP(src)
		}
		Default.Add(Event{
			Time:   now,
			Kind:   "pkt",
			Proto:  proto,
			Src:    src,
			Dst:    dst,
			Domain: domain,
			Bytes:  total,
		})
	case 6:
		if len(payload) < 40 {
			return
		}
		payloadLen := int(binary.BigEndian.Uint16(payload[4:6]))
		protoNum := payload[6]
		src := net.IP(payload[8:24]).String()
		dst := net.IP(payload[24:40]).String()
		Default.Add(Event{
			Time:   now,
			Kind:   "pkt",
			Proto:  protoName(protoNum),
			Src:    src,
			Dst:    dst,
			Domain: Default.DomainForIP(dst),
			Bytes:  40 + payloadLen,
		})
	}
}

func protoName(n byte) string {
	switch n {
	case 1:
		return "icmp"
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 58:
		return "icmp6"
	default:
		return fmt.Sprintf("%d", n)
	}
}

func htons(v uint16) uint16 {
	return (v << 8) | (v >> 8)
}
