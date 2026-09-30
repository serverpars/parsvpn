package ipc

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/serverpars/parsvpn/internal/constants"
)

// Request is a client→daemon JSON line.
type Request struct {
	Cmd     string `json:"cmd"`
	Profile string `json:"profile,omitempty"`
}

// StatusPayload is returned by status / after up.
type StatusPayload struct {
	Active    bool      `json:"active"`
	Profile   string    `json:"profile,omitempty"`
	Interface string    `json:"interface,omitempty"`
	Endpoint  string    `json:"endpoint,omitempty"`
	Address   string    `json:"address,omitempty"`
	Handshake string    `json:"handshake,omitempty"`
	RxBytes   int64     `json:"rx_bytes"`
	TxBytes   int64     `json:"tx_bytes"`
	SplitIPs  []string  `json:"split_ips,omitempty"`
	Overrides []string  `json:"overrides,omitempty"`
	Userspace bool      `json:"userspace,omitempty"`
	Error     string    `json:"error,omitempty"`
	UpdatedAt time.Time `json:"updated_at,omitempty"`
}

// Response wraps command results.
type Response struct {
	OK     bool           `json:"ok"`
	Error  string         `json:"error,omitempty"`
	Status *StatusPayload `json:"status,omitempty"`
}

// Dial connects to the daemon socket.
func Dial() (net.Conn, error) {
	return net.DialTimeout("unix", constants.SocketPath, 3*time.Second)
}

// Call sends one request and reads one response.
func Call(req Request) (*Response, error) {
	conn, err := Dial()
	if err != nil {
		return nil, fmt.Errorf("daemon not running (socket %s): %w", constants.SocketPath, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	enc := json.NewEncoder(conn)
	dec := json.NewDecoder(conn)
	if err := enc.Encode(req); err != nil {
		return nil, err
	}
	var resp Response
	if err := dec.Decode(&resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// Listen creates the Unix socket server listener.
func Listen() (net.Listener, error) {
	_ = os.Remove(constants.SocketPath)
	if err := os.MkdirAll(constants.RuntimeDir, 0o700); err != nil {
		return nil, err
	}
	ln, err := net.Listen("unix", constants.SocketPath)
	if err != nil {
		return nil, err
	}
	_ = os.Chmod(constants.SocketPath, 0o600)
	return ln, nil
}
