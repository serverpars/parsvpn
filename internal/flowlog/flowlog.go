package flowlog

import (
	"sync"
	"time"
)

const DefaultCapacity = 256

// Event is one observed DNS query or tunnel packet sample.
type Event struct {
	Time   time.Time `json:"time"`
	Kind   string    `json:"kind"` // dns | pkt
	Proto  string    `json:"proto,omitempty"`
	Src    string    `json:"src,omitempty"`
	Dst    string    `json:"dst,omitempty"`
	Domain string    `json:"domain,omitempty"`
	Bytes  int       `json:"bytes,omitempty"`
	Detail string    `json:"detail,omitempty"`
}

// Ring is a concurrency-safe circular buffer of recent events.
type Ring struct {
	mu   sync.RWMutex
	buf  []Event
	cap  int
	next int
	full bool
	// ipToDomain maps recent answer IPs to domains for packet annotation.
	ipToDomain map[string]string
}

// Global shared ring used by DNS proxy + packet sampler.
var Default = New(DefaultCapacity)

func New(capacity int) *Ring {
	if capacity < 1 {
		capacity = DefaultCapacity
	}
	return &Ring{
		buf:        make([]Event, capacity),
		cap:        capacity,
		ipToDomain: map[string]string{},
	}
}

func (r *Ring) Add(ev Event) {
	if ev.Time.IsZero() {
		ev.Time = time.Now()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.buf[r.next] = ev
	r.next = (r.next + 1) % r.cap
	if r.next == 0 {
		r.full = true
	}
	if ev.Kind == "dns" && ev.Dst != "" && ev.Domain != "" {
		r.ipToDomain[ev.Dst] = ev.Domain
	}
}

// RememberIP associates an IP with a domain (from DNS answers).
func (r *Ring) RememberIP(ip, domain string) {
	if ip == "" || domain == "" {
		return
	}
	r.mu.Lock()
	r.ipToDomain[ip] = domain
	r.mu.Unlock()
}

// DomainForIP returns a recently learned domain for ip, if any.
func (r *Ring) DomainForIP(ip string) string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.ipToDomain[ip]
}

// Snapshot returns up to n most recent events (oldest→newest). n<=0 → all.
func (r *Ring) Snapshot(n int) []Event {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var all []Event
	if !r.full {
		all = append(all, r.buf[:r.next]...)
	} else {
		all = append(all, r.buf[r.next:]...)
		all = append(all, r.buf[:r.next]...)
	}
	if n > 0 && len(all) > n {
		all = all[len(all)-n:]
	}
	out := make([]Event, len(all))
	copy(out, all)
	return out
}

// Clear empties the ring.
func (r *Ring) Clear() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.buf = make([]Event, r.cap)
	r.next = 0
	r.full = false
	r.ipToDomain = map[string]string{}
}
