package daemon

import (
	"fmt"
	"log"
	"time"

	"github.com/serverpars/parsvpn/internal/constants"
	"github.com/serverpars/parsvpn/internal/ipc"
	"github.com/serverpars/parsvpn/internal/neteng"
)

// reconcileDebounce lets a burst of deletions (networkd removes every rule at
// once) settle into a single repair pass.
const reconcileDebounce = 300 * time.Millisecond

// startRoutingWatch subscribes to rule/route deletions. Without it the
// periodic pass in reconcileLoop still repairs, just up to
// RoutingReconcileIntervalSec later.
func (d *Daemon) startRoutingWatch() {
	if err := d.net.WatchRouting(d.stopCh, d.requestReconcile); err != nil {
		log.Printf("routing watch unavailable: %v — relying on %ds reconcile", err, constants.RoutingReconcileIntervalSec)
	}
}

func (d *Daemon) requestReconcile() {
	select {
	case d.reconcileCh <- struct{}{}:
	default:
	}
}

// reconcileLoop re-installs ParsVPN rules and table routes that something
// else deleted, on netlink events and every RoutingReconcileIntervalSec.
func (d *Daemon) reconcileLoop() {
	t := time.NewTicker(time.Duration(constants.RoutingReconcileIntervalSec) * time.Second)
	defer t.Stop()
	for {
		select {
		case <-d.stopCh:
			return
		case <-t.C:
			d.reconcileRouting(false)
		case <-d.reconcileCh:
			select {
			case <-d.stopCh:
				return
			case <-time.After(reconcileDebounce):
			}
			drainHeal(d.reconcileCh)
			d.reconcileRouting(true)
		}
	}
}

// reconcileRouting runs one repair pass. Up/Reload/Down hold d.mu, so a pass
// never interleaves with them; after our own flush+apply it finds nothing
// missing. During auto-heal the session is being rebuilt and is left alone.
func (d *Daemon) reconcileRouting(fromEvent bool) {
	if d.healing.Load() {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.active == nil {
		return
	}
	now := time.Now()
	if fromEvent && !d.repairs.allowEvent(now) {
		return // repair storm: wait for the periodic pass
	}
	res, err := d.net.Reconcile()
	if !res.Repaired() {
		if err != nil {
			d.repairs.logError(err)
		}
		return
	}
	note := repairNote(res, err)
	log.Print(note)
	if d.repairs.record(now, note) {
		log.Printf("warning: ParsVPN routing was deleted %d times within a minute — something on this host keeps removing it "+
			"(systemd-networkd ManageForeignRoutingPolicyRules, a firewall or network manager?); repairing every %ds until it stops",
			constants.RoutingRepairStormMax, constants.RoutingReconcileIntervalSec)
	}
	_ = d.persistStateLocked()
}

// repairNote is the one log line per repair, e.g.
// "policy rules missing (10/10) — restored".
func repairNote(res neteng.RepairResult, err error) string {
	var what string
	if res.RulesMissing > 0 {
		what = fmt.Sprintf("policy rules missing (%d/%d)", res.RulesMissing, res.RulesExpected)
	}
	if res.RoutesMissing > 0 {
		if what != "" {
			what += ", "
		}
		what += fmt.Sprintf("table %d routes missing (%d/%d)", constants.RouteTable, res.RoutesMissing, res.RoutesExpected)
	}
	if err == nil && res.RulesRestored == res.RulesMissing && res.RoutesRestored == res.RoutesMissing {
		return what + " — restored"
	}
	return fmt.Sprintf("%s — restored %d/%d rules, %d/%d routes: %v",
		what, res.RulesRestored, res.RulesMissing, res.RoutesRestored, res.RoutesMissing, err)
}

func (d *Daemon) routingStatusLocked() *ipc.Routing {
	h, err := d.net.RoutingHealth()
	r := &ipc.Routing{
		RulesExpected:   h.RulesExpected,
		RulesInstalled:  h.RulesInstalled,
		RoutesExpected:  h.RoutesExpected,
		RoutesInstalled: h.RoutesInstalled,
		Repairs:         d.repairs.total,
		LastRepair:      d.repairs.last,
		LastRepairNote:  d.repairs.lastNote,
	}
	if err != nil {
		r.Error = err.Error()
	}
	return r
}

// repairGuard counts routing repairs and detects a repair storm: something
// deleting our rules as fast as we restore them.
type repairGuard struct {
	recent   []time.Time // repairs within the last minute
	storm    bool
	total    int
	last     time.Time
	lastNote string
	lastErr  string
}

const repairWindow = time.Minute

func (g *repairGuard) prune(now time.Time) {
	keep := g.recent[:0]
	for _, t := range g.recent {
		if now.Sub(t) < repairWindow {
			keep = append(keep, t)
		}
	}
	g.recent = keep
	// Hysteresis: periodic repairs alone stay under the threshold, so a storm
	// only ends after a full minute without any repair.
	if g.storm && len(g.recent) == 0 {
		g.storm = false
		log.Printf("routing repairs back to normal")
	}
}

// allowEvent reports whether an event-triggered pass may run. During a storm
// only the periodic pass repairs.
func (g *repairGuard) allowEvent(now time.Time) bool {
	g.prune(now)
	return !g.storm
}

// record notes a repair and reports whether this one started a storm.
func (g *repairGuard) record(now time.Time, note string) bool {
	g.prune(now)
	g.recent = append(g.recent, now)
	g.total++
	g.last = now.UTC()
	g.lastNote = note
	g.lastErr = ""
	if !g.storm && len(g.recent) >= constants.RoutingRepairStormMax {
		g.storm = true
		return true
	}
	return false
}

// logError logs reconcile failures once per distinct message, so a
// persistent error does not repeat every pass.
func (g *repairGuard) logError(err error) {
	if msg := err.Error(); msg != g.lastErr {
		g.lastErr = msg
		log.Printf("routing reconcile: %v", err)
	}
}
