package wireguard

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/go-logr/logr"
	"golang.zx2c4.com/wireguard/wgctrl"
)

// LivenessSource decides whether a peer's downstream routes (spec.routes /
// spec.routesV6) should currently be installed. A nil source means "all peers
// live" — i.e. disabled mode, byte-identical to the pre-feature behavior.
type LivenessSource interface {
	IsLive(publicKey string) bool
}

// isLive is the nil-safe accessor used by the route filters.
func isLive(src LivenessSource, publicKey string) bool {
	if src == nil {
		return true
	}
	return src.IsLive(publicKey)
}

// Mode selects the LivenessSource implementation.
type Mode string

const (
	ModeDisabled Mode = "disabled"
	ModePassive  Mode = "passive"
	ModeActive   Mode = "active"
)

// ParseMode maps an env value to a Mode; anything unrecognised (incl. empty)
// is treated as disabled so a misconfig fails safe to current behavior.
func ParseMode(s string) Mode {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case string(ModePassive):
		return ModePassive
	case string(ModeActive):
		return ModeActive
	default:
		return ModeDisabled
	}
}

// rejectAfterTime is WireGuard's REJECT_AFTER_TIME (seconds) — a session key is
// dead after this with no new handshake. Used as the keepalive-less passive
// down threshold.
const rejectAfterTime = 180 // seconds

// peerStat is the liveness-relevant snapshot of one wg peer.
type peerStat struct {
	PublicKey         string
	LastHandshakeTime time.Time
	ReceiveBytes      int64
}

// deviceReader yields a snapshot of all peers' counters. Abstracted so the
// liveness logic is unit-testable without a real wg0 / root / netlink.
type deviceReader interface {
	readPeers() ([]peerStat, error)
}

// wgctrlReader reads the live device via a long-lived wgctrl client.
type wgctrlReader struct {
	client *wgctrl.Client
	iface  string
}

func newWgctrlReader(iface string) (*wgctrlReader, error) {
	c, err := wgctrl.New()
	if err != nil {
		return nil, err
	}
	return &wgctrlReader{client: c, iface: iface}, nil
}

func (w *wgctrlReader) readPeers() ([]peerStat, error) {
	dev, err := w.client.Device(w.iface)
	if err != nil {
		return nil, err
	}
	out := make([]peerStat, 0, len(dev.Peers))
	for _, p := range dev.Peers {
		out = append(out, peerStat{
			PublicKey:         p.PublicKey.String(),
			LastHandshakeTime: p.LastHandshakeTime,
			ReceiveBytes:      p.ReceiveBytes,
		})
	}
	return out, nil
}

func (w *wgctrlReader) Close() error { return w.client.Close() }

type progress struct {
	lastRX      int64
	lastAdvance time.Time // most recent of {observed RX increase, handshake time}
}

// passiveLiveness derives liveness from counters in the wgctrl device read with
// zero added traffic: a peer is live while its last-progress age is within a
// per-peer window (N × keepalive, or REJECT_AFTER_TIME when no keepalive).
type passiveLiveness struct {
	mu        sync.Mutex
	seen      map[string]progress
	keepalive map[string]time.Duration // per-peer, from spec.PersistentKeepalive
	failures  int                      // N (WG_ROUTE_FAILURE_COUNT)
	now       func() time.Time
}

func newPassiveLiveness(failures int, now func() time.Time) *passiveLiveness {
	if failures < 1 {
		failures = 1
	}
	if now == nil {
		now = time.Now
	}
	return &passiveLiveness{
		seen:      map[string]progress{},
		keepalive: map[string]time.Duration{},
		failures:  failures,
		now:       now,
	}
}

// setKeepalive records a peer's keepalive interval (0/absent ⇒ 180s fallback).
func (p *passiveLiveness) setKeepalive(publicKey string, k time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if k > 0 {
		p.keepalive[publicKey] = k
	} else {
		delete(p.keepalive, publicKey)
	}
}

// observe folds a device snapshot into per-peer last-progress.
func (p *passiveLiveness) observe(stats []peerStat) {
	now := p.now()
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, s := range stats {
		pr := p.seen[s.PublicKey]
		if s.ReceiveBytes > pr.lastRX {
			pr.lastRX = s.ReceiveBytes
			pr.lastAdvance = now
		}
		if s.LastHandshakeTime.After(pr.lastAdvance) {
			pr.lastAdvance = s.LastHandshakeTime
		}
		p.seen[s.PublicKey] = pr
	}
}

// downWindow is the per-peer staleness threshold. Caller must hold p.mu.
func (p *passiveLiveness) downWindow(publicKey string) time.Duration {
	if k, ok := p.keepalive[publicKey]; ok && k > 0 {
		return time.Duration(p.failures) * k
	}
	return rejectAfterTime * time.Second
}

// freshWithin reports whether the peer showed progress within d (used by active).
func (p *passiveLiveness) freshWithin(publicKey string, d time.Duration) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	pr, ok := p.seen[publicKey]
	if !ok || pr.lastAdvance.IsZero() {
		return false
	}
	return p.now().Sub(pr.lastAdvance) <= d
}

func (p *passiveLiveness) IsLive(publicKey string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	pr, ok := p.seen[publicKey]
	if !ok || pr.lastAdvance.IsZero() {
		return false
	}
	return p.now().Sub(pr.lastAdvance) <= p.downWindow(publicKey)
}

// observer is the subset of a liveness source the controller drives each tick.
type observer interface {
	LivenessSource
	observe([]peerStat)
}

// LivenessController owns the watcher goroutine. It reads the device on a timer,
// folds it into the source, and calls apply() only when a peer's live state
// transitions. It also IS the LivenessSource handed to the Wireguard struct.
type LivenessController struct {
	source        observer
	reader        deviceReader
	apply         func() error // wired to wg.Sync(latestState)
	checkInterval time.Duration
	logger        logr.Logger

	mu     sync.Mutex
	lastUp map[string]bool // pubkey -> last observed live state
}

func (c *LivenessController) IsLive(publicKey string) bool { return c.source.IsLive(publicKey) }

// tickOnce performs one read+observe+transition-detect. Returns whether it applied.
func (c *LivenessController) tickOnce() bool {
	stats, err := c.reader.readPeers()
	if err != nil {
		c.logger.Error(err, "liveness read failed")
		return false
	}
	c.source.observe(stats)
	changed := false
	c.mu.Lock()
	for _, s := range stats {
		up := c.source.IsLive(s.PublicKey)
		if prev, ok := c.lastUp[s.PublicKey]; !ok || prev != up {
			c.lastUp[s.PublicKey] = up
			changed = true
			c.logger.V(1).Info("peer liveness transition", "peer", s.PublicKey, "live", up)
		}
	}
	c.mu.Unlock()
	if changed && c.apply != nil {
		if err := c.apply(); err != nil {
			c.logger.Error(err, "liveness apply (wg.Sync) failed")
		}
		return true
	}
	return false
}

// Run drives tickOnce every checkInterval until ctx is done.
func (c *LivenessController) Run(ctx context.Context) {
	t := time.NewTicker(c.checkInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.tickOnce()
		}
	}
}
