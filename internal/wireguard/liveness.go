package wireguard

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/go-logr/logr"
	"golang.zx2c4.com/wireguard/wgctrl"

	"github.com/nccloud/wireguard-operator/internal/agent"
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

// freshWithin reports whether the peer showed progress strictly within the last
// d (used by active to decide "still responding, don't probe"). Strict `<` so a
// peer that last progressed exactly d ago is treated as quiet ⇒ due for a probe.
func (p *passiveLiveness) freshWithin(publicKey string, d time.Duration) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	pr, ok := p.seen[publicKey]
	if !ok || pr.lastAdvance.IsZero() {
		return false
	}
	return p.now().Sub(pr.lastAdvance) < d
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

	// setGauge, if set, is called on every transition with 1 (live) / 0 (down).
	setGauge func(publicKey string, value float64)
}

func (c *LivenessController) IsLive(publicKey string) bool { return c.source.IsLive(publicKey) }

// tickOnce performs one read+observe+transition-detect, calling apply() iff a
// peer's live state changed this tick.
func (c *LivenessController) tickOnce() {
	stats, err := c.reader.readPeers()
	if err != nil {
		c.logger.Error(err, "liveness read failed")
		return
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
			if c.setGauge != nil {
				v := 0.0
				if up {
					v = 1.0
				}
				c.setGauge(s.PublicKey, v)
			}
		}
	}
	c.mu.Unlock()
	if changed && c.apply != nil {
		if err := c.apply(); err != nil {
			c.logger.Error(err, "liveness apply (wg.Sync) failed")
		}
	}
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

// prober forces a handshake toward a peer by sending a packet to its tunnel
// address (routed via the retained /32). Abstracted for tests.
type prober interface {
	probe(addr string)
}

// udpProber sends one byte to <addr>:9 (discard). The kernel routes it via wg0,
// which triggers a WireGuard handshake without needing the downstream route.
type udpProber struct{}

func (udpProber) probe(addr string) {
	c, err := net.DialTimeout("udp", net.JoinHostPort(addr, "9"), time.Second)
	if err != nil {
		return
	}
	defer func() { _ = c.Close() }()
	_, _ = c.Write([]byte{0})
}

// activeLiveness layers /32 probing over passive: it probes a quiet peer every
// probeEvery and marks it down after N consecutive unanswered probes. Any
// inbound progress resets the failure count.
type activeLiveness struct {
	passive    *passiveLiveness
	prober     prober
	failures   int
	probeEvery time.Duration
	now        func() time.Time

	mu        sync.Mutex
	failed    map[string]int
	lastProbe map[string]time.Time
	addr      map[string]string
}

func newActiveLiveness(passive *passiveLiveness, failures int, probeEvery time.Duration, now func() time.Time, pr prober) *activeLiveness {
	if failures < 1 {
		failures = 1
	}
	if now == nil {
		now = time.Now
	}
	return &activeLiveness{
		passive: passive, prober: pr, failures: failures, probeEvery: probeEvery, now: now,
		failed: map[string]int{}, lastProbe: map[string]time.Time{}, addr: map[string]string{},
	}
}

func (a *activeLiveness) setAddr(publicKey, addr string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if addr != "" {
		a.addr[publicKey] = addr
	}
}

// observe satisfies observer; it folds into passive then runs a probe pass.
func (a *activeLiveness) observe(stats []peerStat) { a.tick(stats) }

func (a *activeLiveness) tick(stats []peerStat) {
	a.passive.observe(stats)
	now := a.now()
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, s := range stats {
		pk := s.PublicKey
		// Fresh progress within a probe interval ⇒ healthy, reset failures.
		if a.passive.freshWithin(pk, a.probeEvery) {
			a.failed[pk] = 0
			continue
		}
		// Quiet: probe if due, count this probe as failed until progress proves it.
		if now.Sub(a.lastProbe[pk]) >= a.probeEvery {
			if addr := a.addr[pk]; addr != "" {
				a.prober.probe(addr)
			}
			a.lastProbe[pk] = now
			a.failed[pk]++
		}
	}
}

func (a *activeLiveness) IsLive(publicKey string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.failed[publicKey] < a.failures
}

// Config holds the env-derived liveness knobs.
type Config struct {
	Mode          Mode
	FailureCount  int           // N
	CheckInterval time.Duration // watcher tick (WG_ROUTE_CHECK_INTERVAL)
	ProbeInterval time.Duration // active probe cadence (WG_ROUTE_PROBE_INTERVAL)
}

// BuildController returns a configured controller, or nil for disabled mode.
// The caller wires c.SetApply and starts c.Run; for disabled mode it leaves
// Wireguard.Liveness nil (all-live, current behavior).
func BuildController(cfg Config, reader deviceReader, logger logr.Logger) *LivenessController {
	if cfg.Mode == ModeDisabled {
		return nil
	}
	passive := newPassiveLiveness(cfg.FailureCount, time.Now)
	var src observer = passive
	if cfg.Mode == ModeActive {
		src = newActiveLiveness(passive, cfg.FailureCount, cfg.ProbeInterval, time.Now, udpProber{})
	}
	gauge := routesActiveGauge()
	return &LivenessController{
		source:        src,
		reader:        reader,
		checkInterval: cfg.CheckInterval,
		logger:        logger,
		lastUp:        map[string]bool{},
		setGauge:      func(pk string, v float64) { gauge.WithLabelValues(pk).Set(v) },
	}
}

// peerInfo is the minimal per-peer config the controller needs.
type peerInfo struct {
	PublicKey string
	Keepalive time.Duration
	Address   string
}

// SetPeers feeds per-peer keepalive + (active) tunnel addresses from the latest
// state so windows and probe targets track config. Safe on every state change.
func (c *LivenessController) SetPeers(peers []peerInfo) {
	switch s := c.source.(type) {
	case *passiveLiveness:
		for _, p := range peers {
			s.setKeepalive(p.PublicKey, p.Keepalive)
		}
	case *activeLiveness:
		for _, p := range peers {
			s.passive.setKeepalive(p.PublicKey, p.Keepalive)
			s.setAddr(p.PublicKey, p.Address)
		}
	}
}

// SetApply wires the controller's transition action (wg.Sync of latest state).
func (c *LivenessController) SetApply(fn func() error) { c.apply = fn }

// NewDeviceReader returns the production wgctrl-backed reader (exported for main).
func NewDeviceReader(iface string) (deviceReader, error) { return newWgctrlReader(iface) }

// PeerInfos extracts the controller's per-peer config from agent state.
func PeerInfos(state agent.State) []peerInfo {
	out := make([]peerInfo, 0, len(state.Peers))
	for _, p := range state.Peers {
		var k time.Duration
		if p.Spec.PersistentKeepalive != nil && *p.Spec.PersistentKeepalive > 0 {
			k = time.Duration(*p.Spec.PersistentKeepalive) * time.Second
		}
		out = append(out, peerInfo{PublicKey: p.Spec.PublicKey, Keepalive: k, Address: p.Spec.Address})
	}
	return out
}
