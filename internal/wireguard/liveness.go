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
	seenRX      bool      // first observe has recorded an RX baseline for this peer
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
		if !pr.seenRX {
			// First sight: record the baseline only. A nonzero counter here is a
			// pre-existing value (agent restarted against a live wg0), not fresh
			// traffic, so it must NOT seed lastAdvance — gated peers start dead.
			pr.lastRX = s.ReceiveBytes
			pr.seenRX = true
		} else if s.ReceiveBytes > pr.lastRX {
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
// explicitMode parses a CRD routeLiveness value. ok=false for "" / unrecognised
// (meaning "inherit"); an explicit "disabled" returns (ModeDisabled, true) so it
// overrides a passive/active level above it in the cascade.
func explicitMode(s string) (Mode, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case string(ModeDisabled):
		return ModeDisabled, true
	case string(ModePassive):
		return ModePassive, true
	case string(ModeActive):
		return ModeActive, true
	default:
		return ModeDisabled, false
	}
}

// resolveMode applies the cascade: per-peer > per-instance > cluster default.
func resolveMode(peerMode, instanceMode string, clusterDefault Mode) Mode {
	if m, ok := explicitMode(peerMode); ok {
		return m
	}
	if m, ok := explicitMode(instanceMode); ok {
		return m
	}
	return clusterDefault
}

// LivenessController owns the watcher goroutine and IS the LivenessSource handed
// to the Wireguard struct. It resolves a per-peer effective mode (peer > instance
// > cluster default), tracks every peer passively, probes only active-mode peers,
// and calls apply() only when a GATED peer's live state transitions.
type LivenessController struct {
	passive        *passiveLiveness
	active         *activeLiveness
	reader         deviceReader
	apply          func() error // wired to wg.Sync(latestState)
	checkInterval  time.Duration
	clusterDefault Mode
	logger         logr.Logger

	mu     sync.Mutex
	mode   map[string]Mode // effective mode per pubkey (resolved in SetPeers)
	lastUp map[string]bool // pubkey -> last observed live state (gated peers only)

	// setGauge, if set, is called on every transition with 1 (live) / 0 (down).
	setGauge func(publicKey string, value float64)
}

// modeFor returns a peer's effective mode (cluster default if not yet resolved).
func (c *LivenessController) modeFor(publicKey string) Mode {
	c.mu.Lock()
	defer c.mu.Unlock()
	if m, ok := c.mode[publicKey]; ok {
		return m
	}
	return c.clusterDefault
}

// IsLive branches on the peer's effective mode: disabled ⇒ always live (ungated,
// routes static), passive ⇒ stall signal, active ⇒ stall + probe.
func (c *LivenessController) IsLive(publicKey string) bool {
	switch c.modeFor(publicKey) {
	case ModePassive:
		return c.passive.IsLive(publicKey)
	case ModeActive:
		return c.active.IsLive(publicKey)
	default: // ModeDisabled / unknown ⇒ ungated
		return true
	}
}

// tickOnce reads the device, folds it into the passive tracker, runs the active
// probe pass, and calls apply() iff a GATED peer's live state changed this tick.
func (c *LivenessController) tickOnce() {
	stats, err := c.reader.readPeers()
	if err != nil {
		c.logger.Error(err, "liveness read failed")
		return
	}
	c.passive.observe(stats)
	c.active.probePass(stats)
	changed := false
	c.mu.Lock()
	for _, s := range stats {
		// Only gated peers participate — a disabled peer's routes are static so
		// there is nothing to (un)install on a transition.
		mode := c.mode[s.PublicKey]
		if mode != ModePassive && mode != ModeActive {
			continue
		}
		up := mode == ModePassive && c.passive.IsLive(s.PublicKey) ||
			mode == ModeActive && c.active.IsLive(s.PublicKey)
		if prev, ok := c.lastUp[s.PublicKey]; !ok || prev != up {
			c.lastUp[s.PublicKey] = up
			changed = true
			c.logger.V(1).Info("peer liveness transition", "peer", s.PublicKey, "mode", string(mode), "live", up)
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
	confirmed map[string]bool // peer has shown >=1 positive reachability signal
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
		confirmed: map[string]bool{},
	}
}

func (a *activeLiveness) setAddr(publicKey, addr string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if addr != "" {
		a.addr[publicKey] = addr
	}
}

// probePass probes quiet ACTIVE-mode peers (those with a registered addr) and
// tracks consecutive unanswered probes. The controller calls passive.observe
// separately, so this does NOT re-observe. Peers without a registered addr
// (i.e. not effective-active) are skipped entirely.
func (a *activeLiveness) probePass(stats []peerStat) {
	now := a.now()
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, s := range stats {
		pk := s.PublicKey
		addr, isActive := a.addr[pk]
		if !isActive || addr == "" {
			continue
		}
		// Passive-live (handshake / inbound progress within its window) ⇒ confirm
		// reachability: this is what lets a peer leave its start-dead state, and
		// it fires on the very first tick for a genuinely-connected peer (the
		// handshake age is absolute). An active peer is never live until proven
		// reachable this way or by a probe response.
		if a.passive.IsLive(pk) {
			a.confirmed[pk] = true
		}
		// Fresh progress within a probe interval ⇒ healthy, reset failures and
		// don't probe.
		if a.passive.freshWithin(pk, a.probeEvery) {
			a.failed[pk] = 0
			continue
		}
		// Quiet: probe if due, count this probe as failed until progress proves it.
		if now.Sub(a.lastProbe[pk]) >= a.probeEvery {
			a.prober.probe(addr)
			a.lastProbe[pk] = now
			a.failed[pk]++
		}
	}
}

func (a *activeLiveness) IsLive(publicKey string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	// Start dead: an active peer is live only once a probe pass has positively
	// confirmed reachability (fresh handshake / inbound progress) AND it has not
	// since exhausted its consecutive-unanswered-probe budget. This prevents a
	// down peer from holding its downstream routes through the initial window.
	return a.confirmed[publicKey] && a.failed[publicKey] < a.failures
}

// Config holds the env-derived liveness knobs.
type Config struct {
	Mode          Mode
	FailureCount  int           // N
	CheckInterval time.Duration // watcher tick (WG_ROUTE_CHECK_INTERVAL)
	ProbeInterval time.Duration // active probe cadence (WG_ROUTE_PROBE_INTERVAL)
}

// BuildController always returns a controller (never nil): per-peer / per-instance
// routeLiveness can enable gating even when the cluster default is disabled, so
// the watcher must run regardless. When every peer resolves to disabled it is a
// cheap no-op read loop (IsLive ⇒ true ⇒ routes static). cfg.Mode is the cluster
// default. The caller wires SetApply, feeds SetPeers, and starts Run.
func BuildController(cfg Config, reader deviceReader, logger logr.Logger) *LivenessController {
	passive := newPassiveLiveness(cfg.FailureCount, time.Now)
	active := newActiveLiveness(passive, cfg.FailureCount, cfg.ProbeInterval, time.Now, udpProber{})
	gauge := routesActiveGauge()
	return &LivenessController{
		passive:        passive,
		active:         active,
		reader:         reader,
		checkInterval:  cfg.CheckInterval,
		clusterDefault: cfg.Mode,
		logger:         logger,
		mode:           map[string]Mode{},
		lastUp:         map[string]bool{},
		setGauge:       func(pk string, v float64) { gauge.WithLabelValues(pk).Set(v) },
	}
}

// peerInfo is the minimal per-peer config the controller needs.
type peerInfo struct {
	PublicKey string
	Keepalive time.Duration
	Address   string
	Mode      string // explicit per-peer routeLiveness ("" = inherit)
}

// SetPeers resolves each peer's effective mode (peer > instance > cluster default)
// and feeds keepalive (all peers) + probe addresses (active-mode peers only).
// Safe on every state change.
func (c *LivenessController) SetPeers(instanceMode string, peers []peerInfo) {
	c.mu.Lock()
	for _, p := range peers {
		c.mode[p.PublicKey] = resolveMode(p.Mode, instanceMode, c.clusterDefault)
	}
	c.mu.Unlock()
	for _, p := range peers {
		c.passive.setKeepalive(p.PublicKey, p.Keepalive)
		if c.modeFor(p.PublicKey) == ModeActive {
			c.active.setAddr(p.PublicKey, p.Address)
		}
	}
}

// SetApply wires the controller's transition action (wg.Sync of latest state).
func (c *LivenessController) SetApply(fn func() error) { c.apply = fn }

// NewDeviceReader returns the production wgctrl-backed reader (exported for main).
func NewDeviceReader(iface string) (deviceReader, error) { return newWgctrlReader(iface) }

// InstanceMode returns the instance-level routeLiveness from the server CR.
func InstanceMode(state agent.State) string { return state.Server.Spec.RouteLiveness }

// PeerInfos extracts the controller's per-peer config from agent state.
func PeerInfos(state agent.State) []peerInfo {
	out := make([]peerInfo, 0, len(state.Peers))
	for _, p := range state.Peers {
		var k time.Duration
		if p.Spec.PersistentKeepalive != nil && *p.Spec.PersistentKeepalive > 0 {
			k = time.Duration(*p.Spec.PersistentKeepalive) * time.Second
		}
		out = append(out, peerInfo{PublicKey: p.Spec.PublicKey, Keepalive: k, Address: p.Spec.Address, Mode: p.Spec.RouteLiveness})
	}
	return out
}
