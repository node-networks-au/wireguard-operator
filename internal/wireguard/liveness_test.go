package wireguard

import (
	"testing"
	"time"

	"github.com/go-logr/logr"

	"github.com/nccloud/wireguard-operator/api/v1alpha1"
	"github.com/nccloud/wireguard-operator/internal/agent"
)

func TestBuildController_AlwaysBuiltAndClusterDefaultUngated(t *testing.T) {
	// Always non-nil now: per-peer/per-instance can enable even when the cluster
	// default is disabled, so the watcher must run regardless.
	for _, m := range []Mode{ModeDisabled, ModePassive, ModeActive} {
		c := BuildController(Config{Mode: m, FailureCount: 3, CheckInterval: time.Second, ProbeInterval: 15 * time.Second}, fakeReader{}, logr.Discard())
		if c == nil {
			t.Fatalf("cluster default %q must still yield a controller", m)
		}
	}
	// With cluster default disabled, an unresolved peer is ungated (always live).
	c := BuildController(Config{Mode: ModeDisabled, FailureCount: 3, CheckInterval: time.Second, ProbeInterval: 15 * time.Second}, fakeReader{}, logr.Discard())
	if !c.IsLive("unknown") {
		t.Fatal("cluster-default-disabled peer must be ungated (always live)")
	}
}

func TestResolveMode_Cascade(t *testing.T) {
	cases := []struct {
		peer, inst string
		def        Mode
		want       Mode
	}{
		{"", "", ModeDisabled, ModeDisabled},              // nothing set ⇒ default
		{"", "", ModePassive, ModePassive},                // cluster default applies
		{"", "active", ModeDisabled, ModeActive},          // instance overrides default
		{"passive", "active", ModeDisabled, ModePassive},  // peer overrides instance
		{"disabled", "active", ModePassive, ModeDisabled}, // explicit disabled overrides downward
		{"bogus", "", ModePassive, ModePassive},           // unrecognised peer ⇒ inherit
	}
	for _, tc := range cases {
		if got := resolveMode(tc.peer, tc.inst, tc.def); got != tc.want {
			t.Errorf("resolveMode(%q,%q,%q)=%q want %q", tc.peer, tc.inst, tc.def, got, tc.want)
		}
	}
}

func TestController_PerPeerModeResolution(t *testing.T) {
	clk := ts(1000)
	pass := newPassiveLiveness(3, func() time.Time { return clk })
	c := &LivenessController{
		passive:        pass,
		active:         newActiveLiveness(pass, 3, 15*time.Second, func() time.Time { return clk }, proberFunc(func(string) {})),
		clusterDefault: ModeDisabled,
		mode:           map[string]Mode{},
		lastUp:         map[string]bool{},
	}
	// instance=active; DC1 explicitly disabled (fallback); DC2 inherits active.
	// Both are site peers carrying downstream routes — without routes there would
	// be nothing to gate and both would resolve to disabled.
	c.SetPeers("active", []peerInfo{
		{PublicKey: "dc1", Mode: "disabled", Keepalive: 25 * time.Second, Address: "172.31.255.11", HasRoutes: true},
		{PublicKey: "dc2", Mode: "", Keepalive: 25 * time.Second, Address: "172.31.255.12", HasRoutes: true},
	})
	if c.modeFor("dc1") != ModeDisabled {
		t.Errorf("dc1 explicit disabled, got %s", c.modeFor("dc1"))
	}
	if c.modeFor("dc2") != ModeActive {
		t.Errorf("dc2 should inherit instance active, got %s", c.modeFor("dc2"))
	}
	if !c.IsLive("dc1") {
		t.Error("dc1 (disabled) must be ungated / always live")
	}
}

func TestController_RouteLessPeerIsNeverGated(t *testing.T) {
	// A peer with no routes has nothing to install or withdraw, so gating it can
	// never change forwarding — it only produces pointless liveness transitions,
	// each of which triggers an apply()/state push. Road-warrior peers (laptops
	// that come and go) are exactly this shape, and their churn was driving
	// fleet-wide state pushes. Such peers must be ungated regardless of mode.
	clk := ts(1000)
	pass := newPassiveLiveness(3, func() time.Time { return clk })
	c := &LivenessController{
		passive:        pass,
		active:         newActiveLiveness(pass, 3, 15*time.Second, func() time.Time { return clk }, proberFunc(func(string) {})),
		clusterDefault: ModeActive,
		mode:           map[string]Mode{},
		lastUp:         map[string]bool{},
	}
	c.SetPeers("active", []peerInfo{
		{PublicKey: "roadwarrior", Mode: "", Keepalive: 25 * time.Second, Address: "172.31.255.8", HasRoutes: false},
		{PublicKey: "site", Mode: "", Keepalive: 25 * time.Second, Address: "172.31.255.3", HasRoutes: true},
	})
	if got := c.modeFor("roadwarrior"); got != ModeDisabled {
		t.Errorf("route-less peer must be ungated, got mode %q", got)
	}
	if !c.IsLive("roadwarrior") {
		t.Error("route-less peer must always be live (nothing to gate)")
	}
	// A peer that does carry routes still inherits the active mode.
	if got := c.modeFor("site"); got != ModeActive {
		t.Errorf("peer with routes should inherit active, got %q", got)
	}
}

func TestController_RouteLessPeerIgnoresExplicitActive(t *testing.T) {
	// Even an explicit routeLiveness=active is meaningless without routes.
	clk := ts(1000)
	pass := newPassiveLiveness(3, func() time.Time { return clk })
	c := &LivenessController{
		passive:        pass,
		active:         newActiveLiveness(pass, 3, 15*time.Second, func() time.Time { return clk }, proberFunc(func(string) {})),
		clusterDefault: ModeDisabled,
		mode:           map[string]Mode{},
		lastUp:         map[string]bool{},
	}
	c.SetPeers("", []peerInfo{
		{PublicKey: "rw", Mode: "active", Keepalive: 25 * time.Second, Address: "172.31.255.9", HasRoutes: false},
	})
	if got := c.modeFor("rw"); got != ModeDisabled {
		t.Errorf("route-less peer must be ungated even when explicitly active, got %q", got)
	}
}

func TestPeerInfos_DerivesHasRoutesFromSpec(t *testing.T) {
	state := agent.State{Peers: []v1alpha1.WireguardPeer{
		{Spec: v1alpha1.WireguardPeerSpec{PublicKey: "none", Address: "172.31.255.8"}},
		{Spec: v1alpha1.WireguardPeerSpec{PublicKey: "v4", Address: "172.31.255.3", Routes: []string{"10.254.0.0/16"}}},
		{Spec: v1alpha1.WireguardPeerSpec{PublicKey: "v6", Address: "172.31.255.4", RoutesV6: []string{"fd00::/64"}}},
	}}
	got := map[string]bool{}
	for _, p := range PeerInfos(state) {
		got[p.PublicKey] = p.HasRoutes
	}
	if got["none"] {
		t.Error("peer without routes should have HasRoutes=false")
	}
	if !got["v4"] {
		t.Error("peer with IPv4 routes should have HasRoutes=true")
	}
	if !got["v6"] {
		t.Error("peer with only IPv6 routes should have HasRoutes=true")
	}
}

func TestPeerStat_FakeReaderRoundTrips(t *testing.T) {
	now := time.Unix(1000, 0)
	r := fakeReader{peers: []peerStat{{PublicKey: "k", LastHandshakeTime: now, ReceiveBytes: 42}}}
	got, err := r.readPeers()
	if err != nil || len(got) != 1 || got[0].ReceiveBytes != 42 || got[0].PublicKey != "k" {
		t.Fatalf("readPeers = %+v, %v", got, err)
	}
}

type fakeReader struct {
	peers []peerStat
	err   error
}

func (f fakeReader) readPeers() ([]peerStat, error) { return f.peers, f.err }

func ts(sec int64) time.Time { return time.Unix(sec, 0) }

func TestController_SetsRoutesActiveGauge(t *testing.T) {
	clk := ts(1000)
	pass := newPassiveLiveness(3, func() time.Time { return clk })
	pass.setKeepalive("k", 25*time.Second)
	var lastPK string
	var lastVal float64
	c := &LivenessController{
		passive:  pass,
		active:   newActiveLiveness(pass, 3, 15*time.Second, func() time.Time { return clk }, proberFunc(func(string) {})),
		reader:   fakeReader{peers: []peerStat{{PublicKey: "k", ReceiveBytes: 100, LastHandshakeTime: ts(990)}}},
		apply:    func() error { return nil },
		mode:     map[string]Mode{"k": ModePassive},
		lastUp:   map[string]bool{},
		setGauge: func(pk string, v float64) { lastPK = pk; lastVal = v },
	}
	c.tickOnce() // fresh handshake (absolute) ⇒ live on the first tick
	if lastPK != "k" || lastVal != 1 {
		t.Fatalf("gauge = (%q,%v), want (k,1) on up-transition", lastPK, lastVal)
	}
}

func TestActive_DownAfterNUnansweredProbes(t *testing.T) {
	clk := ts(1000)
	pass := newPassiveLiveness(3, func() time.Time { return clk })
	pass.setKeepalive("k", 25*time.Second)
	pass.observe([]peerStat{{PublicKey: "k", ReceiveBytes: 100, LastHandshakeTime: ts(995)}}) // baseline + fresh handshake
	probes := 0
	a := newActiveLiveness(pass, 3, 15*time.Second, func() time.Time { return clk }, proberFunc(func(string) { probes++ }))
	a.setAddr("k", "172.31.255.11")
	a.probePass([]peerStat{{PublicKey: "k", ReceiveBytes: 100, LastHandshakeTime: ts(995)}}) // confirm reachable ⇒ live
	if !a.IsLive("k") {
		t.Fatal("starts live")
	}
	// advance past window with no progress; each probe interval => one failed probe.
	// Mirror the controller: observe (no RX change) then probePass.
	for i := 1; i <= 3; i++ {
		clk = ts(1000 + int64(i)*15)
		pass.observe([]peerStat{{PublicKey: "k", ReceiveBytes: 100}})
		a.probePass([]peerStat{{PublicKey: "k", ReceiveBytes: 100}})
	}
	if probes < 3 {
		t.Fatalf("expected >=3 probes, got %d", probes)
	}
	if a.IsLive("k") {
		t.Fatal("peer must be down after N unanswered probes")
	}
}

func TestActive_ProbeResponseRevives(t *testing.T) {
	clk := ts(1000)
	pass := newPassiveLiveness(3, func() time.Time { return clk })
	pass.setKeepalive("k", 25*time.Second)
	pass.observe([]peerStat{{PublicKey: "k", ReceiveBytes: 100}})
	a := newActiveLiveness(pass, 3, 15*time.Second, func() time.Time { return clk }, proberFunc(func(string) {}))
	a.setAddr("k", "172.31.255.11")
	clk = ts(1016)
	pass.observe([]peerStat{{PublicKey: "k", ReceiveBytes: 100}})
	a.probePass([]peerStat{{PublicKey: "k", ReceiveBytes: 100}}) // 1 failed probe
	clk = ts(1031)
	pass.observe([]peerStat{{PublicKey: "k", ReceiveBytes: 200}}) // RX advanced
	a.probePass([]peerStat{{PublicKey: "k", ReceiveBytes: 200}})  // fresh ⇒ revive
	if !a.IsLive("k") {
		t.Fatal("inbound progress must reset failure count and keep peer live")
	}
}

type proberFunc func(addr string)

func (f proberFunc) probe(addr string) { f(addr) }

func TestController_AppliesOnlyOnTransition(t *testing.T) {
	clk := ts(1000)
	pass := newPassiveLiveness(3, func() time.Time { return clk })
	pass.setKeepalive("k", 25*time.Second)
	applied := 0
	c := &LivenessController{
		passive: pass,
		active:  newActiveLiveness(pass, 3, 15*time.Second, func() time.Time { return clk }, proberFunc(func(string) {})),
		reader:  fakeReader{peers: []peerStat{{PublicKey: "k", ReceiveBytes: 100, LastHandshakeTime: ts(995)}}},
		apply:   func() error { applied++; return nil },
		mode:    map[string]Mode{"k": ModePassive},
		lastUp:  map[string]bool{},
	}
	c.tickOnce() // first observation: fresh handshake ⇒ k transitions dead->live
	if applied != 1 {
		t.Fatalf("expected 1 apply on first up-transition, got %d", applied)
	}
	c.tickOnce() // no change ⇒ no apply
	if applied != 1 {
		t.Fatalf("quiet tick must not apply, got %d", applied)
	}
	clk = ts(1100) // 100s later, > 75s window, no new bytes
	c.tickOnce()   // live->not-live transition
	if applied != 2 {
		t.Fatalf("expected apply on down-transition, got %d", applied)
	}
}

func TestPassive_NeverActiveIsNotLive(t *testing.T) {
	clk := ts(1000)
	p := newPassiveLiveness(3, func() time.Time { return clk })
	p.setKeepalive("k", 25*time.Second)
	p.observe([]peerStat{{PublicKey: "k", ReceiveBytes: 0}}) // never any progress
	if p.IsLive("k") {
		t.Fatal("never-active peer must be not-live")
	}
}

func TestPassive_LiveWhileReceiveBytesAdvance(t *testing.T) {
	clk := ts(1000)
	p := newPassiveLiveness(3, func() time.Time { return clk })
	p.setKeepalive("k", 25*time.Second) // downWindow = 75s
	// First observe is a baseline only; a fresh handshake is the absolute signal
	// that makes the peer live within its window from the start.
	p.observe([]peerStat{{PublicKey: "k", ReceiveBytes: 100, LastHandshakeTime: ts(1000)}})
	clk = ts(1050) // 50s later, still within 75s
	if !p.IsLive("k") {
		t.Fatal("peer within downWindow must be live")
	}
}

func TestPassive_DownAfterNKeepalivesMissed(t *testing.T) {
	clk := ts(1000)
	p := newPassiveLiveness(3, func() time.Time { return clk })
	p.setKeepalive("k", 25*time.Second) // downWindow = 75s
	p.observe([]peerStat{{PublicKey: "k", ReceiveBytes: 100}})
	clk = ts(1076) // 76s later, > 75s, no new bytes
	p.observe([]peerStat{{PublicKey: "k", ReceiveBytes: 100}})
	if p.IsLive("k") {
		t.Fatal("peer silent > N*keepalive must be not-live")
	}
}

func TestPassive_KeepaliveLessFallsBackTo180s(t *testing.T) {
	clk := ts(1000)
	p := newPassiveLiveness(3, func() time.Time { return clk })
	// no setKeepalive ⇒ 180s fallback
	p.observe([]peerStat{{PublicKey: "k", ReceiveBytes: 100, LastHandshakeTime: ts(1000)}})
	clk = ts(1170) // 170s < 180s
	if !p.IsLive("k") {
		t.Fatal("keepalive-less peer within 180s must be live")
	}
	clk = ts(1181) // 181s > 180s
	if p.IsLive("k") {
		t.Fatal("keepalive-less peer past 180s must be not-live")
	}
}

func TestPassive_HandshakeCountsAsProgress(t *testing.T) {
	clk := ts(2000)
	p := newPassiveLiveness(3, func() time.Time { return clk })
	p.setKeepalive("k", 25*time.Second)
	// no RX increase, but a fresh handshake at t=1990
	p.observe([]peerStat{{PublicKey: "k", ReceiveBytes: 0, LastHandshakeTime: ts(1990)}})
	if !p.IsLive("k") {
		t.Fatal("recent handshake must keep peer live even without RX delta")
	}
}

func TestWireguard_LivenessFieldDefaultsNil(t *testing.T) {
	wg := Wireguard{}
	if wg.Liveness != nil {
		t.Fatal("Liveness must default nil (disabled / all-live)")
	}
}

func TestPeerAllowedIPs_NotLiveDropsRoutesKeepsBase(t *testing.T) {
	peer := v1alpha1.WireguardPeer{Spec: v1alpha1.WireguardPeerSpec{
		PublicKey: validPeerPublicKey, Address: "172.31.255.11",
		Routes: []string{"10.254.2.0/24", "192.168.0.0/16"},
	}}
	live := peerAllowedIPs(peer, fakeSource{live: map[string]bool{validPeerPublicKey: true}})
	if live != "172.31.255.11/32,10.254.2.0/24,192.168.0.0/16" {
		t.Errorf("live peer = %q, want base+routes", live)
	}
	down := peerAllowedIPs(peer, fakeSource{live: map[string]bool{validPeerPublicKey: false}})
	if down != "172.31.255.11/32" {
		t.Errorf("not-live peer = %q, want base /32 only", down)
	}
	none := peerAllowedIPs(peer, nil) // disabled ⇒ all live
	if none != "172.31.255.11/32,10.254.2.0/24,192.168.0.0/16" {
		t.Errorf("nil source = %q, want base+routes (unchanged)", none)
	}
}

func TestIsLive_NilSourceIsAllLive(t *testing.T) {
	if !isLive(nil, "anykey") {
		t.Fatal("nil LivenessSource must report all peers live (disabled mode)")
	}
}

func TestIsLive_DelegatesToSource(t *testing.T) {
	src := fakeSource{live: map[string]bool{"up": true, "down": false}}
	if !isLive(src, "up") {
		t.Error("expected up live")
	}
	if isLive(src, "down") {
		t.Error("expected down not-live")
	}
	if isLive(src, "unknown") {
		t.Error("expected unknown (absent) not-live")
	}
}

func TestParseMode(t *testing.T) {
	cases := map[string]Mode{"": ModeDisabled, "disabled": ModeDisabled, "passive": ModePassive, "active": ModeActive, "PASSIVE": ModePassive, "bogus": ModeDisabled}
	for in, want := range cases {
		if got := ParseMode(in); got != want {
			t.Errorf("ParseMode(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDesiredKernelRoutes_GatedByLiveness(t *testing.T) {
	peers := []v1alpha1.WireguardPeer{
		{Spec: v1alpha1.WireguardPeerSpec{PublicKey: validPeerPublicKey, Address: "10.0.0.1", Routes: []string{"10.254.1.0/24"}}},
		{Spec: v1alpha1.WireguardPeerSpec{PublicKey: validPeerPublicKey2, Address: "10.0.0.2", Routes: []string{"10.254.2.0/24"}}},
	}
	src := fakeSource{live: map[string]bool{validPeerPublicKey: true, validPeerPublicKey2: false}}
	got := desiredKernelRoutes(peers, src)
	if len(got) != 1 || got[0] != "10.254.1.0/24" {
		t.Errorf("gated desiredKernelRoutes = %v, want [10.254.1.0/24] (down peer's /24 excluded)", got)
	}
	all := desiredKernelRoutes(peers, nil) // disabled ⇒ both
	if len(all) != 2 {
		t.Errorf("nil source = %v, want both routes (unchanged)", all)
	}
}

type fakeSource struct{ live map[string]bool }

func (f fakeSource) IsLive(pk string) bool { return f.live[pk] }

// --- start-dead semantics: gated peers must NOT hold routes until confirmed ---

// A gated (passive) peer with a stale wgctrl counter but no recent handshake
// must start DEAD on the first observation, so desiredKernelRoutes excludes its
// downstream CIDR (no blackhole during the initial window). The stale nonzero
// ReceiveBytes is a pre-existing counter (agent restarted against a live wg0),
// not fresh traffic.
func TestPassive_StartsDeadWithStaleCounterNoHandshake(t *testing.T) {
	clk := ts(1000)
	p := newPassiveLiveness(3, func() time.Time { return clk })
	p.setKeepalive("k", 25*time.Second)
	// Counter already nonzero at first sight; handshake is old (outside window).
	p.observe([]peerStat{{PublicKey: "k", ReceiveBytes: 100, LastHandshakeTime: ts(800)}})
	if p.IsLive("k") {
		t.Fatal("gated peer with stale counter / no fresh handshake must start dead")
	}
	// And its routes must NOT be installed.
	peers := []v1alpha1.WireguardPeer{
		{Spec: v1alpha1.WireguardPeerSpec{PublicKey: validPeerPublicKey, Address: "10.0.0.1", Routes: []string{"10.254.2.0/24"}}},
	}
	src := fakeSource{live: map[string]bool{validPeerPublicKey: p.IsLive("k")}}
	if got := desiredKernelRoutes(peers, src); len(got) != 0 {
		t.Fatalf("dead gated peer must install no routes, got %v", got)
	}
}

// A gated (active) peer must also start DEAD on the first observation: with the
// cluster default of active, a down site peer must not hold its /24 through the
// ~N*probeInterval window. Only a confirmed probe / progress revives it.
func TestActive_StartsDeadUntilConfirmed(t *testing.T) {
	clk := ts(1000)
	pass := newPassiveLiveness(3, func() time.Time { return clk })
	pass.setKeepalive("k", 25*time.Second)
	a := newActiveLiveness(pass, 3, 15*time.Second, func() time.Time { return clk }, proberFunc(func(string) {}))
	a.setAddr("k", "172.31.255.11")
	// Stale counter, no fresh handshake — exactly the production down-peer case.
	pass.observe([]peerStat{{PublicKey: "k", ReceiveBytes: 100, LastHandshakeTime: ts(800)}})
	if a.IsLive("k") {
		t.Fatal("active peer must start dead before any probe/progress confirms it")
	}
	a.probePass([]peerStat{{PublicKey: "k", ReceiveBytes: 100, LastHandshakeTime: ts(800)}})
	if a.IsLive("k") {
		t.Fatal("an unanswered/quiet active peer must remain dead (no confirmation)")
	}
}

// A gated (passive) peer with a FRESH handshake must be live on the very first
// check — the handshake age is absolute, so live peers get their routes back
// within ~one check interval of startup rather than blackholing.
func TestPassive_FreshHandshakeLiveOnFirstCheck(t *testing.T) {
	clk := ts(1000)
	p := newPassiveLiveness(3, func() time.Time { return clk })
	p.setKeepalive("k", 25*time.Second)
	p.observe([]peerStat{{PublicKey: "k", ReceiveBytes: 100, LastHandshakeTime: ts(990)}})
	if !p.IsLive("k") {
		t.Fatal("gated peer with a fresh handshake must be live on the first check")
	}
}

// A gated (active) peer with a fresh handshake confirms and is live on the first
// probe pass (tick 1), without waiting for a probe round-trip.
func TestActive_FreshHandshakeLiveOnFirstCheck(t *testing.T) {
	clk := ts(1000)
	pass := newPassiveLiveness(3, func() time.Time { return clk })
	pass.setKeepalive("k", 25*time.Second)
	a := newActiveLiveness(pass, 3, 15*time.Second, func() time.Time { return clk }, proberFunc(func(string) {}))
	a.setAddr("k", "172.31.255.11")
	pass.observe([]peerStat{{PublicKey: "k", ReceiveBytes: 100, LastHandshakeTime: ts(990)}})
	a.probePass([]peerStat{{PublicKey: "k", ReceiveBytes: 100, LastHandshakeTime: ts(990)}})
	if !a.IsLive("k") {
		t.Fatal("active peer with a fresh handshake must be live on the first check")
	}
}

// A disabled-mode peer is ALWAYS live from the start (no initial gap): it is a
// fallback gateway whose routes must be installed immediately. The controller's
// IsLive short-circuits to true for disabled mode regardless of any counter.
func TestController_DisabledPeerAlwaysLiveFromStart(t *testing.T) {
	clk := ts(1000)
	pass := newPassiveLiveness(3, func() time.Time { return clk })
	c := &LivenessController{
		passive:        pass,
		active:         newActiveLiveness(pass, 3, 15*time.Second, func() time.Time { return clk }, proberFunc(func(string) {})),
		clusterDefault: ModeActive,
		mode:           map[string]Mode{"gw": ModeDisabled},
		lastUp:         map[string]bool{},
	}
	// No observation at all — a disabled peer must still be live immediately.
	if !c.IsLive("gw") {
		t.Fatal("disabled-mode peer must be always-live from the start (fallback gateway)")
	}
}
