package wireguard

import (
	"testing"
	"time"

	"github.com/nccloud/wireguard-operator/api/v1alpha1"
)

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

func TestController_AppliesOnlyOnTransition(t *testing.T) {
	clk := ts(1000)
	pass := newPassiveLiveness(3, func() time.Time { return clk })
	pass.setKeepalive("k", 25*time.Second)
	applied := 0
	c := &LivenessController{
		source: pass,
		reader: fakeReader{peers: []peerStat{{PublicKey: "k", ReceiveBytes: 100}}},
		apply:  func() error { applied++; return nil },
		lastUp: map[string]bool{},
	}
	c.tickOnce() // first observation: k transitions absent->live
	if applied != 1 {
		t.Fatalf("expected 1 apply on first up-transition, got %d", applied)
	}
	c.tickOnce() // no change ⇒ no apply
	if applied != 1 {
		t.Fatalf("quiet tick must not apply, got %d", applied)
	}
	clk = ts(1100) // 100s later, > 75s window, no new bytes
	c.reader = fakeReader{peers: []peerStat{{PublicKey: "k", ReceiveBytes: 100}}}
	c.tickOnce() // live->not-live transition
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
	p.observe([]peerStat{{PublicKey: "k", ReceiveBytes: 100}})
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
	p.observe([]peerStat{{PublicKey: "k", ReceiveBytes: 100}})
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
