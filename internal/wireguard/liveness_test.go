package wireguard

import (
	"testing"

	"github.com/nccloud/wireguard-operator/api/v1alpha1"
)

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
