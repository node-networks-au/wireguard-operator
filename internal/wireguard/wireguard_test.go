package wireguard

import (
	"strings"
	"testing"

	"github.com/nccloud/wireguard-operator/api/v1alpha1"
	"github.com/nccloud/wireguard-operator/internal/agent"
)

// validServerPrivateKey is a syntactically valid 44-char base64 wgtypes key.
// wgtypes.ParseKey only validates length+base64 form, not key-pair correctness,
// so a constant fixture is sufficient for config-string generation tests.
const validServerPrivateKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

// validPeerPublicKey is another syntactically valid 44-char base64 wgtypes key.
const validPeerPublicKey = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA="

const validPeerPublicKey2 = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA="

// TestBuildWgQuickConfig_PreservesMultiCIDRAllowedIPs is the canary for the
// Phase E fix. Upstream's wgctrl-based path constructed each PeerConfig with
// only `<addr>/32` and then called ConfigureDevice with ReplaceAllowedIPs=true,
// which truncated downstream-LAN CIDRs that ops added via
// WireguardPeer.spec.allowedIPs. The new wg-syncconf path must read that
// field and emit it verbatim into the [Peer] AllowedIPs CSV.
func TestBuildWgQuickConfig_PreservesMultiCIDRAllowedIPs(t *testing.T) {
	state := agent.State{
		ServerPrivateKey: validServerPrivateKey,
		Server: v1alpha1.Wireguard{
			Spec: v1alpha1.WireguardSpec{},
		},
		Peers: []v1alpha1.WireguardPeer{
			{
				Spec: v1alpha1.WireguardPeerSpec{
					PublicKey:  validPeerPublicKey,
					Address:    "172.31.255.11",
					AllowedIPs: "172.31.255.11/32,10.254.0.0/16",
				},
			},
		},
	}

	cfg, err := BuildWgQuickConfig(state, 51820)
	if err != nil {
		t.Fatalf("BuildWgQuickConfig: %v", err)
	}

	if !strings.Contains(cfg, "172.31.255.11/32") {
		t.Errorf("config missing peer /32:\n%s", cfg)
	}
	if !strings.Contains(cfg, "10.254.0.0/16") {
		t.Errorf("config missing extra LAN CIDR — this is the wgctrl truncation bug:\n%s", cfg)
	}
	if !strings.Contains(cfg, "PublicKey = "+validPeerPublicKey) {
		t.Errorf("config missing peer PublicKey:\n%s", cfg)
	}
}

// TestBuildWgQuickConfig_NoSpecAllowedIPs covers the backwards-compat path:
// a peer with only Address (no AllowedIPs CSV) must still produce a usable
// [Peer] section with the implicit /32. This guards against regressing existing
// peers that don't know about the new spec field.
func TestBuildWgQuickConfig_NoSpecAllowedIPs(t *testing.T) {
	state := agent.State{
		ServerPrivateKey: validServerPrivateKey,
		Server:           v1alpha1.Wireguard{},
		Peers: []v1alpha1.WireguardPeer{
			{
				Spec: v1alpha1.WireguardPeerSpec{
					PublicKey: validPeerPublicKey,
					Address:   "172.31.255.11",
				},
			},
		},
	}

	cfg, err := BuildWgQuickConfig(state, 51820)
	if err != nil {
		t.Fatalf("BuildWgQuickConfig: %v", err)
	}

	if !strings.Contains(cfg, "172.31.255.11/32") {
		t.Errorf("config missing peer /32:\n%s", cfg)
	}
}

// TestBuildWgQuickConfig_InterfaceSection asserts the [Interface] block carries
// the server PrivateKey and ListenPort that wg syncconf needs.
func TestBuildWgQuickConfig_InterfaceSection(t *testing.T) {
	state := agent.State{
		ServerPrivateKey: validServerPrivateKey,
		Server:           v1alpha1.Wireguard{},
		Peers:            nil,
	}

	cfg, err := BuildWgQuickConfig(state, 51820)
	if err != nil {
		t.Fatalf("BuildWgQuickConfig: %v", err)
	}

	if !strings.Contains(cfg, "[Interface]") {
		t.Errorf("config missing [Interface] header:\n%s", cfg)
	}
	if !strings.Contains(cfg, "PrivateKey = "+validServerPrivateKey) {
		t.Errorf("config missing server PrivateKey line:\n%s", cfg)
	}
	if !strings.Contains(cfg, "ListenPort = 51820") {
		t.Errorf("config missing ListenPort line:\n%s", cfg)
	}
}

// TestBuildWgQuickConfig_SkipsDisabledAndEmptyKeys verifies the same filtering
// invariants the old wgctrl path enforced: disabled peers and peers without a
// PublicKey or any address must not appear in the rendered config (otherwise
// wg syncconf would either error or leave a dangling peer).
func TestBuildWgQuickConfig_SkipsDisabledAndEmptyKeys(t *testing.T) {
	state := agent.State{
		ServerPrivateKey: validServerPrivateKey,
		Server:           v1alpha1.Wireguard{},
		Peers: []v1alpha1.WireguardPeer{
			{Spec: v1alpha1.WireguardPeerSpec{PublicKey: validPeerPublicKey, Address: "10.0.0.1", Disabled: true}},
			{Spec: v1alpha1.WireguardPeerSpec{PublicKey: "", Address: "10.0.0.2"}},
			{Spec: v1alpha1.WireguardPeerSpec{PublicKey: validPeerPublicKey2, Address: ""}},
		},
	}

	cfg, err := BuildWgQuickConfig(state, 51820)
	if err != nil {
		t.Fatalf("BuildWgQuickConfig: %v", err)
	}

	if strings.Contains(cfg, validPeerPublicKey) {
		t.Errorf("disabled peer must not appear:\n%s", cfg)
	}
	if strings.Contains(cfg, validPeerPublicKey2) {
		t.Errorf("address-less peer must not appear:\n%s", cfg)
	}
	if strings.Contains(cfg, "10.0.0.2") {
		t.Errorf("empty-PublicKey peer must not appear:\n%s", cfg)
	}
}

// TestBuildWgQuickConfig_TrimsAllowedIPsWhitespace covers the common case where
// ops paste a CSV with spaces — `172.31.255.11/32, 10.254.0.0/16`. wg syncconf
// is strict about CSV format; we must normalize.
func TestBuildWgQuickConfig_TrimsAllowedIPsWhitespace(t *testing.T) {
	state := agent.State{
		ServerPrivateKey: validServerPrivateKey,
		Server:           v1alpha1.Wireguard{},
		Peers: []v1alpha1.WireguardPeer{
			{
				Spec: v1alpha1.WireguardPeerSpec{
					PublicKey:  validPeerPublicKey,
					Address:    "172.31.255.11",
					AllowedIPs: "172.31.255.11/32, 10.254.0.0/16 , 192.168.1.0/24",
				},
			},
		},
	}

	cfg, err := BuildWgQuickConfig(state, 51820)
	if err != nil {
		t.Fatalf("BuildWgQuickConfig: %v", err)
	}

	for _, want := range []string{"172.31.255.11/32", "10.254.0.0/16", "192.168.1.0/24"} {
		if !strings.Contains(cfg, want) {
			t.Errorf("trimmed CIDR %q missing from config:\n%s", want, cfg)
		}
	}
}
