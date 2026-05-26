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

// TestBuildWgQuickConfig_IncludesPersistentKeepalive locks down Phase F: when
// WireguardPeer.spec.persistentKeepalive is set, the rendered server-side wg
// config must emit a `PersistentKeepalive = <N>` line inside the [Peer] block.
// Without it the server doesn't send keep-alives, conntrack entries for the
// OVN egress NAT expire after the kernel's UDP timeout, and replies destined
// for the peer get dropped by the conntrack-based SNAT. Setting the field on
// the server side ensures the server itself emits keepalives — necessary even
// though the peer also has it set, because conntrack expiration is a function
// of the LAST packet seen in either direction.
func TestBuildWgQuickConfig_IncludesPersistentKeepalive(t *testing.T) {
	keepalive := int32(25)
	state := agent.State{
		ServerPrivateKey: validServerPrivateKey,
		Server:           v1alpha1.Wireguard{},
		Peers: []v1alpha1.WireguardPeer{
			{
				Spec: v1alpha1.WireguardPeerSpec{
					PublicKey:           validPeerPublicKey,
					Address:             "172.31.255.11",
					PersistentKeepalive: &keepalive,
				},
			},
		},
	}

	cfg, err := BuildWgQuickConfig(state, 51820)
	if err != nil {
		t.Fatalf("BuildWgQuickConfig: %v", err)
	}

	if !strings.Contains(cfg, "PersistentKeepalive = 25") {
		t.Errorf("config missing PersistentKeepalive line:\n%s", cfg)
	}
}

// TestBuildWgQuickConfig_OmitsPersistentKeepaliveWhenUnset locks down backwards
// compatibility: peers without the new field (the entire installed fleet at
// rollout time) must produce a [Peer] block with no PersistentKeepalive line.
// `wg syncconf` treats an absent PersistentKeepalive as "0" (disabled), and
// emitting a stray line would either error on parse or — worse — silently
// re-enable keepalives ops never asked for.
func TestBuildWgQuickConfig_OmitsPersistentKeepaliveWhenUnset(t *testing.T) {
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

	if strings.Contains(cfg, "PersistentKeepalive") {
		t.Errorf("PersistentKeepalive must NOT appear when the field is unset:\n%s", cfg)
	}
}

// TestBuildWgQuickConfig_RoutesAppendedToAllowedIPs locks down Phase G: when
// WireguardPeer.spec.routes is set, the rendered server-side [Peer] AllowedIPs
// CSV must include the peer's own /32 PLUS every CIDR in Routes. This is what
// lets wg0 accept and route packets for downstream LANs reachable through the
// peer — without it the kernel drops anything that doesn't match an explicit
// AllowedIP. Adapted from PetzJohannes' PR #1.
func TestBuildWgQuickConfig_RoutesAppendedToAllowedIPs(t *testing.T) {
	state := agent.State{
		ServerPrivateKey: validServerPrivateKey,
		Server:           v1alpha1.Wireguard{},
		Peers: []v1alpha1.WireguardPeer{
			{
				Spec: v1alpha1.WireguardPeerSpec{
					PublicKey:  validPeerPublicKey,
					Address:    "172.31.255.11",
					AllowedIPs: "172.31.255.11/32",
					Routes:     []string{"10.254.11.0/24", "192.168.42.0/24"},
				},
			},
		},
	}

	cfg, err := BuildWgQuickConfig(state, 51820)
	if err != nil {
		t.Fatalf("BuildWgQuickConfig: %v", err)
	}

	for _, want := range []string{"172.31.255.11/32", "10.254.11.0/24", "192.168.42.0/24"} {
		if !strings.Contains(cfg, want) {
			t.Errorf("expected CIDR %q in AllowedIPs:\n%s", want, cfg)
		}
	}
}

// TestBuildWgQuickConfig_RoutesV6AppendedToAllowedIPs is the IPv6 counterpart.
func TestBuildWgQuickConfig_RoutesV6AppendedToAllowedIPs(t *testing.T) {
	state := agent.State{
		ServerPrivateKey: validServerPrivateKey,
		Server:           v1alpha1.Wireguard{},
		Peers: []v1alpha1.WireguardPeer{
			{
				Spec: v1alpha1.WireguardPeerSpec{
					PublicKey:  validPeerPublicKey,
					AddressV6:  "fd00:255::11",
					AllowedIPs: "fd00:255::11/128",
					RoutesV6:   []string{"fd00:254:11::/64"},
				},
			},
		},
	}

	cfg, err := BuildWgQuickConfig(state, 51820)
	if err != nil {
		t.Fatalf("BuildWgQuickConfig: %v", err)
	}

	for _, want := range []string{"fd00:255::11/128", "fd00:254:11::/64"} {
		if !strings.Contains(cfg, want) {
			t.Errorf("expected CIDR %q in AllowedIPs:\n%s", want, cfg)
		}
	}
}

// TestBuildWgQuickConfig_RoutesAppendedToDefaultAllowedIPs covers the path where
// the operator hasn't set spec.allowedIPs at all — the default `<addr>/32`
// derivation must still get Routes appended (otherwise Routes is silently lost
// for peers that rely on the implicit /32).
func TestBuildWgQuickConfig_RoutesAppendedToDefaultAllowedIPs(t *testing.T) {
	state := agent.State{
		ServerPrivateKey: validServerPrivateKey,
		Server:           v1alpha1.Wireguard{},
		Peers: []v1alpha1.WireguardPeer{
			{
				Spec: v1alpha1.WireguardPeerSpec{
					PublicKey: validPeerPublicKey,
					Address:   "172.31.255.11",
					// no spec.AllowedIPs — falls through to default /32
					Routes: []string{"10.254.11.0/24"},
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
	if !strings.Contains(cfg, "10.254.11.0/24") {
		t.Errorf("config missing Route CIDR:\n%s", cfg)
	}
}

// TestBuildWgQuickConfig_EmptyRoutesUnchanged guards backwards compat: a peer
// with no Routes set must produce a [Peer] line identical to what Phase E/F
// produced, with no trailing comma and no extra CIDRs.
func TestBuildWgQuickConfig_EmptyRoutesUnchanged(t *testing.T) {
	state := agent.State{
		ServerPrivateKey: validServerPrivateKey,
		Server:           v1alpha1.Wireguard{},
		Peers: []v1alpha1.WireguardPeer{
			{
				Spec: v1alpha1.WireguardPeerSpec{
					PublicKey:  validPeerPublicKey,
					Address:    "172.31.255.11",
					AllowedIPs: "172.31.255.11/32",
					// Routes/RoutesV6 unset
				},
			},
		},
	}

	cfg, err := BuildWgQuickConfig(state, 51820)
	if err != nil {
		t.Fatalf("BuildWgQuickConfig: %v", err)
	}

	if !strings.Contains(cfg, "AllowedIPs = 172.31.255.11/32\n") {
		t.Errorf("expected exact `AllowedIPs = 172.31.255.11/32` with no trailing CIDRs:\n%s", cfg)
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

// TestDesiredKernelRoutes_CollectsRoutesAndRoutesV6 locks down Phase G follow-up:
// the netlink route-install loop reads from a pure function that returns the
// union of every enabled peer's Routes + RoutesV6 (deduped). Disabled peers,
// empty-PublicKey peers, and blank/whitespace entries must be filtered. The
// resulting list is what the agent will pass to `netlink.RouteReplace` for
// dev wg0.
func TestDesiredKernelRoutes_CollectsRoutesAndRoutesV6(t *testing.T) {
	peers := []v1alpha1.WireguardPeer{
		{
			Spec: v1alpha1.WireguardPeerSpec{
				PublicKey: validPeerPublicKey,
				Address:   "172.31.255.11",
				Routes:    []string{"10.254.11.0/24", "192.168.42.0/24"},
				RoutesV6:  []string{"fd00:42::/48"},
			},
		},
		{
			Spec: v1alpha1.WireguardPeerSpec{
				PublicKey: validPeerPublicKey2,
				Address:   "172.31.255.12",
				// no Routes
			},
		},
	}

	got := desiredKernelRoutes(peers)
	want := []string{"10.254.11.0/24", "192.168.42.0/24", "fd00:42::/48"}
	if len(got) != len(want) {
		t.Fatalf("desiredKernelRoutes len = %d (%v), want %d (%v)", len(got), got, len(want), want)
	}
	gotSet := map[string]bool{}
	for _, c := range got {
		gotSet[c] = true
	}
	for _, w := range want {
		if !gotSet[w] {
			t.Errorf("desiredKernelRoutes missing %q (got %v)", w, got)
		}
	}
}

// TestDesiredKernelRoutes_SkipsDisabledAndEmptyKeyPeers asserts the same
// filtering invariants peerAllowedIPs honours: a Disabled peer must NOT
// contribute its Routes (otherwise the kernel keeps routing to a tunnel
// the wg config no longer carries), and a PublicKey-less peer must NOT
// contribute either (it can't actually receive packets).
func TestDesiredKernelRoutes_SkipsDisabledAndEmptyKeyPeers(t *testing.T) {
	peers := []v1alpha1.WireguardPeer{
		{Spec: v1alpha1.WireguardPeerSpec{PublicKey: validPeerPublicKey, Address: "10.0.0.1", Disabled: true, Routes: []string{"10.10.0.0/24"}}},
		{Spec: v1alpha1.WireguardPeerSpec{PublicKey: "", Address: "10.0.0.2", Routes: []string{"10.20.0.0/24"}}},
		{Spec: v1alpha1.WireguardPeerSpec{PublicKey: validPeerPublicKey2, Address: "10.0.0.3", Routes: []string{"10.30.0.0/24"}}},
	}

	got := desiredKernelRoutes(peers)
	if len(got) != 1 || got[0] != "10.30.0.0/24" {
		t.Errorf("desiredKernelRoutes filtered set = %v, want [10.30.0.0/24]", got)
	}
}

// TestDesiredKernelRoutes_TrimsWhitespaceAndSkipsEmpty guards against ops
// pasting CSVs into the per-string Routes slice with trailing whitespace.
// Empty entries (post-trim) must be dropped — netlink would reject them.
func TestDesiredKernelRoutes_TrimsWhitespaceAndSkipsEmpty(t *testing.T) {
	peers := []v1alpha1.WireguardPeer{
		{
			Spec: v1alpha1.WireguardPeerSpec{
				PublicKey: validPeerPublicKey,
				Address:   "10.0.0.1",
				Routes:    []string{" 10.10.0.0/24 ", "", "  "},
				RoutesV6:  []string{" fd00::/64 "},
			},
		},
	}

	got := desiredKernelRoutes(peers)
	wantSet := map[string]bool{"10.10.0.0/24": true, "fd00::/64": true}
	if len(got) != 2 {
		t.Fatalf("desiredKernelRoutes len = %d (%v), want 2", len(got), got)
	}
	for _, c := range got {
		if !wantSet[c] {
			t.Errorf("unexpected entry %q in %v", c, got)
		}
	}
}

// TestDesiredKernelRoutes_Dedupes guards against the case where two peers
// declare overlapping Routes (operator misconfig, or one peer carries a
// /24 the other carries a /25 of the same prefix — they'd both end up
// trying to claim the same kernel route, and we don't want a hot loop
// of RouteReplace calls).
func TestDesiredKernelRoutes_Dedupes(t *testing.T) {
	peers := []v1alpha1.WireguardPeer{
		{Spec: v1alpha1.WireguardPeerSpec{PublicKey: validPeerPublicKey, Address: "10.0.0.1", Routes: []string{"10.10.0.0/24"}}},
		{Spec: v1alpha1.WireguardPeerSpec{PublicKey: validPeerPublicKey2, Address: "10.0.0.2", Routes: []string{"10.10.0.0/24"}}},
	}

	got := desiredKernelRoutes(peers)
	if len(got) != 1 || got[0] != "10.10.0.0/24" {
		t.Errorf("desiredKernelRoutes dedup = %v, want [10.10.0.0/24]", got)
	}
}

// TestWgSyncconfTempDir_IsWritableEmptyDirMount guards against a regression of
// the Phase E follow-up bug: os.CreateTemp("", ...) defaults to $TMPDIR/`/tmp`,
// but the agent container's securityContext sets readOnlyRootFilesystem: true,
// so /tmp is read-only and every reconcile fails with "read-only file system".
// The operator's deployment template mounts an emptyDir named `socket` at
// /var/run/wireguard/, which is always writable. If anyone moves the temp
// file off that path they must also add a writable mount.
func TestWgSyncconfTempDir_IsWritableEmptyDirMount(t *testing.T) {
	if wgSyncconfTempDir != "/var/run/wireguard" {
		t.Errorf("wgSyncconfTempDir = %q, want %q (the operator's deployment template mounts an emptyDir at this path; changing it requires a matching volume change in internal/resources/deployment.go)", wgSyncconfTempDir, "/var/run/wireguard")
	}
}
