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

// TestBuildWgQuickConfig_OmitsPersistentKeepaliveServerSide locks down the
// inversion of original Phase F: even when WireguardPeer.spec.persistentKeepalive
// IS set on the CR, the server-side wg0 [Peer] block must NOT emit a
// `PersistentKeepalive = <N>` line. The server is strictly responder-only —
// it sits behind a stable LoadBalancer IP (not behind NAT) and has no mapping
// to keep alive. PersistentKeepalive belongs on the PEER side only (in the
// wg-quick blob handed to customer devices), where it keeps the peer's outbound
// NAT/conntrack mapping fresh. Setting it on the server would make the server
// emit unsolicited keepalive packets once a peer has dialed in, which is
// "active" behavior we explicitly don't want.
func TestBuildWgQuickConfig_OmitsPersistentKeepaliveServerSide(t *testing.T) {
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

	if strings.Contains(cfg, "PersistentKeepalive") {
		t.Errorf("server-side wg0 [Peer] block must NOT include PersistentKeepalive even when the CR field is set (server is responder-only; only the peer-side wg-quick blob should set keepalive):\n%s", cfg)
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
