package iptables

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-logr/logr"
	"github.com/nccloud/wireguard-operator/api/v1alpha1"
	"github.com/nccloud/wireguard-operator/internal/agent"
)

// test helpers

func TestIptableRules(t *testing.T) {
	tests := []struct {
		name                 string
		peerIp               string
		kubeDnsIp            string
		wgServerIp           string
		networkPolicies      v1alpha1.EgressNetworkPolicies
		expectedIptableRules string
	}{
		{
			name:       "EgressNetworkPolicy with destination IP address filter",
			peerIp:     "192.168.1.115",
			kubeDnsIp:  "69.96.1.42",
			wgServerIp: "192.168.1.1",
			networkPolicies: v1alpha1.EgressNetworkPolicies{
				v1alpha1.EgressNetworkPolicy{
					Action: v1alpha1.EgressNetworkPolicyActionAccept,
					To:     v1alpha1.EgressNetworkPolicyTo{Ip: "8.8.8.8"}},
			},
			expectedIptableRules: `# start of rules for peer 192.168.1.115
:192-168-1-115 - [0:0]
-A FORWARD -s 192.168.1.115 -j 192-168-1-115
-A 192-168-1-115 -d 192.168.1.1 -p icmp -j ACCEPT
-A 192-168-1-115 -d 192.168.1.115 -j ACCEPT
-A 192-168-1-115 -d 69.96.1.42 -p UDP --dport 53 -j ACCEPT
-A 192-168-1-115 -d 69.96.1.42 -p TCP --dport 53 -j ACCEPT
-A 192-168-1-115 -d 8.8.8.8 -j ACCEPT
-A 192-168-1-115 -j REJECT --reject-with icmp-port-unreachable
# end of rules for peer 192.168.1.115`,
		},
		{
			name:       "Able to filter egress by UDP",
			peerIp:     "10.8.0.9",
			kubeDnsIp:  "100.64.0.10",
			wgServerIp: "10.8.0.1",
			networkPolicies: v1alpha1.EgressNetworkPolicies{
				v1alpha1.EgressNetworkPolicy{
					Action:   v1alpha1.EgressNetworkPolicyActionAccept,
					Protocol: "UDP",
					To:       v1alpha1.EgressNetworkPolicyTo{}},
			},
			expectedIptableRules: `# start of rules for peer 10.8.0.9
:10-8-0-9 - [0:0]
-A FORWARD -s 10.8.0.9 -j 10-8-0-9
-A 10-8-0-9 -d 10.8.0.1 -p icmp -j ACCEPT
-A 10-8-0-9 -d 10.8.0.9 -j ACCEPT
-A 10-8-0-9 -d 100.64.0.10 -p UDP --dport 53 -j ACCEPT
-A 10-8-0-9 -d 100.64.0.10 -p TCP --dport 53 -j ACCEPT
-A 10-8-0-9 -p UDP -j ACCEPT
-A 10-8-0-9 -j REJECT --reject-with icmp-port-unreachable
# end of rules for peer 10.8.0.9`,
		},
		{
			name:            "Empty networkPolicies",
			peerIp:          "10.8.0.9",
			kubeDnsIp:       "100.64.0.10",
			wgServerIp:      "10.8.0.1",
			networkPolicies: v1alpha1.EgressNetworkPolicies{},
			expectedIptableRules: `# start of rules for peer 10.8.0.9
:10-8-0-9 - [0:0]
-A FORWARD -s 10.8.0.9 -j 10-8-0-9
-A 10-8-0-9 -d 10.8.0.1 -p icmp -j ACCEPT
-A 10-8-0-9 -d 10.8.0.9 -j ACCEPT
-A 10-8-0-9 -d 100.64.0.10 -p UDP --dport 53 -j ACCEPT
-A 10-8-0-9 -d 100.64.0.10 -p TCP --dport 53 -j ACCEPT
# end of rules for peer 10.8.0.9`,
		},
		{
			// Regression: an anycast DNS pair arrives as a comma+space separated
			// list ("172.31.255.253, 172.31.255.254"). Interpolated raw it yields
			// `-d 172.31.255.253, 172.31.255.254`, which iptables-restore tokenises
			// on whitespace and rejects with "Bad argument `172.31.255.254'" —
			// aborting the whole restore and leaving forwarding rules broken.
			// Each address must get its own rule.
			name:            "Multiple DNS servers emit one rule per address",
			peerIp:          "10.8.0.9",
			kubeDnsIp:       "172.31.255.253, 172.31.255.254",
			wgServerIp:      "10.8.0.1",
			networkPolicies: v1alpha1.EgressNetworkPolicies{},
			expectedIptableRules: `# start of rules for peer 10.8.0.9
:10-8-0-9 - [0:0]
-A FORWARD -s 10.8.0.9 -j 10-8-0-9
-A 10-8-0-9 -d 10.8.0.1 -p icmp -j ACCEPT
-A 10-8-0-9 -d 10.8.0.9 -j ACCEPT
-A 10-8-0-9 -d 172.31.255.253 -p UDP --dport 53 -j ACCEPT
-A 10-8-0-9 -d 172.31.255.253 -p TCP --dport 53 -j ACCEPT
-A 10-8-0-9 -d 172.31.255.254 -p UDP --dport 53 -j ACCEPT
-A 10-8-0-9 -d 172.31.255.254 -p TCP --dport 53 -j ACCEPT
# end of rules for peer 10.8.0.9`,
		},
		{
			name:            "networkPolicies with 1 empty networkPolicy",
			peerIp:          "10.8.0.11",
			kubeDnsIp:       "100.64.0.21",
			wgServerIp:      "10.7.0.1",
			networkPolicies: v1alpha1.EgressNetworkPolicies{v1alpha1.EgressNetworkPolicy{}},
			expectedIptableRules: `# start of rules for peer 10.8.0.11
:10-8-0-11 - [0:0]
-A FORWARD -s 10.8.0.11 -j 10-8-0-11
-A 10-8-0-11 -d 10.7.0.1 -p icmp -j ACCEPT
-A 10-8-0-11 -d 10.8.0.11 -j ACCEPT
-A 10-8-0-11 -d 100.64.0.21 -p UDP --dport 53 -j ACCEPT
-A 10-8-0-11 -d 100.64.0.21 -p TCP --dport 53 -j ACCEPT
-A 10-8-0-11 -j REJECT --reject-with icmp-port-unreachable
# end of rules for peer 10.8.0.11`,
		},
		{
			name:       "EgressNetworkPolicy with destination port Allowed",
			peerIp:     "10.8.0.9",
			kubeDnsIp:  "100.64.0.10",
			wgServerIp: "10.8.0.1",
			networkPolicies: v1alpha1.EgressNetworkPolicies{v1alpha1.EgressNetworkPolicy{
				Protocol: v1alpha1.EgressNetworkPolicyProtocolTCP,
				Action:   v1alpha1.EgressNetworkPolicyActionAccept,
				To:       v1alpha1.EgressNetworkPolicyTo{Port: 8080},
			}},
			expectedIptableRules: `# start of rules for peer 10.8.0.9
:10-8-0-9 - [0:0]
-A FORWARD -s 10.8.0.9 -j 10-8-0-9
-A 10-8-0-9 -d 10.8.0.1 -p icmp -j ACCEPT
-A 10-8-0-9 -d 10.8.0.9 -j ACCEPT
-A 10-8-0-9 -d 100.64.0.10 -p UDP --dport 53 -j ACCEPT
-A 10-8-0-9 -d 100.64.0.10 -p TCP --dport 53 -j ACCEPT
-A 10-8-0-9 -p TCP --dport 8080 -j ACCEPT
-A 10-8-0-9 -j REJECT --reject-with icmp-port-unreachable
# end of rules for peer 10.8.0.9`,
		},
	}

	for _, test := range tests {

		t.Run(test.name, func(t *testing.T) {

			rules := GenerateIptableRulesFromNetworkPolicies(test.networkPolicies, test.peerIp, test.kubeDnsIp, test.wgServerIp)
			if rules != test.expectedIptableRules {
				t.Errorf("got %s, want %s", rules, test.expectedIptableRules)
			}
		})
	}
}

func TestGenerateIptableRulesFromPeersUsesProvidedCIDR(t *testing.T) {
	peers := []v1alpha1.WireguardPeer{}
	const cidr = "192.168.100.0/24"
	rules := GenerateIptableRulesFromPeers(cidr, "1.2.3.4", "8.8.8.8", peers)
	if !containsSubstring(rules, "-A POSTROUTING -s "+cidr+" -o eth0 -j MASQUERADE") {
		t.Fatalf("expected NAT rule to use cidr %s, got: %s", cidr, rules)
	}
}

func containsSubstring(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 || (len(s) > len(sub) && (containsSubstring(s[1:], sub) || s[:len(sub)] == sub)))
}

// fakeRestoreOnPath installs stub iptables-restore/ip6tables-restore binaries on PATH
// that append one line per invocation to a counter file, and returns its path.
// This exercises the real exec path rather than mocking it out.
func fakeRestoreOnPath(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	counter := filepath.Join(dir, "invocations")
	script := "#!/bin/sh\ncat >/dev/null\necho x >> " + counter + "\n"
	for _, name := range []string{"iptables-restore", "ip6tables-restore"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0o755); err != nil {
			t.Fatalf("writing stub %s: %v", name, err)
		}
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return counter
}

func restoreInvocations(t *testing.T, counter string) int {
	t.Helper()
	b, err := os.ReadFile(counter)
	if os.IsNotExist(err) {
		return 0
	}
	if err != nil {
		t.Fatalf("reading counter: %v", err)
	}
	return strings.Count(string(b), "x")
}

func testState() agent.State {
	return agent.State{
		Server: v1alpha1.Wireguard{
			Spec:   v1alpha1.WireguardSpec{PeerCIDR: "10.8.0.0/24"},
			Status: v1alpha1.WireguardStatus{Address: "192.168.1.1", Dns: "10.96.0.10"},
		},
		Peers: []v1alpha1.WireguardPeer{
			{Spec: v1alpha1.WireguardPeerSpec{Address: "10.8.0.2"}},
		},
	}
}

// A gratuitous iptables-restore tears down and rebuilds the ruleset, which blackholes
// forwarding through wg0 for ~1-3s. Every state push triggers one even when the rendered
// ruleset is byte-identical, so the whole fleet false-downs. It must be skipped.
func TestSyncSkipsRestoreWhenRulesUnchanged(t *testing.T) {
	counter := fakeRestoreOnPath(t)
	it := &Iptables{Logger: logr.Discard()}
	state := testState()

	if err := it.Sync(state); err != nil {
		t.Fatalf("first sync: %v", err)
	}
	if got := restoreInvocations(t, counter); got != 1 {
		t.Fatalf("first sync should apply once, got %d invocations", got)
	}

	if err := it.Sync(state); err != nil {
		t.Fatalf("second sync: %v", err)
	}
	if got := restoreInvocations(t, counter); got != 1 {
		t.Fatalf("second sync with identical rules must skip iptables-restore, got %d invocations", got)
	}
}

// The manager builds the peer list from a cached client List, which returns informer-map
// iteration order and so reshuffles between reconciles even when nothing about the peers
// changed. Rendering walks the slice in order, so without a canonical order the rendered
// ruleset is byte-different but semantically identical, the unchanged-ruleset cache never
// hits, and every state push still runs a full restore -- blackholing wg0 for ~1-3s and
// false-downing whole LibreNMS fleets. Measured in production: 54 syncs, 0 skips.
func TestSyncSkipsRestoreWhenPeerOrderChanges(t *testing.T) {
	counter := fakeRestoreOnPath(t)
	it := &Iptables{Logger: logr.Discard()}

	state := testState()
	state.Peers = peersAt("10.8.0.2", "10.8.0.3", "10.8.0.4")
	if err := it.Sync(state); err != nil {
		t.Fatalf("first sync: %v", err)
	}
	if got := restoreInvocations(t, counter); got != 1 {
		t.Fatalf("first sync should apply once, got %d invocations", got)
	}

	reordered := testState()
	reordered.Peers = peersAt("10.8.0.4", "10.8.0.2", "10.8.0.3")
	if err := it.Sync(reordered); err != nil {
		t.Fatalf("sync with reordered peers: %v", err)
	}
	if got := restoreInvocations(t, counter); got != 1 {
		t.Fatalf("reordering the same peer set must not re-apply, want 1 invocation, got %d", got)
	}
}

// IPv6-only tenants leave Spec.Address empty on every peer, so ordering on Address alone is
// not a total order and the render goes right back to being unstable -- for exactly the
// deployments the cache is supposed to protect.
func TestSyncSkipsRestoreWhenIPv6OnlyPeerOrderChanges(t *testing.T) {
	counter := fakeRestoreOnPath(t)
	it := &Iptables{Logger: logr.Discard()}

	v6State := func(addrs ...string) agent.State {
		s := testState()
		s.Server.Spec = v1alpha1.WireguardSpec{PeerCIDRv6: "fd00::/64", IPv6Only: true}
		s.Server.Status = v1alpha1.WireguardStatus{Address: "192.168.1.1", Dns: "fd00::10"}
		s.Peers = nil
		for _, a := range addrs {
			s.Peers = append(s.Peers, v1alpha1.WireguardPeer{
				Spec: v1alpha1.WireguardPeerSpec{AddressV6: a},
			})
		}
		return s
	}

	if err := it.Sync(v6State("fd00::2", "fd00::3", "fd00::4")); err != nil {
		t.Fatalf("first sync: %v", err)
	}
	if got := restoreInvocations(t, counter); got != 1 {
		t.Fatalf("first sync should apply once, got %d invocations", got)
	}

	if err := it.Sync(v6State("fd00::4", "fd00::2", "fd00::3")); err != nil {
		t.Fatalf("sync with reordered peers: %v", err)
	}
	if got := restoreInvocations(t, counter); got != 1 {
		t.Fatalf("reordering the same IPv6-only peer set must not re-apply, want 1 invocation, got %d", got)
	}
}

// Sync renders from the state, so it must not reorder the caller's slice: cmd/agent keeps
// the pushed state in latestState and the liveness controller re-applies wg.Sync on it
// later, and agent.UpdatePeerNameMapping reads the same slice. Canonicalising the order for
// rendering must stay local to rendering.
func TestSyncDoesNotReorderCallerPeers(t *testing.T) {
	fakeRestoreOnPath(t)
	it := &Iptables{Logger: logr.Discard()}

	state := testState()
	state.Peers = peersAt("10.8.0.4", "10.8.0.2", "10.8.0.3")
	if err := it.Sync(state); err != nil {
		t.Fatalf("sync: %v", err)
	}

	for i, want := range []string{"10.8.0.4", "10.8.0.2", "10.8.0.3"} {
		if got := state.Peers[i].Spec.Address; got != want {
			t.Fatalf("Sync reordered the caller's peers: index %d is %s, want %s", i, got, want)
		}
	}
}

func peersAt(addrs ...string) []v1alpha1.WireguardPeer {
	peers := make([]v1alpha1.WireguardPeer, 0, len(addrs))
	for _, a := range addrs {
		peers = append(peers, v1alpha1.WireguardPeer{Spec: v1alpha1.WireguardPeerSpec{Address: a}})
	}
	return peers
}

func TestSyncReappliesWhenRulesChange(t *testing.T) {
	counter := fakeRestoreOnPath(t)
	it := &Iptables{Logger: logr.Discard()}
	state := testState()

	if err := it.Sync(state); err != nil {
		t.Fatalf("first sync: %v", err)
	}

	changed := testState()
	changed.Peers = append(changed.Peers, v1alpha1.WireguardPeer{
		Spec: v1alpha1.WireguardPeerSpec{Address: "10.8.0.3"},
	})
	if err := it.Sync(changed); err != nil {
		t.Fatalf("sync after change: %v", err)
	}

	if got := restoreInvocations(t, counter); got != 2 {
		t.Fatalf("changed rules must be re-applied, want 2 invocations, got %d", got)
	}
}

// If the restore fails the cache must not be poisoned, otherwise a transient failure
// would leave the dataplane permanently un-synced.
func TestSyncRetriesAfterFailedApply(t *testing.T) {
	dir := t.TempDir()
	counter := filepath.Join(dir, "invocations")
	// stub that records the call then fails
	script := "#!/bin/sh\ncat >/dev/null\necho x >> " + counter + "\nexit 1\n"
	for _, name := range []string{"iptables-restore", "ip6tables-restore"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0o755); err != nil {
			t.Fatalf("writing stub %s: %v", name, err)
		}
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	it := &Iptables{Logger: logr.Discard()}
	state := testState()

	if err := it.Sync(state); err == nil {
		t.Fatalf("expected first sync to fail")
	}
	if err := it.Sync(state); err == nil {
		t.Fatalf("expected second sync to fail")
	}
	if got := restoreInvocations(t, counter); got != 2 {
		t.Fatalf("failed apply must not be cached, want 2 invocations, got %d", got)
	}
}
