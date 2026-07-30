package iptables

import (
	"fmt"
	"os/exec"
	"sort"
	"strings"

	"github.com/go-logr/logr"
	"github.com/nccloud/wireguard-operator/api/v1alpha1"
	"github.com/nccloud/wireguard-operator/internal/agent"
	"github.com/nccloud/wireguard-operator/internal/ipam"
)

func ApplyRules(rules string) error {
	cmd := exec.Command("iptables-restore")
	cmd.Stdin = strings.NewReader(rules)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("iptables-restore failed: %w: %s", err, string(out))
	}
	return nil
}

func ApplyRulesV6(rules string) error {
	cmd := exec.Command("ip6tables-restore")
	cmd.Stdin = strings.NewReader(rules)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("ip6tables-restore failed: %w: %s", err, string(out))
	}
	return nil
}

type Iptables struct {
	Logger logr.Logger

	// lastV4/lastV6 hold the most recently applied rulesets.
	//
	// iptables-restore is not free: it flushes and rebuilds the chains, which blackholes
	// forwarding through wg0 for ~1-3s. Sync runs on every operator state push, and the
	// rendered ruleset is usually byte-identical (a peer's routes or keys changing does
	// not alter the rules at all), so re-applying it is pure downtime for no benefit.
	// Re-applying only on an actual change removes that.
	//
	// The cache starts empty, so the first Sync after agent start always applies and the
	// dataplane is guaranteed correct on restart. Nothing outside this agent writes these
	// chains, so there is no periodic re-assert (one would reintroduce the very blip this
	// avoids, far more often than state pushes occur).
	//
	// Not guarded by a mutex: Sync is only ever called from the single OnStateChange
	// watcher goroutine. Guard these if that ever changes.
	lastV4 string
	lastV6 string
}

func (it *Iptables) Sync(state agent.State) error {
	it.Logger.Info("syncing network policies")
	wgHostName := state.Server.Status.Address
	dns := state.Server.Status.Dns
	// Render from a canonically ordered copy of the peers.
	//
	// The manager builds the peer list from a cached client List, which returns informer-map
	// iteration order, so it reshuffles between reconciles even when no peer changed. The
	// renderers below walk the slice in order, so without this the rendered ruleset comes out
	// byte-different but semantically identical, the lastV4/lastV6 cache never hits, and every
	// state push still runs a full restore -- the ~1-3s wg0 blackhole this cache exists to
	// avoid. Sorting is semantically inert: each peer gets its own chain, peer addresses are
	// disjoint, so the order rules are emitted in cannot change what matches.
	//
	// Copy rather than sort in place: the caller retains this slice (cmd/agent keeps it as
	// latestState and re-applies wg.Sync on it) and must not observe our reordering.
	//
	// The key must be a total order across both families: IPv6-only tenants leave Address
	// empty on every peer, so Address alone would tie and leave the order unstable there.
	peers := make([]v1alpha1.WireguardPeer, len(state.Peers))
	copy(peers, state.Peers)
	sort.Slice(peers, func(i, j int) bool {
		a, b := peers[i].Spec, peers[j].Spec
		if a.Address != b.Address {
			return a.Address < b.Address
		}
		if a.AddressV6 != b.AddressV6 {
			return a.AddressV6 < b.AddressV6
		}
		return peers[i].Name < peers[j].Name
	})
	spec := state.Server.Spec

	enableV6 := spec.PeerCIDRv6 != ""
	ipv6Only := spec.IPv6Only && enableV6

	// IPv4 rules (skip in IPv6-only mode).
	if !ipv6Only {
		cidr4 := spec.PeerCIDR
		if cidr4 == "" {
			cidr4 = ipam.DefaultPeerCIDR4
		}
		if cidr4 != "" {
			cfg := GenerateIptableRulesFromPeers(cidr4, wgHostName, dns, peers)
			if cfg == it.lastV4 {
				it.Logger.V(1).Info("iptables rules unchanged, skipping restore")
			} else {
				if err := ApplyRules(cfg); err != nil {
					return err
				}
				it.lastV4 = cfg
			}
		}
	}

	// IPv6 rules.
	if enableV6 {
		cidr6 := spec.PeerCIDRv6
		cfg6 := GenerateIp6tableRulesFromPeers(cidr6, wgHostName, dns, peers)
		if cfg6 == it.lastV6 {
			it.Logger.V(1).Info("ip6tables rules unchanged, skipping restore")
		} else {
			if err := ApplyRulesV6(cfg6); err != nil {
				return err
			}
			it.lastV6 = cfg6
		}
	}

	return nil
}

func GenerateIptableRulesFromNetworkPolicies(policies v1alpha1.EgressNetworkPolicies, peerIp string, kubeDnsIp string, wgServerIp string) string {
	peerChain := strings.ReplaceAll(peerIp, ".", "-")

	rules := []string{
		// add a comment
		fmt.Sprintf("# start of rules for peer %s", peerIp),

		// create chain for peer
		fmt.Sprintf(":%s - [0:0]", peerChain),

		// associate peer chain to FORWARD chain
		fmt.Sprintf("-A FORWARD -s %s -j %s", peerIp, peerChain),

		// allow peer to ping (ICMP) wireguard server for debugging purposes
		fmt.Sprintf("-A %s -d %s -p icmp -j ACCEPT", peerChain, wgServerIp),

		// allow peer to communicate with itself
		fmt.Sprintf("-A %s -d %s -j ACCEPT", peerChain, peerIp),
	}

	// allow peer to communicate with kube-dns (UDP and TCP for large DNS responses).
	// kubeDnsIp may carry more than one address (e.g. an anycast resolver pair) as a
	// comma-separated list. iptables-restore takes a single address per -d and
	// tokenises on whitespace, so interpolating the list raw produces
	// `-d 1.2.3.4, 5.6.7.8` and the whole restore aborts with "Bad argument" —
	// leaving the ruleset half-applied and forwarding broken. Emit one rule per address.
	for _, dns := range strings.Split(kubeDnsIp, ",") {
		dns = strings.TrimSpace(dns)
		if dns == "" {
			continue
		}
		rules = append(rules,
			fmt.Sprintf("-A %s -d %s -p UDP --dport 53 -j ACCEPT", peerChain, dns),
			fmt.Sprintf("-A %s -d %s -p TCP --dport 53 -j ACCEPT", peerChain, dns),
		)
	}

	for _, policy := range policies {
		// skip empty policies to avoid redundant unconditional REJECT rules
		if policy.Action == "" && policy.Protocol == "" && policy.To.Ip == "" && policy.To.Port == 0 {
			continue
		}
		rules = append(rules, EgressNetworkPolicyToIpTableRules(policy, peerChain)...)
	}

	// if policies are defined impose an implicit deny all
	if len(policies) != 0 {
		rules = append(rules, fmt.Sprintf("-A %s -j REJECT --reject-with icmp-port-unreachable", peerChain))
	}

	// add a comment
	rules = append(rules, fmt.Sprintf("# end of rules for peer %s", peerIp))

	return strings.Join(rules, "\n")
}

func GenerateIptableRulesFromPeers(peerCIDR string, wgHostName string, dns string, peers []v1alpha1.WireguardPeer) string {
	var rules []string

	var natTableRules = fmt.Sprintf(`
*nat
:PREROUTING ACCEPT [0:0]
:INPUT ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
-A POSTROUTING -s %s -o eth0 -j MASQUERADE
COMMIT`, peerCIDR)

	for _, peer := range peers {

		//tc(peer.Spec.DownloadSpeed, peer.Spec.UploadSpeed)
		rules = append(rules, GenerateIptableRulesFromNetworkPolicies(peer.Spec.EgressNetworkPolicies, peer.Spec.Address, dns, wgHostName))
	}

	var filterTableRules = fmt.Sprintf(`
*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
%s
COMMIT
`, strings.Join(rules, "\n"))

	return fmt.Sprintf("%s\n%s", natTableRules, filterTableRules)
}

// GenerateIp6tableRulesFromPeers mirrors GenerateIptableRulesFromPeers but for IPv6 traffic.
func GenerateIp6tableRulesFromPeers(peerCIDR string, wgHostName string, dns string, peers []v1alpha1.WireguardPeer) string {
	var rules []string

	var natTableRules = fmt.Sprintf(`
*nat
::PREROUTING ACCEPT [0:0]
::INPUT ACCEPT [0:0]
::OUTPUT ACCEPT [0:0]
::POSTROUTING ACCEPT [0:0]
-A POSTROUTING -s %s -o eth0 -j MASQUERADE
COMMIT`, peerCIDR)

	for _, peer := range peers {
		if peer.Spec.AddressV6 == "" {
			continue
		}
		// Reuse the same network policy rendering but with IPv6 peer IPs.
		rules = append(rules, GenerateIptableRulesFromNetworkPolicies(peer.Spec.EgressNetworkPolicies, peer.Spec.AddressV6, dns, wgHostName))
	}

	var filterTableRules = fmt.Sprintf(`
*filter
::INPUT ACCEPT [0:0]
::FORWARD ACCEPT [0:0]
::OUTPUT ACCEPT [0:0]
%s
COMMIT
`, strings.Join(rules, "\n"))

	return fmt.Sprintf("%s\n%s", natTableRules, filterTableRules)
}

func EgressNetworkPolicyToIpTableRules(policy v1alpha1.EgressNetworkPolicy, peerChain string) []string {

	var rules []string

	if policy.Protocol == "" && policy.To.Port != 0 {
		policy.Protocol = "TCP"
		rules = append(rules, EgressNetworkPolicyToIpTableRules(policy, peerChain)[0])
		policy.Protocol = "UDP"
		rules = append(rules, EgressNetworkPolicyToIpTableRules(policy, peerChain)[0])
		return rules
	}

	// customer rules
	var rulePeerChain = "-A " + peerChain
	var ruleAction = "-j REJECT"
	var ruleProtocol = ""
	var ruleDestIp = ""
	var ruleDestPort = ""

	if policy.To.Ip != "" {
		ruleDestIp = "-d " + policy.To.Ip
	}

	if policy.Protocol != "" {
		ruleProtocol = "-p " + strings.ToUpper(string(policy.Protocol))
	}

	if policy.To.Port != 0 {
		ruleDestPort = "--dport " + fmt.Sprint(policy.To.Port)
	}

	if policy.Action != "" {
		ruleAction = "-j " + strings.ToUpper(string(policy.Action))
	}

	var options = []string{rulePeerChain, ruleDestIp, ruleProtocol, ruleDestPort, ruleAction}
	var filteredOptions []string
	for _, option := range options {
		if len(option) != 0 {
			filteredOptions = append(filteredOptions, option)
		}
	}
	rules = append(rules, strings.Join(filteredOptions, " "))

	return rules

}
