package controllers

import (
	"sort"

	"github.com/nccloud/wireguard-operator/api/v1alpha1"
	"github.com/nccloud/wireguard-operator/internal/agent"
)

// stateForAgent builds the state marshalled into the Wireguard Secret and watched by each
// tenant's agent.
//
// The reconciler rewrites that Secret whenever the marshalled bytes differ from what is
// stored, and every rewrite pokes the WG pod of EVERY tenant. So the marshalled form has to
// be a function of the peers' content only -- if it also depends on the order they happen to
// arrive in, the Secret is rewritten on reconciles where nothing actually changed.
//
// The peers arrive from a controller-runtime CACHED List, which iterates the informer's map
// and therefore hands back a different order on every call. Canonicalising by name is enough:
// names are unique within a namespace and always set, so it is a total order.
//
// Sort a copy — the caller built the slice and may still be using it.
func stateForAgent(wireguard *v1alpha1.Wireguard, privateKey string, peers []v1alpha1.WireguardPeer) agent.State {
	ordered := make([]v1alpha1.WireguardPeer, len(peers))
	copy(ordered, peers)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Name < ordered[j].Name })

	return agent.State{
		Server:           *wireguard.DeepCopy(),
		ServerPrivateKey: privateKey,
		Peers:            ordered,
	}
}
