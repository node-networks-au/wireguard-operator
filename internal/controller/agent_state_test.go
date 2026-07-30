package controllers

import (
	"bytes"
	"encoding/json"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/nccloud/wireguard-operator/api/v1alpha1"
)

// The reconciler rewrites the state Secret whenever the marshalled bytes differ from what is
// stored, and every rewrite pokes the WG pod of EVERY tenant. The peer list comes from a
// controller-runtime CACHED List, which returns informer-map iteration order and so reshuffles
// between reconciles even when no peer changed. Unless the marshalled state is
// order-independent, those reshuffles alone rewrite the Secret and push to the whole fleet for
// nothing.
//
// Measured on managed-superopti: 340 "Updating secret with new config" in 37h (~9/h), and 8
// consecutive pushes carried ONE peer set in EIGHT distinct orders -- normalising the order
// collapsed all 8 to a single hash, with no other field differing.
func TestStateForAgentIsByteIdenticalRegardlessOfPeerOrder(t *testing.T) {
	wg := &v1alpha1.Wireguard{
		ObjectMeta: metav1.ObjectMeta{Name: "wireguard", Namespace: "managed-x"},
	}

	first := statePeers("site-resv", "172.31.255.3", "site-bar", "172.31.255.12", "oob-nxtb2", "172.31.255.110")
	shuffled := statePeers("oob-nxtb2", "172.31.255.110", "site-resv", "172.31.255.3", "site-bar", "172.31.255.12")

	a, err := json.Marshal(stateForAgent(wg, "priv", first))
	if err != nil {
		t.Fatalf("marshal first order: %v", err)
	}
	b, err := json.Marshal(stateForAgent(wg, "priv", shuffled))
	if err != nil {
		t.Fatalf("marshal shuffled order: %v", err)
	}

	if !bytes.Equal(a, b) {
		t.Fatalf("marshalled state depends on peer list order: a reshuffled List would rewrite the Secret and push to every tenant with nothing changed")
	}
}

// stateForAgent must not reorder the slice it is handed -- the caller built it and may keep it.
func TestStateForAgentDoesNotReorderCallerPeers(t *testing.T) {
	wg := &v1alpha1.Wireguard{
		ObjectMeta: metav1.ObjectMeta{Name: "wireguard", Namespace: "managed-x"},
	}
	peers := statePeers("site-zulu", "172.31.255.99", "site-alpha", "172.31.255.2")

	_ = stateForAgent(wg, "priv", peers)

	for i, want := range []string{"site-zulu", "site-alpha"} {
		if got := peers[i].Name; got != want {
			t.Fatalf("caller's peers were reordered: index %d is %s, want %s", i, got, want)
		}
	}
}

func statePeers(nameAddrPairs ...string) []v1alpha1.WireguardPeer {
	var peers []v1alpha1.WireguardPeer
	for i := 0; i+1 < len(nameAddrPairs); i += 2 {
		name := nameAddrPairs[i]
		peers = append(peers, v1alpha1.WireguardPeer{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "managed-x"},
			Spec: v1alpha1.WireguardPeerSpec{
				Address:   nameAddrPairs[i+1],
				PublicKey: "pk-" + name,
			},
		})
	}
	return peers
}
