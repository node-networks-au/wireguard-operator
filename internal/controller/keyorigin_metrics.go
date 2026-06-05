package controllers

import (
	"context"

	"github.com/nccloud/wireguard-operator/api/v1alpha1"
	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/client"
	crmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
)

const (
	// keyOriginDeclared: a user-supplied publicKey with no operator-managed
	// private key (e.g. a roaming client). Not a migration backlog item.
	keyOriginDeclared = "declared"
	// keyOriginUnknown: no provenance annotation but an operator-managed
	// privateKeyRef — a legacy peer that predates provenance tracking and
	// needs annotating (generated vs external). This is the actionable backlog.
	keyOriginUnknown = "unknown"
)

// keyOrigin derives the provenance bucket for a peer for the
// wireguard_peer_key_origin metric. The annotation is authoritative; absent it,
// the privateKeyRef discriminates a legacy operator-managed key (unknown) from
// a user-declared one (declared).
func keyOrigin(peer *v1alpha1.WireguardPeer) string {
	switch peer.Annotations[keyOriginAnnotation] {
	case keyOriginGenerated:
		return keyOriginGenerated
	case keyOriginExternal:
		return keyOriginExternal
	}
	if peer.Spec.PrivateKey.SecretKeyRef.Name != "" {
		return keyOriginUnknown
	}
	return keyOriginDeclared
}

var keyOriginDesc = prometheus.NewDesc(
	"wireguard_peer_key_origin",
	"Provenance of a WireguardPeer's spec.publicKey, as a constant 1 per peer labelled by origin "+
		"(generated|external|declared|unknown). origin=unknown marks legacy operator-managed keys that need annotating.",
	[]string{"namespace", "peer", "origin"}, nil,
)

// keyOriginCollector lists WireguardPeers on each scrape and emits their
// provenance, so series never go stale (a deleted peer simply stops appearing).
type keyOriginCollector struct {
	client client.Client
}

func (c *keyOriginCollector) Describe(ch chan<- *prometheus.Desc) { ch <- keyOriginDesc }

func (c *keyOriginCollector) Collect(ch chan<- prometheus.Metric) {
	peers := &v1alpha1.WireguardPeerList{}
	if err := c.client.List(context.Background(), peers); err != nil {
		return
	}
	for i := range peers.Items {
		p := &peers.Items[i]
		ch <- prometheus.MustNewConstMetric(keyOriginDesc, prometheus.GaugeValue, 1,
			p.Namespace, p.Name, keyOrigin(p))
	}
}

// RegisterKeyOriginCollector registers the key-origin collector with the
// controller-runtime metrics registry. Re-registration is treated as a no-op.
func RegisterKeyOriginCollector(c client.Client) error {
	err := crmetrics.Registry.Register(&keyOriginCollector{client: c})
	if err != nil {
		if _, ok := err.(prometheus.AlreadyRegisteredError); ok {
			return nil
		}
		return err
	}
	return nil
}
