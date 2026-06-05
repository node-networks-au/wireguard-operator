package controllers

import (
	"testing"

	"github.com/nccloud/wireguard-operator/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
)

func peerWith(anno, privRef string) *v1alpha1.WireguardPeer {
	p := &v1alpha1.WireguardPeer{}
	if anno != "" {
		p.Annotations = map[string]string{keyOriginAnnotation: anno}
	}
	if privRef != "" {
		p.Spec.PrivateKey = v1alpha1.PrivateKey{SecretKeyRef: corev1.SecretKeySelector{
			LocalObjectReference: corev1.LocalObjectReference{Name: privRef}, Key: "privateKey"}}
	}
	return p
}

func TestKeyOrigin(t *testing.T) {
	cases := []struct {
		name, anno, privRef, want string
	}{
		{"generated annotation wins", "generated", "x-peer", "generated"},
		{"external annotation wins", "external", "x-peer", "external"},
		{"legacy operator-managed: no annotation, privateKeyRef set", "", "x-peer", "unknown"},
		{"declared: no annotation, no privateKeyRef", "", "", "declared"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := keyOrigin(peerWith(tc.anno, tc.privRef)); got != tc.want {
				t.Fatalf("keyOrigin = %q, want %q", got, tc.want)
			}
		})
	}
}
