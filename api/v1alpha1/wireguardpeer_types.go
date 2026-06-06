/*
Copyright 2021.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type PrivateKey struct {
	SecretKeyRef corev1.SecretKeySelector `json:"secretKeyRef"`
}

type Status struct {
}

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// WireguardPeerSpec defines the desired state of WireguardPeer
type WireguardPeerSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file
	// The address of the peer.
	Address string `json:"address,omitempty"`
	// The IPv6 address of the peer.
	AddressV6 string `json:"addressV6,omitempty"`
	// The AllowedIPs of the peer.
	AllowedIPs string `json:"allowedIPs,omitempty"`
	// Set to true to temporarily disable the peer.
	Disabled bool `json:"disabled,omitempty"`
	// The DNS configuration for the peer.
	Dns string `json:"dns,omitempty"`
	// The DNS search domain(s) for the peer.
	DnsSearchDomain string `json:"dnsSearchDomain,omitempty"`
	// The private key of the peer
	PrivateKey PrivateKey `json:"privateKeyRef,omitempty"`
	// The key used by the peer to authenticate with the wg server.
	PublicKey string `json:"publicKey,omitempty"`
	// Resolved preshared-key value, carried into the agent state (state.json)
	// so the server-side [Peer] block can emit PresharedKey. Populated by the
	// controller in-memory from the per-peer `<name>-peer` Secret's
	// `presharedKey` key; NOT meant to be set directly on the CR (it is never
	// patched back, so it does not persist).
	PresharedKey string `json:"presharedKey,omitempty"`
	// The name of the Wireguard instance in k8s that the peer belongs to. The wg instance should be in the same namespace as the peer.
	//+kubebuilder:validation:Required
	//+kubebuilder:validation:MinLength=1
	WireguardRef string `json:"wireguardRef"`
	// Egress network policies for the peer.
	EgressNetworkPolicies EgressNetworkPolicies `json:"egressNetworkPolicies,omitempty"`
	DownloadSpeed         Speed                 `json:"downloadSpeed,omitempty"`
	UploadSpeed           Speed                 `json:"uploadSpeed,omitempty"`
	// PersistentKeepalive is the interval (in seconds) at which the peer
	// sends a keep-alive message to maintain a NAT mapping and the wg
	// handshake. Recommended 25s for peers behind NAT or stateful
	// firewalls. Written into the peer-side wg-quick blob AND the
	// server-side [Peer] block so the server maintains conntrack state
	// for replies traversing OVN's natOutgoing SNAT.
	// +optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	PersistentKeepalive *int32 `json:"persistentKeepalive,omitempty"`
	// Routes are downstream IPv4 CIDRs reachable through this peer. They
	// are appended to the server-side [Peer].AllowedIPs CSV so wg0 will
	// accept and forward packets for those CIDRs to/from this peer. In
	// PetzJohannes' upstream PR these CIDRs were also installed as
	// netlink routes on the WG pod's netns pointing at the peer's WG
	// address as nexthop — that piece is deferred in our fork because
	// kube-ovn policyRoutes already steer cluster-side traffic for those
	// CIDRs to the wireguard service IP. Adapted from
	// https://github.com/nccloud/wireguard-operator/pull/1 by
	// PetzJohannes.
	// +optional
	Routes []string `json:"routes,omitempty"`
	// RoutesV6 are downstream IPv6 CIDRs reachable through this peer.
	// See Routes for full semantics.
	// +optional
	RoutesV6 []string `json:"routesV6,omitempty"`
	// RouteLiveness overrides the liveness-gating mode for THIS peer's routes:
	// disabled (always installed), passive (withdraw on inbound silence), or
	// active (passive + /32 handshake probes). Unset ⇒ inherit the instance
	// (Wireguard.spec.routeLiveness) then the cluster default. An explicit
	// `disabled` forces this peer's routes always-on even when its instance is
	// passive/active — e.g. a fallback gateway whose broad route must never flap.
	// Valid values: "disabled", "passive", "active". Unset/empty (or any
	// unrecognised value) ⇒ inherit. NOT enum-validated so KRO can always render
	// "" (inherit); the agent validates (unknown ⇒ inherit, fail-safe).
	// +optional
	RouteLiveness string `json:"routeLiveness,omitempty"`
}

type EgressNetworkPolicies []EgressNetworkPolicy

// +kubebuilder:validation:Enum=ACCEPT;REJECT;Accept;Reject
type EgressNetworkPolicyAction string

// +kubebuilder:validation:Enum=TCP;UDP;ICMP
type EgressNetworkPolicyProtocol string

const (
	EgressNetworkPolicyActionAccept EgressNetworkPolicyAction = "Accept"
	EgressNetworkPolicyActionDeny   EgressNetworkPolicyAction = "Reject"
)

const (
	EgressNetworkPolicyProtocolTCP EgressNetworkPolicyProtocol = "TCP"
	EgressNetworkPolicyProtocolUDP EgressNetworkPolicyProtocol = "UDP"
)

type EgressNetworkPolicy struct {
	// Specifies the action to take when outgoing traffic from a Wireguard peer matches the policy. This could be 'Accept' or 'Reject'.
	Action EgressNetworkPolicyAction `json:"action,omitempty"`
	// A struct that specifies the destination address and port for the traffic. This could include IP addresses or hostnames, as well as specific port numbers or port ranges.
	To EgressNetworkPolicyTo `json:"to,omitempty"`
	// Specifies the protocol to match for this policy. This could be TCP, UDP, or ICMP.
	Protocol EgressNetworkPolicyProtocol `json:"protocol,omitempty"`
}

type EgressNetworkPolicyTo struct {
	// A string field that specifies the destination IP address for traffic that matches the policy.
	Ip string `json:"ip,omitempty"`
	// An integer field that specifies the destination port number for traffic that matches the policy.
	Port int32 `json:"port,omitempty" protobuf:"varint,3,opt,name=port"`
}

// WireguardPeerStatus defines the observed state of WireguardPeer
type WireguardPeerStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file
	// A string field that represents the current status of the Wireguard peer. This could include values like ready, pending, or error.
	Status string `json:"status,omitempty"`
	// A string field that provides additional information about the status of the Wireguard peer. This could include error messages or other information that helps to diagnose issues with the peer.
	Message string `json:"message,omitempty"`
	// Conditions represent the latest available observations of the WireguardPeer's state.
	// +optional
	// +patchMergeKey=type
	// +patchStrategy=merge
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type"`
}

type Speed struct {
	Value int `json:"config,omitempty"`

	// +kubebuilder:validation:Enum=mbps;kbps
	Unit string `json:"unit,omitempty"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status
//+kubebuilder:printcolumn:name="Status",type=string,JSONPath=`.status.status`
//+kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// WireguardPeer is the Schema for the wireguardpeers API
type WireguardPeer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// The desired state of the peer.
	Spec WireguardPeerSpec `json:"spec,omitempty"`
	// A field that defines the observed state of the Wireguard peer. This includes fields like the current configuration and status of the peer.
	Status WireguardPeerStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// WireguardPeerList contains a list of WireguardPeer
type WireguardPeerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []WireguardPeer `json:"items"`
}

func init() {
	SchemeBuilder.Register(&WireguardPeer{}, &WireguardPeerList{})
}
