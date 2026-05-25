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

package resources

import (
	"fmt"
	"strconv"

	"github.com/nccloud/wireguard-operator/api/v1alpha1"
)

// PeerEndpointPort returns the port written into the peer-side wg-quick blob's
// `Endpoint = <addr>:<port>` line. When Spec.ExternalPort is set, it overrides
// Status.Port (the agent's own listen port). Otherwise the agent listen port
// is preserved for backwards compatibility.
//
// Decoupling the published Endpoint port from the agent's listen port lets
// operators share a single LoadBalancer EIP across tenants with per-tenant
// UDP-port demux — the downloaded blob carries the customer-facing port even
// when the agent inside the pod listens on the upstream default (51820).
func PeerEndpointPort(wg *v1alpha1.Wireguard) string {
	if wg.Spec.ExternalPort != nil {
		return strconv.Itoa(int(*wg.Spec.ExternalPort))
	}
	return wg.Status.Port
}

// BuildPeerEndpointLine returns the full `Endpoint = <addr>:<port>` line for
// the peer-side wg-quick blob. The address falls back from Spec.ExternalAddress
// to Status.Address; the port is resolved via PeerEndpointPort. Callers in the
// controller that already have a fully-resolved server address (including
// Service LoadBalancer / node-IP fallbacks) should compose the line manually
// using PeerEndpointPort.
func BuildPeerEndpointLine(wg *v1alpha1.Wireguard) string {
	addr := wg.Spec.ExternalAddress
	if addr == "" {
		addr = wg.Status.Address
	}
	return fmt.Sprintf("Endpoint = %s:%s", addr, PeerEndpointPort(wg))
}
