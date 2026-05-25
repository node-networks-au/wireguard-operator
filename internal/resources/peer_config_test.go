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
	"strings"
	"testing"

	"github.com/nccloud/wireguard-operator/api/v1alpha1"
)

// TestBlobEndpointFollowsExternalPort validates that the peer-config blob's
// `Endpoint = <ExternalAddress>:<port>` line uses Spec.ExternalPort when set
// and falls back to Status.Port (the agent listen port) when unset.
func TestBlobEndpointFollowsExternalPort(t *testing.T) {
	externalPort := int32(51821)
	tests := []struct {
		name           string
		externalPort   *int32
		statusPortVal  string
		expectEndpoint string
	}{
		{
			name:           "default to status.port when ExternalPort unset",
			externalPort:   nil,
			statusPortVal:  "51820",
			expectEndpoint: "example.tunnel.test:51820",
		},
		{
			name:           "ExternalPort wins over Status.Port",
			externalPort:   &externalPort,
			statusPortVal:  "51820",
			expectEndpoint: "example.tunnel.test:51821",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			wg := &v1alpha1.Wireguard{
				Spec: v1alpha1.WireguardSpec{
					ExternalAddress: "example.tunnel.test",
					ExternalPort:    tc.externalPort,
				},
				Status: v1alpha1.WireguardStatus{Port: tc.statusPortVal},
			}
			line := BuildPeerEndpointLine(wg)
			want := "Endpoint = " + tc.expectEndpoint
			if !strings.Contains(line, want) {
				t.Fatalf("expected endpoint line to contain %q; got %q", want, line)
			}
		})
	}
}
