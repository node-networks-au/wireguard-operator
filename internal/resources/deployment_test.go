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
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

func newTestDeploymentBuilder(t *testing.T) *DeploymentBuilder {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("failed to register v1alpha1 with scheme: %v", err)
	}
	return NewDeploymentBuilder(scheme, "agent:test", corev1.PullIfNotPresent)
}

func newTestWireguard(spec v1alpha1.WireguardSpec) *v1alpha1.Wireguard {
	return &v1alpha1.Wireguard{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",
		},
		Spec: spec,
	}
}

func agentContainer(t *testing.T, containers []corev1.Container) corev1.Container {
	t.Helper()
	for _, c := range containers {
		if c.Name == "agent" {
			return c
		}
	}
	t.Fatalf("agent container not found; got containers: %+v", containers)
	return corev1.Container{}
}

func cmdContains(cmd []string, s string) bool {
	for _, c := range cmd {
		if c == s {
			return true
		}
	}
	return false
}

func cmdHasFlagValue(cmd []string, flag, value string) bool {
	for i, c := range cmd {
		if c == flag && i+1 < len(cmd) && cmd[i+1] == value {
			return true
		}
	}
	return false
}

func TestDeploymentAgentListenPortDefault(t *testing.T) {
	b := newTestDeploymentBuilder(t)
	wg := newTestWireguard(v1alpha1.WireguardSpec{})

	dep, err := b.ForWireguard(wg)
	if err != nil {
		t.Fatalf("ForWireguard returned error: %v", err)
	}

	agent := agentContainer(t, dep.Spec.Template.Spec.Containers)
	if !cmdContains(agent.Command, "--wg-listen-port") {
		t.Fatalf("expected agent command to contain --wg-listen-port; got %v", agent.Command)
	}
	if !cmdHasFlagValue(agent.Command, "--wg-listen-port", "51820") {
		t.Fatalf("default agent listen-port must remain 51820 for backwards compatibility; got command %v", agent.Command)
	}
}

func TestDeploymentAgentListenPortCustom(t *testing.T) {
	b := newTestDeploymentBuilder(t)
	listenPort := int32(51821)
	wg := newTestWireguard(v1alpha1.WireguardSpec{
		AgentListenPort: &listenPort,
	})

	dep, err := b.ForWireguard(wg)
	if err != nil {
		t.Fatalf("ForWireguard returned error: %v", err)
	}

	agent := agentContainer(t, dep.Spec.Template.Spec.Containers)
	if !cmdContains(agent.Command, "--wg-listen-port") {
		t.Fatalf("expected agent command to contain --wg-listen-port; got %v", agent.Command)
	}
	if !cmdHasFlagValue(agent.Command, "--wg-listen-port", "51821") {
		t.Fatalf("expected agent --wg-listen-port=51821 when AgentListenPort is set; got command %v", agent.Command)
	}
	// Ensure the literal default does not also appear as the listen-port value.
	if cmdHasFlagValue(agent.Command, "--wg-listen-port", "51820") {
		t.Fatalf("when AgentListenPort is set, the default 51820 must not also appear as the --wg-listen-port value; got command %v", agent.Command)
	}
	// Sanity: no stray "51820" token anywhere in Command slice once overridden.
	for _, tok := range agent.Command {
		if strings.TrimSpace(tok) == "51820" {
			t.Fatalf("unexpected literal 51820 token in agent command when AgentListenPort=51821: %v", agent.Command)
		}
	}
}
