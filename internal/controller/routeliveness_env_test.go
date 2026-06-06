package controllers

import (
	"reflect"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func depWithAgentEnv(env []corev1.EnvVar) *appsv1.Deployment {
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: "x-dep"},
		Spec: appsv1.DeploymentSpec{
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{Name: "wstunnel"},
						{Name: "agent", Env: env},
					},
				},
			},
		},
	}
}

func TestRouteLivenessEnvOf(t *testing.T) {
	cases := []struct {
		name string
		env  []corev1.EnvVar
		want map[string]string
	}{
		{"none", nil, map[string]string{}},
		{"only non-route", []corev1.EnvVar{{Name: "FOO", Value: "bar"}}, map[string]string{}},
		{"liveness only", []corev1.EnvVar{
			{Name: "WG_ROUTE_LIVENESS", Value: "active"},
			{Name: "FOO", Value: "bar"},
		}, map[string]string{"WG_ROUTE_LIVENESS": "active"}},
		{"full set", []corev1.EnvVar{
			{Name: "WG_ROUTE_LIVENESS", Value: "active"},
			{Name: "WG_ROUTE_FAILURE_COUNT", Value: ""},
			{Name: "WG_ROUTE_CHECK_INTERVAL", Value: "1s"},
			{Name: "WG_ROUTE_PROBE_INTERVAL", Value: "15s"},
		}, map[string]string{
			"WG_ROUTE_LIVENESS":       "active",
			"WG_ROUTE_FAILURE_COUNT":  "",
			"WG_ROUTE_CHECK_INTERVAL": "1s",
			"WG_ROUTE_PROBE_INTERVAL": "15s",
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := routeLivenessEnvOf(depWithAgentEnv(tc.env)); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}
}

func TestRouteLivenessEnvOf_NoAgentContainer(t *testing.T) {
	dep := &appsv1.Deployment{Spec: appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "wstunnel"}}},
	}}}
	if got := routeLivenessEnvOf(dep); len(got) != 0 {
		t.Fatalf("expected empty map for missing agent container, got %v", got)
	}
}

// TestRouteLivenessEnvDrift mirrors the reconcile decision: an agent Deployment
// created before the manager carried WG_ROUTE_LIVENESS has no such env, so it
// must register as drift against the freshly-built desired (which DOES carry it)
// — this is exactly the case the create-only stamping used to miss. Once the env
// matches, there must be no drift (no update churn).
func TestRouteLivenessEnvDrift(t *testing.T) {
	found := depWithAgentEnv(nil) // predates the manager env
	desired := depWithAgentEnv([]corev1.EnvVar{
		{Name: "WG_ROUTE_LIVENESS", Value: "active"},
		{Name: "WG_ROUTE_FAILURE_COUNT", Value: ""},
		{Name: "WG_ROUTE_CHECK_INTERVAL", Value: ""},
		{Name: "WG_ROUTE_PROBE_INTERVAL", Value: ""},
	})
	if reflect.DeepEqual(routeLivenessEnvOf(found), routeLivenessEnvOf(desired)) {
		t.Fatal("expected drift between env-less Deployment and desired carrying WG_ROUTE_LIVENESS")
	}
	if !reflect.DeepEqual(routeLivenessEnvOf(desired), routeLivenessEnvOf(desired)) {
		t.Fatal("expected no drift for identical env (would cause update churn)")
	}
}
