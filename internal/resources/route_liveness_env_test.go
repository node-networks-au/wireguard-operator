package resources

import "testing"

// TestRouteLivenessEnv_SurfacesAllKnobs locks down that the agent container's
// liveness-gated-route knobs are all surfaced from the operator's own env
// (deployment-template passthrough). Unset keys produce empty values, so the
// agent defaults to disabled — byte-identical to pre-feature behaviour.
func TestRouteLivenessEnv_SurfacesAllKnobs(t *testing.T) {
	want := map[string]bool{
		"WG_ROUTE_LIVENESS":       false,
		"WG_ROUTE_FAILURE_COUNT":  false,
		"WG_ROUTE_CHECK_INTERVAL": false,
		"WG_ROUTE_PROBE_INTERVAL": false,
	}

	got := routeLivenessEnv()
	for _, e := range got {
		if _, ok := want[e.Name]; ok {
			want[e.Name] = true
		}
	}

	for name, found := range want {
		if !found {
			t.Errorf("routeLivenessEnv() must surface env %q (deployment-template passthrough)", name)
		}
	}
	if len(got) != len(want) {
		t.Errorf("routeLivenessEnv() returned %d vars, want %d", len(got), len(want))
	}
}
