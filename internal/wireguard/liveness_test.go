package wireguard

import "testing"

func TestIsLive_NilSourceIsAllLive(t *testing.T) {
	if !isLive(nil, "anykey") {
		t.Fatal("nil LivenessSource must report all peers live (disabled mode)")
	}
}

func TestIsLive_DelegatesToSource(t *testing.T) {
	src := fakeSource{live: map[string]bool{"up": true, "down": false}}
	if !isLive(src, "up") {
		t.Error("expected up live")
	}
	if isLive(src, "down") {
		t.Error("expected down not-live")
	}
	if isLive(src, "unknown") {
		t.Error("expected unknown (absent) not-live")
	}
}

func TestParseMode(t *testing.T) {
	cases := map[string]Mode{"": ModeDisabled, "disabled": ModeDisabled, "passive": ModePassive, "active": ModeActive, "PASSIVE": ModePassive, "bogus": ModeDisabled}
	for in, want := range cases {
		if got := ParseMode(in); got != want {
			t.Errorf("ParseMode(%q) = %q, want %q", in, got, want)
		}
	}
}

type fakeSource struct{ live map[string]bool }

func (f fakeSource) IsLive(pk string) bool { return f.live[pk] }
