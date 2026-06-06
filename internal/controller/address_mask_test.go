package controllers

import "testing"

func TestAddrWithMask(t *testing.T) {
	cases := []struct {
		name, addr, cidr, want string
	}{
		{"v4 /24", "172.31.255.11", "172.31.255.0/24", "172.31.255.11/24"},
		{"v4 /16", "10.8.0.2", "10.8.0.0/16", "10.8.0.2/16"},
		{"v6 /64", "fd00::2", "fd00::/64", "fd00::2/64"},
		{"empty cidr falls back to bare", "172.31.255.11", "", "172.31.255.11"},
		{"empty addr stays empty", "", "172.31.255.0/24", ""},
		{"already masked is unchanged", "172.31.255.11/24", "172.31.255.0/24", "172.31.255.11/24"},
		{"invalid cidr falls back to bare", "172.31.255.11", "not-a-cidr", "172.31.255.11"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := addrWithMask(tc.addr, tc.cidr); got != tc.want {
				t.Fatalf("addrWithMask(%q, %q) = %q, want %q", tc.addr, tc.cidr, got, tc.want)
			}
		})
	}
}
