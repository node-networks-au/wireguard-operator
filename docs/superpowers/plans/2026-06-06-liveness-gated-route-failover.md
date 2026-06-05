# Liveness-gated WireGuard route failover — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make a WireGuard peer's downstream `spec.routes` install in `wg0` only while the peer is reachable, so traffic fails over to a broader live peer (longest-prefix) when it goes silent and re-attaches when it recovers.

**Architecture:** Agent-side only, as an extension of the existing Phase-G route path. A `LivenessSource` predicate is threaded into the existing route filters (`peerAllowedIPs`, `desiredKernelRoutes`) — a not-live peer is treated like a `Disabled` peer *for routes only*, keeping its `/32`. A 1 s watcher reads `wgctrl` counters, computes per-peer liveness (passive: `ReceiveBytes`/handshake stall at `N × keepalive`; active: `/32` handshake probes), and calls the existing `wg.Sync` on a transition. All add/remove reuses the existing `wg syncconf` diff + `RouteReplace`/`RouteDel` prune. Off by default (`WG_ROUTE_LIVENESS=disabled` ⇒ byte-identical).

**Tech Stack:** Go 1.26, `golang.zx2c4.com/wireguard/wgctrl`, `github.com/vishvananda/netlink`, stdlib `net`/`time`/`sync`. Module `github.com/nccloud/wireguard-operator`. Spec: `docs/superpowers/specs/2026-06-05-liveness-gated-route-failover-design.md`.

---

### Task 0: Verify clean baseline

**Files:** none.

- [ ] **Step 1: Run the existing package tests**

Run: `go test ./internal/wireguard/... ./internal/agent/...`
Expected: PASS (all existing tests green on `feat/liveness-gated-routes`).

- [ ] **Step 2: Confirm the gating seam exists**

Run: `grep -n "if peer.Spec.Disabled" internal/wireguard/wireguard.go`
Expected: two matches — in `BuildWgQuickConfig` and `desiredKernelRoutes`. These are the insertion points.

---

### Task 1: `LivenessSource` interface + nil-safe helper + mode parsing

**Files:**
- Create: `internal/wireguard/liveness.go`
- Test: `internal/wireguard/liveness_test.go`

- [ ] **Step 1: Write the failing test**

```go
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/wireguard/ -run 'TestIsLive|TestParseMode' -v`
Expected: FAIL — `undefined: isLive`, `undefined: Mode`, `undefined: ParseMode`.

- [ ] **Step 3: Write minimal implementation**

```go
package wireguard

import "strings"

// LivenessSource decides whether a peer's downstream routes (spec.routes /
// spec.routesV6) should currently be installed. A nil source means "all peers
// live" — i.e. disabled mode, byte-identical to the pre-feature behavior.
type LivenessSource interface {
	IsLive(publicKey string) bool
}

// isLive is the nil-safe accessor used by the route filters.
func isLive(src LivenessSource, publicKey string) bool {
	if src == nil {
		return true
	}
	return src.IsLive(publicKey)
}

// Mode selects the LivenessSource implementation.
type Mode string

const (
	ModeDisabled Mode = "disabled"
	ModePassive  Mode = "passive"
	ModeActive   Mode = "active"
)

// ParseMode maps an env value to a Mode; anything unrecognised (incl. empty)
// is treated as disabled so a misconfig fails safe to current behavior.
func ParseMode(s string) Mode {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case string(ModePassive):
		return ModePassive
	case string(ModeActive):
		return ModeActive
	default:
		return ModeDisabled
	}
}

// rejectAfterTime is WireGuard's REJECT_AFTER_TIME — a session key is dead after
// this with no new handshake. Used as the keepalive-less passive down threshold.
const rejectAfterTime = 180 // seconds
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/wireguard/ -run 'TestIsLive|TestParseMode' -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/wireguard/liveness.go internal/wireguard/liveness_test.go
git commit -m "feat(wireguard): add LivenessSource interface + Mode parsing"
```

---

### Task 2: Gate `peerAllowedIPs` / `BuildWgQuickConfig` on liveness (keep /32, gate spec.routes)

**Files:**
- Modify: `internal/wireguard/wireguard.go` (`peerAllowedIPs`, `BuildWgQuickConfig`)
- Modify: `internal/wireguard/wireguard_test.go` (existing `BuildWgQuickConfig(state, 51820)` call sites → add `nil`)
- Test: `internal/wireguard/wireguard_test.go` (new cases)

- [ ] **Step 1: Write the failing test**

```go
func TestPeerAllowedIPs_NotLiveDropsRoutesKeepsBase(t *testing.T) {
	peer := v1alpha1.WireguardPeer{Spec: v1alpha1.WireguardPeerSpec{
		PublicKey: validPeerPublicKey, Address: "172.31.255.11",
		Routes: []string{"10.254.2.0/24", "192.168.0.0/16"},
	}}
	// peerAllowedIPs renders allowedIPs from address/32 (base) + routes.
	live := peerAllowedIPs(peer, fakeSource{live: map[string]bool{validPeerPublicKey: true}})
	if live != "172.31.255.11/32,10.254.2.0/24,192.168.0.0/16" {
		t.Errorf("live peer = %q, want base+routes", live)
	}
	down := peerAllowedIPs(peer, fakeSource{live: map[string]bool{validPeerPublicKey: false}})
	if down != "172.31.255.11/32" {
		t.Errorf("not-live peer = %q, want base /32 only", down)
	}
	none := peerAllowedIPs(peer, nil) // disabled ⇒ all live
	if none != "172.31.255.11/32,10.254.2.0/24,192.168.0.0/16" {
		t.Errorf("nil source = %q, want base+routes (unchanged)", none)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/wireguard/ -run TestPeerAllowedIPs_NotLive -v`
Expected: FAIL — `peerAllowedIPs` takes 1 arg, not 2.

- [ ] **Step 3: Change `peerAllowedIPs` and `BuildWgQuickConfig` signatures**

In `internal/wireguard/wireguard.go`, change `func peerAllowedIPs(peer v1alpha1.WireguardPeer) string` to accept the source and gate the route appends:

```go
func peerAllowedIPs(peer v1alpha1.WireguardPeer, src LivenessSource) string {
	var out []string

	if peer.Spec.AllowedIPs != "" {
		for _, p := range strings.Split(peer.Spec.AllowedIPs, ",") {
			if p = strings.TrimSpace(p); p != "" {
				out = append(out, p)
			}
		}
	} else {
		if peer.Spec.Address != "" {
			out = append(out, peer.Spec.Address+"/32")
		}
		if peer.Spec.AddressV6 != "" {
			out = append(out, peer.Spec.AddressV6+"/128")
		}
	}

	// Liveness gate: spec.routes / spec.routesV6 are the downstream CIDRs and are
	// installed only while the peer is live. The base (above) is always kept so
	// the peer can still handshake and recover. A not-live peer is treated like a
	// Disabled peer FOR ROUTES ONLY.
	if isLive(src, peer.Spec.PublicKey) {
		for _, r := range peer.Spec.Routes {
			if r = strings.TrimSpace(r); r != "" {
				out = append(out, r)
			}
		}
		for _, r := range peer.Spec.RoutesV6 {
			if r = strings.TrimSpace(r); r != "" {
				out = append(out, r)
			}
		}
	}

	return strings.Join(out, ",")
}
```

Then in `BuildWgQuickConfig`, change the signature and the one call site:

```go
func BuildWgQuickConfig(state agent.State, listenPort int, src LivenessSource) (string, error) {
```

and inside its peer loop replace `allowed := peerAllowedIPs(peer)` with:

```go
		allowed := peerAllowedIPs(peer, src)
```

- [ ] **Step 4: Update existing `BuildWgQuickConfig` call sites to pass `nil`**

In `internal/wireguard/wireguard.go`, `syncWireguard` calls it — change to thread the field added in Task 4. For now (pre-Task-4) pass `nil`:

```go
	cfg, err := BuildWgQuickConfig(state, listenPort, nil)
```

In `internal/wireguard/wireguard_test.go`, update **every** `BuildWgQuickConfig(state, 51820)` to `BuildWgQuickConfig(state, 51820, nil)` (preserves existing assertions — nil = all live = old behavior).

Run: `grep -n "BuildWgQuickConfig(" internal/wireguard/wireguard_test.go` and fix each.

- [ ] **Step 5: Run tests to verify pass**

Run: `go test ./internal/wireguard/ -v`
Expected: PASS (new `TestPeerAllowedIPs_NotLive...` + all pre-existing tests with `nil`).

- [ ] **Step 6: Commit**

```bash
git add internal/wireguard/wireguard.go internal/wireguard/wireguard_test.go
git commit -m "feat(wireguard): gate peer spec.routes in AllowedIPs by liveness (keep /32)"
```

---

### Task 3: Gate `desiredKernelRoutes` on liveness

**Files:**
- Modify: `internal/wireguard/wireguard.go` (`desiredKernelRoutes`, its caller `syncPeerRoutes`)
- Modify: `internal/wireguard/wireguard_test.go` (existing `desiredKernelRoutes(peers)` calls → add `nil`)
- Test: `internal/wireguard/wireguard_test.go` (new case)

- [ ] **Step 1: Write the failing test**

```go
func TestDesiredKernelRoutes_GatedByLiveness(t *testing.T) {
	peers := []v1alpha1.WireguardPeer{
		{Spec: v1alpha1.WireguardPeerSpec{PublicKey: validPeerPublicKey, Address: "10.0.0.1", Routes: []string{"10.254.1.0/24"}}},
		{Spec: v1alpha1.WireguardPeerSpec{PublicKey: validPeerPublicKey2, Address: "10.0.0.2", Routes: []string{"10.254.2.0/24"}}},
	}
	src := fakeSource{live: map[string]bool{validPeerPublicKey: true, validPeerPublicKey2: false}}
	got := desiredKernelRoutes(peers, src)
	if len(got) != 1 || got[0] != "10.254.1.0/24" {
		t.Errorf("gated desiredKernelRoutes = %v, want [10.254.1.0/24] (down peer's /24 excluded)", got)
	}
	all := desiredKernelRoutes(peers, nil) // disabled ⇒ both
	if len(all) != 2 {
		t.Errorf("nil source = %v, want both routes (unchanged)", all)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/wireguard/ -run TestDesiredKernelRoutes_GatedByLiveness -v`
Expected: FAIL — `desiredKernelRoutes` takes 1 arg.

- [ ] **Step 3: Change `desiredKernelRoutes` to gate on liveness**

```go
func desiredKernelRoutes(peers []v1alpha1.WireguardPeer, src LivenessSource) []string {
	seen := map[string]bool{}
	var out []string
	for _, peer := range peers {
		if peer.Spec.Disabled {
			continue
		}
		if peer.Spec.PublicKey == "" {
			continue
		}
		// Liveness gate: mirror the Disabled skip — a not-live peer's downstream
		// routes must not sit in the kernel table either (the RouteDel prune in
		// syncPeerRoutes withdraws them when they drop out of this set).
		if !isLive(src, peer.Spec.PublicKey) {
			continue
		}
		for _, r := range peer.Spec.Routes {
			r = strings.TrimSpace(r)
			if r == "" || seen[r] {
				continue
			}
			seen[r] = true
			out = append(out, r)
		}
		for _, r := range peer.Spec.RoutesV6 {
			r = strings.TrimSpace(r)
			if r == "" || seen[r] {
				continue
			}
			seen[r] = true
			out = append(out, r)
		}
	}
	return out
}
```

- [ ] **Step 4: Update callers**

In `syncPeerRoutes`, change `desired := desiredKernelRoutes(state.Peers)` to thread the field (Task 4); for now pass `nil`:

```go
	desired := desiredKernelRoutes(state.Peers, nil)
```

In `wireguard_test.go`, update every `desiredKernelRoutes(peers)` to `desiredKernelRoutes(peers, nil)`.

- [ ] **Step 5: Run tests to verify pass**

Run: `go test ./internal/wireguard/ -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/wireguard/wireguard.go internal/wireguard/wireguard_test.go
git commit -m "feat(wireguard): gate desiredKernelRoutes by liveness (mirrors Disabled skip)"
```

---

### Task 4: Wire `Wireguard.Liveness` field through `Sync`

**Files:**
- Modify: `internal/wireguard/wireguard.go` (`Wireguard` struct, `syncWireguard`, `syncPeerRoutes`)
- Test: `internal/wireguard/wireguard_test.go`

- [ ] **Step 1: Write the failing test**

```go
func TestWireguard_LivenessFieldDefaultsNil(t *testing.T) {
	wg := Wireguard{}
	if wg.Liveness != nil {
		t.Fatal("Liveness must default nil (disabled / all-live)")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/wireguard/ -run TestWireguard_LivenessFieldDefaultsNil -v`
Expected: FAIL — `wg.Liveness` undefined.

- [ ] **Step 3: Add the field and thread it**

Add to the `Wireguard` struct:

```go
type Wireguard struct {
	Logger                            logr.Logger
	Iface                             string
	ListenPort                        int
	WgUserspaceImplementationFallback string
	WgUseUserspaceImpl                bool
	// Liveness gates per-peer spec.routes. nil ⇒ all peers live (disabled mode).
	Liveness LivenessSource
}
```

In `syncWireguard`, change the `BuildWgQuickConfig` call from `nil` to `wg.Liveness`:

```go
	cfg, err := BuildWgQuickConfig(state, listenPort, wg.Liveness)
```

In `Sync`, change the `syncPeerRoutes` call to pass the source. Update `syncPeerRoutes`'s signature to take it:

```go
func syncPeerRoutes(iface string, state agent.State, src LivenessSource, logger logr.Logger) error {
```

and inside it: `desired := desiredKernelRoutes(state.Peers, src)`. Update the call in `Sync`:

```go
	if err := syncPeerRoutes(wg.Iface, state, wg.Liveness, wg.Logger); err != nil {
```

- [ ] **Step 4: Run tests to verify pass**

Run: `go test ./internal/wireguard/ -v`
Expected: PASS — `wg.Liveness` nil by default keeps every existing test green.

- [ ] **Step 5: Commit**

```bash
git add internal/wireguard/wireguard.go internal/wireguard/wireguard_test.go
git commit -m "feat(wireguard): thread Wireguard.Liveness through Sync (nil=disabled, no behavior change)"
```

---

### Task 5: `deviceReader` interface + wgctrl implementation

**Files:**
- Modify: `internal/wireguard/liveness.go`
- Test: `internal/wireguard/liveness_test.go`

- [ ] **Step 1: Write the failing test**

```go
import "time"

func TestPeerStat_FakeReaderRoundTrips(t *testing.T) {
	now := time.Unix(1000, 0)
	r := fakeReader{peers: []peerStat{{PublicKey: "k", LastHandshakeTime: now, ReceiveBytes: 42}}}
	got, err := r.readPeers()
	if err != nil || len(got) != 1 || got[0].ReceiveBytes != 42 || got[0].PublicKey != "k" {
		t.Fatalf("readPeers = %+v, %v", got, err)
	}
}

type fakeReader struct {
	peers []peerStat
	err   error
}

func (f fakeReader) readPeers() ([]peerStat, error) { return f.peers, f.err }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/wireguard/ -run TestPeerStat_FakeReader -v`
Expected: FAIL — `undefined: peerStat`, `readPeers`.

- [ ] **Step 3: Implement `peerStat`, `deviceReader`, and the wgctrl reader**

Append to `internal/wireguard/liveness.go`:

```go
import (
	"time"

	"golang.zx2c4.com/wireguard/wgctrl"
)

// peerStat is the liveness-relevant snapshot of one wg peer.
type peerStat struct {
	PublicKey         string
	LastHandshakeTime time.Time
	ReceiveBytes      int64
}

// deviceReader yields a snapshot of all peers' counters. Abstracted so the
// liveness logic is unit-testable without a real wg0 / root / netlink.
type deviceReader interface {
	readPeers() ([]peerStat, error)
}

// wgctrlReader reads the live device via a long-lived wgctrl client.
type wgctrlReader struct {
	client *wgctrl.Client
	iface  string
}

func newWgctrlReader(iface string) (*wgctrlReader, error) {
	c, err := wgctrl.New()
	if err != nil {
		return nil, err
	}
	return &wgctrlReader{client: c, iface: iface}, nil
}

func (w *wgctrlReader) readPeers() ([]peerStat, error) {
	dev, err := w.client.Device(w.iface)
	if err != nil {
		return nil, err
	}
	out := make([]peerStat, 0, len(dev.Peers))
	for _, p := range dev.Peers {
		out = append(out, peerStat{
			PublicKey:         p.PublicKey.String(),
			LastHandshakeTime: p.LastHandshakeTime,
			ReceiveBytes:      p.ReceiveBytes,
		})
	}
	return out, nil
}

func (w *wgctrlReader) Close() error { return w.client.Close() }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/wireguard/ -run TestPeerStat_FakeReader -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/wireguard/liveness.go internal/wireguard/liveness_test.go
git commit -m "feat(wireguard): deviceReader interface + long-lived wgctrl reader"
```

---

### Task 6: `passiveLiveness` source (ReceiveBytes/handshake stall, per-peer downWindow)

**Files:**
- Modify: `internal/wireguard/liveness.go`
- Test: `internal/wireguard/liveness_test.go`

- [ ] **Step 1: Write the failing tests (the four scenarios)**

```go
func ts(sec int64) time.Time { return time.Unix(sec, 0) }

func TestPassive_NeverActiveIsNotLive(t *testing.T) {
	clk := ts(1000)
	p := newPassiveLiveness(3, func() time.Time { return clk })
	p.setKeepalive("k", 25*time.Second)
	p.observe([]peerStat{{PublicKey: "k", ReceiveBytes: 0}}) // never any progress
	if p.IsLive("k") {
		t.Fatal("never-active peer must be not-live")
	}
}

func TestPassive_LiveWhileReceiveBytesAdvance(t *testing.T) {
	clk := ts(1000)
	p := newPassiveLiveness(3, func() time.Time { return clk })
	p.setKeepalive("k", 25*time.Second) // downWindow = 75s
	p.observe([]peerStat{{PublicKey: "k", ReceiveBytes: 100}})
	clk = ts(1050) // 50s later, still within 75s
	if !p.IsLive("k") {
		t.Fatal("peer within downWindow must be live")
	}
}

func TestPassive_DownAfterNKeepalivesMissed(t *testing.T) {
	clk := ts(1000)
	p := newPassiveLiveness(3, func() time.Time { return clk })
	p.setKeepalive("k", 25*time.Second) // downWindow = 75s
	p.observe([]peerStat{{PublicKey: "k", ReceiveBytes: 100}})
	clk = ts(1076) // 76s later, > 75s, no new bytes
	p.observe([]peerStat{{PublicKey: "k", ReceiveBytes: 100}})
	if p.IsLive("k") {
		t.Fatal("peer silent > N*keepalive must be not-live")
	}
}

func TestPassive_KeepaliveLessFallsBackTo180s(t *testing.T) {
	clk := ts(1000)
	p := newPassiveLiveness(3, func() time.Time { return clk })
	// no setKeepalive ⇒ 180s fallback
	p.observe([]peerStat{{PublicKey: "k", ReceiveBytes: 100}})
	clk = ts(1170) // 170s < 180s
	if !p.IsLive("k") {
		t.Fatal("keepalive-less peer within 180s must be live")
	}
	clk = ts(1181) // 181s > 180s
	if p.IsLive("k") {
		t.Fatal("keepalive-less peer past 180s must be not-live")
	}
}

func TestPassive_HandshakeCountsAsProgress(t *testing.T) {
	clk := ts(2000)
	p := newPassiveLiveness(3, func() time.Time { return clk })
	p.setKeepalive("k", 25*time.Second)
	// no RX increase, but a fresh handshake at t=1990
	p.observe([]peerStat{{PublicKey: "k", ReceiveBytes: 0, LastHandshakeTime: ts(1990)}})
	if !p.IsLive("k") {
		t.Fatal("recent handshake must keep peer live even without RX delta")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/wireguard/ -run TestPassive -v`
Expected: FAIL — `undefined: newPassiveLiveness`.

- [ ] **Step 3: Implement `passiveLiveness`**

Append to `internal/wireguard/liveness.go` (add `"sync"` to imports):

```go
type progress struct {
	lastRX      int64
	lastAdvance time.Time // most recent of {observed RX increase, handshake time}
}

type passiveLiveness struct {
	mu        sync.Mutex
	seen      map[string]progress
	keepalive map[string]time.Duration // per-peer, from spec.PersistentKeepalive
	failures  int                      // N (WG_ROUTE_FAILURE_COUNT)
	now       func() time.Time
}

func newPassiveLiveness(failures int, now func() time.Time) *passiveLiveness {
	if failures < 1 {
		failures = 1
	}
	if now == nil {
		now = time.Now
	}
	return &passiveLiveness{
		seen:      map[string]progress{},
		keepalive: map[string]time.Duration{},
		failures:  failures,
		now:       now,
	}
}

// setKeepalive records a peer's keepalive interval (0/absent ⇒ 180s fallback).
func (p *passiveLiveness) setKeepalive(publicKey string, k time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if k > 0 {
		p.keepalive[publicKey] = k
	} else {
		delete(p.keepalive, publicKey)
	}
}

// observe folds a device snapshot into per-peer last-progress.
func (p *passiveLiveness) observe(stats []peerStat) {
	now := p.now()
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, s := range stats {
		pr := p.seen[s.PublicKey]
		if s.ReceiveBytes > pr.lastRX {
			pr.lastRX = s.ReceiveBytes
			pr.lastAdvance = now
		}
		if s.LastHandshakeTime.After(pr.lastAdvance) {
			pr.lastAdvance = s.LastHandshakeTime
		}
		p.seen[s.PublicKey] = pr
	}
}

func (p *passiveLiveness) downWindow(publicKey string) time.Duration {
	if k, ok := p.keepalive[publicKey]; ok && k > 0 {
		return time.Duration(p.failures) * k
	}
	return rejectAfterTime * time.Second
}

// freshWithin reports whether the peer showed progress within d (used by active).
func (p *passiveLiveness) freshWithin(publicKey string, d time.Duration) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	pr, ok := p.seen[publicKey]
	if !ok || pr.lastAdvance.IsZero() {
		return false
	}
	return p.now().Sub(pr.lastAdvance) <= d
}

func (p *passiveLiveness) IsLive(publicKey string) bool {
	p.mu.Lock()
	win := p.downWindow(publicKey)
	pr, ok := p.seen[publicKey]
	now := p.now()
	p.mu.Unlock()
	if !ok || pr.lastAdvance.IsZero() {
		return false
	}
	return now.Sub(pr.lastAdvance) <= win
}
```

> Note: `downWindow` locks via callers; `IsLive` reads `keepalive`/`seen` under the same lock — keep the lock around both map reads as written.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/wireguard/ -run TestPassive -v`
Expected: PASS (all five scenarios).

- [ ] **Step 5: Commit**

```bash
git add internal/wireguard/liveness.go internal/wireguard/liveness_test.go
git commit -m "feat(wireguard): passive liveness source (ReceiveBytes/handshake stall, per-peer N*keepalive window)"
```

---

### Task 7: `LivenessController` watcher (tick → observe → transition → Sync)

**Files:**
- Modify: `internal/wireguard/liveness.go`
- Test: `internal/wireguard/liveness_test.go`

- [ ] **Step 1: Write the failing test**

```go
func TestController_AppliesOnlyOnTransition(t *testing.T) {
	clk := ts(1000)
	pass := newPassiveLiveness(3, func() time.Time { return clk })
	pass.setKeepalive("k", 25*time.Second)
	applied := 0
	c := &LivenessController{
		source:  pass,
		reader:  fakeReader{peers: []peerStat{{PublicKey: "k", ReceiveBytes: 100}}},
		apply:   func() error { applied++; return nil },
		lastUp:  map[string]bool{},
	}
	c.tickOnce() // first observation: k transitions absent->live
	if applied != 1 {
		t.Fatalf("expected 1 apply on first up-transition, got %d", applied)
	}
	c.tickOnce() // no change ⇒ no apply
	if applied != 1 {
		t.Fatalf("quiet tick must not apply, got %d", applied)
	}
	clk = ts(1100) // 100s later, > 75s window, no new bytes
	c.reader = fakeReader{peers: []peerStat{{PublicKey: "k", ReceiveBytes: 100}}}
	c.tickOnce() // live->not-live transition
	if applied != 2 {
		t.Fatalf("expected apply on down-transition, got %d", applied)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/wireguard/ -run TestController_AppliesOnlyOnTransition -v`
Expected: FAIL — `undefined: LivenessController`.

- [ ] **Step 3: Implement the controller**

Append to `internal/wireguard/liveness.go` (add `"context"` to imports):

```go
// observer is the subset of a liveness source the controller drives each tick.
type observer interface {
	LivenessSource
	observe([]peerStat)
}

// LivenessController owns the watcher goroutine. It reads the device on a timer,
// folds it into the source, and calls apply() only when a peer's live state
// transitions. It also IS the LivenessSource handed to the Wireguard struct.
type LivenessController struct {
	source        observer
	reader        deviceReader
	apply         func() error // wired to wg.Sync(latestState)
	checkInterval time.Duration
	logger        logr.Logger

	mu     sync.Mutex
	lastUp map[string]bool // pubkey -> last observed live state
}

func (c *LivenessController) IsLive(publicKey string) bool { return c.source.IsLive(publicKey) }

// tickOnce performs one read+observe+transition-detect. Returns whether it applied.
func (c *LivenessController) tickOnce() bool {
	stats, err := c.reader.readPeers()
	if err != nil {
		c.logger.Error(err, "liveness read failed")
		return false
	}
	c.source.observe(stats)
	changed := false
	c.mu.Lock()
	for _, s := range stats {
		up := c.source.IsLive(s.PublicKey)
		if prev, ok := c.lastUp[s.PublicKey]; !ok || prev != up {
			c.lastUp[s.PublicKey] = up
			changed = true
			c.logger.V(1).Info("peer liveness transition", "peer", s.PublicKey, "live", up)
		}
	}
	c.mu.Unlock()
	if changed && c.apply != nil {
		if err := c.apply(); err != nil {
			c.logger.Error(err, "liveness apply (wg.Sync) failed")
		}
		return true
	}
	return false
}

// Run drives tickOnce every checkInterval until ctx is done.
func (c *LivenessController) Run(ctx context.Context) {
	t := time.NewTicker(c.checkInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.tickOnce()
		}
	}
}
```

> `passiveLiveness` already satisfies `observer` (it has `IsLive` and `observe`).

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/wireguard/ -run TestController_AppliesOnlyOnTransition -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/wireguard/liveness.go internal/wireguard/liveness_test.go
git commit -m "feat(wireguard): LivenessController watcher — edge-triggered Sync on transition"
```

---

### Task 8: Active mode — `/32` probe + N-unanswered down

**Files:**
- Modify: `internal/wireguard/liveness.go`
- Test: `internal/wireguard/liveness_test.go`

- [ ] **Step 1: Write the failing test**

```go
func TestActive_DownAfterNUnansweredProbes(t *testing.T) {
	clk := ts(1000)
	pass := newPassiveLiveness(3, func() time.Time { return clk })
	pass.setKeepalive("k", 25*time.Second)
	pass.observe([]peerStat{{PublicKey: "k", ReceiveBytes: 100}}) // start live
	probes := 0
	a := newActiveLiveness(pass, 3, 15*time.Second, func() time.Time { return clk }, proberFunc(func(string) { probes++ }))
	a.setAddr("k", "172.31.255.11")
	if !a.IsLive("k") {
		t.Fatal("starts live")
	}
	// advance past window with no progress; each probe interval => one failed probe
	for i := 1; i <= 3; i++ {
		clk = ts(1000 + int64(i)*15)
		a.tick([]peerStat{{PublicKey: "k", ReceiveBytes: 100}})
	}
	if probes < 3 {
		t.Fatalf("expected >=3 probes, got %d", probes)
	}
	if a.IsLive("k") {
		t.Fatal("peer must be down after N unanswered probes")
	}
}

func TestActive_ProbeResponseRevives(t *testing.T) {
	clk := ts(1000)
	pass := newPassiveLiveness(3, func() time.Time { return clk })
	pass.setKeepalive("k", 25*time.Second)
	pass.observe([]peerStat{{PublicKey: "k", ReceiveBytes: 100}})
	a := newActiveLiveness(pass, 3, 15*time.Second, func() time.Time { return clk }, proberFunc(func(string) {}))
	a.setAddr("k", "172.31.255.11")
	clk = ts(1016)
	a.tick([]peerStat{{PublicKey: "k", ReceiveBytes: 100}}) // 1 failed probe
	clk = ts(1031)
	a.tick([]peerStat{{PublicKey: "k", ReceiveBytes: 200}}) // RX advanced ⇒ revive
	if !a.IsLive("k") {
		t.Fatal("inbound progress must reset failure count and keep peer live")
	}
}

type proberFunc func(addr string)

func (f proberFunc) probe(addr string) { f(addr) }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/wireguard/ -run TestActive -v`
Expected: FAIL — `undefined: newActiveLiveness`.

- [ ] **Step 3: Implement `activeLiveness` + UDP prober**

Append to `internal/wireguard/liveness.go` (add `"net"` to imports):

```go
// prober forces a handshake toward a peer by sending a packet to its tunnel
// address (routed via the retained /32). Abstracted for tests.
type prober interface {
	probe(addr string)
}

// udpProber sends one byte to <addr>:9 (discard). The kernel routes it via wg0,
// which triggers a WireGuard handshake without needing the downstream route.
type udpProber struct{}

func (udpProber) probe(addr string) {
	c, err := net.DialTimeout("udp", net.JoinHostPort(addr, "9"), time.Second)
	if err != nil {
		return
	}
	defer c.Close()
	_, _ = c.Write([]byte{0})
}

// activeLiveness layers /32 probing over passive: it probes a quiet peer every
// probeEvery and marks it down after N consecutive unanswered probes. Any
// inbound progress resets the failure count.
type activeLiveness struct {
	passive   *passiveLiveness
	prober    prober
	failures  int
	probeEvery time.Duration
	now       func() time.Time

	mu        sync.Mutex
	failed    map[string]int
	lastProbe map[string]time.Time
	addr      map[string]string
}

func newActiveLiveness(passive *passiveLiveness, failures int, probeEvery time.Duration, now func() time.Time, pr prober) *activeLiveness {
	if failures < 1 {
		failures = 1
	}
	if now == nil {
		now = time.Now
	}
	return &activeLiveness{
		passive: passive, prober: pr, failures: failures, probeEvery: probeEvery, now: now,
		failed: map[string]int{}, lastProbe: map[string]time.Time{}, addr: map[string]string{},
	}
}

func (a *activeLiveness) setAddr(publicKey, addr string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if addr != "" {
		a.addr[publicKey] = addr
	}
}

// observe satisfies observer; it folds into passive then runs a probe pass.
func (a *activeLiveness) observe(stats []peerStat) { a.tick(stats) }

func (a *activeLiveness) tick(stats []peerStat) {
	a.passive.observe(stats)
	now := a.now()
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, s := range stats {
		pk := s.PublicKey
		// Fresh progress within a probe interval ⇒ healthy, reset failures.
		if a.passive.freshWithin(pk, a.probeEvery) {
			a.failed[pk] = 0
			continue
		}
		// Quiet: probe if due, count this probe as failed until progress proves it.
		if now.Sub(a.lastProbe[pk]) >= a.probeEvery {
			if addr := a.addr[pk]; addr != "" {
				a.prober.probe(addr)
			}
			a.lastProbe[pk] = now
			a.failed[pk]++
		}
	}
}

func (a *activeLiveness) IsLive(publicKey string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.failed[publicKey] < a.failures
}
```

> `activeLiveness` satisfies `observer` (has `IsLive` + `observe`). The controller treats either source uniformly.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/wireguard/ -run TestActive -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/wireguard/liveness.go internal/wireguard/liveness_test.go
git commit -m "feat(wireguard): active liveness — /32 UDP probe, down after N unanswered, progress revives"
```

---

### Task 9: Env wiring in `cmd/agent/main.go`

**Files:**
- Modify: `cmd/agent/main.go`
- Modify: `internal/wireguard/liveness.go` (a `BuildController` constructor)
- Test: `internal/wireguard/liveness_test.go`

- [ ] **Step 1: Write the failing test for the constructor**

```go
func TestBuildController_DisabledReturnsNil(t *testing.T) {
	c := BuildController(Config{Mode: ModeDisabled}, nil, logr.Discard())
	if c != nil {
		t.Fatal("disabled mode must yield a nil controller (no watcher, nil Liveness)")
	}
}

func TestBuildController_PassiveAndActiveNonNil(t *testing.T) {
	for _, m := range []Mode{ModePassive, ModeActive} {
		c := BuildController(Config{Mode: m, FailureCount: 3, CheckInterval: time.Second, ProbeInterval: 15 * time.Second}, fakeReader{}, logr.Discard())
		if c == nil {
			t.Fatalf("mode %q must yield a controller", m)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/wireguard/ -run TestBuildController -v`
Expected: FAIL — `undefined: BuildController`, `Config`.

- [ ] **Step 3: Implement the constructor**

Append to `internal/wireguard/liveness.go`:

```go
// Config holds the env-derived liveness knobs.
type Config struct {
	Mode          Mode
	FailureCount  int           // N
	CheckInterval time.Duration // watcher tick (WG_ROUTE_CHECK_INTERVAL)
	ProbeInterval time.Duration // active probe cadence (WG_ROUTE_PROBE_INTERVAL)
}

// BuildController returns a configured controller, or nil for disabled mode.
// The caller wires c.apply and starts c.Run; for disabled mode it leaves
// Wireguard.Liveness nil (all-live, current behavior).
func BuildController(cfg Config, reader deviceReader, logger logr.Logger) *LivenessController {
	if cfg.Mode == ModeDisabled {
		return nil
	}
	passive := newPassiveLiveness(cfg.FailureCount, time.Now)
	var src observer = passive
	if cfg.Mode == ModeActive {
		src = newActiveLiveness(passive, cfg.FailureCount, cfg.ProbeInterval, time.Now, udpProber{})
	}
	return &LivenessController{
		source:        src,
		reader:        reader,
		checkInterval: cfg.CheckInterval,
		logger:        logger,
		lastUp:        map[string]bool{},
	}
}

// SetPeers feeds per-peer keepalive + (active) tunnel addresses from the latest
// state so windows and probe targets track config. Safe to call on every state
// change. No-op fields are ignored.
func (c *LivenessController) SetPeers(peers []peerInfo) {
	switch s := c.source.(type) {
	case *passiveLiveness:
		for _, p := range peers {
			s.setKeepalive(p.PublicKey, p.Keepalive)
		}
	case *activeLiveness:
		for _, p := range peers {
			s.passive.setKeepalive(p.PublicKey, p.Keepalive)
			s.setAddr(p.PublicKey, p.Address)
		}
	}
}

// peerInfo is the minimal per-peer config the controller needs.
type peerInfo struct {
	PublicKey string
	Keepalive time.Duration
	Address   string
}
```

- [ ] **Step 4: Wire it into `cmd/agent/main.go`**

Add env parsing near the other flags in `main()` (after `flag.Parse()`), and a helper. Add imports `"os"`, `"strconv"`, `"time"`, `"context"` if missing (context/os already present):

```go
	// Liveness-gated routes (off by default → nil Liveness → current behavior).
	livenessCfg := wireguard.Config{
		Mode:          wireguard.ParseMode(os.Getenv("WG_ROUTE_LIVENESS")),
		FailureCount:  envInt("WG_ROUTE_FAILURE_COUNT", 3),
		CheckInterval: envDur("WG_ROUTE_CHECK_INTERVAL", time.Second),
		ProbeInterval: envDur("WG_ROUTE_PROBE_INTERVAL", 15*time.Second),
	}
```

Add helpers at file scope in `main.go`:

```go
func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return def
}

func envDur(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return def
}
```

After `wg` is constructed and before the HTTP server starts, build + start the controller and share the latest state. Replace the existing `OnStateChange(...)` wiring so the callback updates a shared state pointer and (when a controller exists) feeds peers:

```go
	var (
		stateMu     sync.Mutex
		latestState agent.State
	)
	applyLatest := func() error {
		stateMu.Lock()
		s := latestState
		stateMu.Unlock()
		return wg.Sync(s)
	}

	reader, _ := wireguard.NewDeviceReader(iface) // nil-safe; logs handled in Run
	controller := wireguard.BuildController(livenessCfg, reader, log.WithName("liveness"))
	if controller != nil {
		wg.Liveness = controller
		controller.SetApply(applyLatest)
	}

	close, err := agent.OnStateChange(configFilePath, log, func(state agent.State) {
		stateMu.Lock()
		latestState = state
		stateMu.Unlock()
		if controller != nil {
			controller.SetPeers(wireguard.PeerInfos(state))
		}
		if err := wg.Sync(state); err != nil {
			log.Error(err, "Error while syncing wireguard")
		}
		if err := it.Sync(state); err != nil {
			log.Error(err, "Error while syncing network policies")
		}
	})
	...
	if controller != nil {
		go controller.Run(ctx) // ctx from signal.NotifyContext below — move its creation above this line
	}
```

> Implementation notes for the engineer: (1) move the `ctx, stop := signal.NotifyContext(...)` line above the `controller.Run` call. (2) `it.Sync` is the existing network-policy sync — preserve it exactly as in the current `onFileChange`. (3) add `"sync"` to imports.

- [ ] **Step 5: Add the small exported shims used above**

Append to `internal/wireguard/liveness.go`:

```go
// NewDeviceReader returns the production wgctrl-backed reader (exported for main).
func NewDeviceReader(iface string) (deviceReader, error) { return newWgctrlReader(iface) }

// SetApply wires the controller's transition action (wg.Sync of latest state).
func (c *LivenessController) SetApply(fn func() error) { c.apply = fn }

// PeerInfos extracts the controller's per-peer config from agent state.
func PeerInfos(state agent.State) []peerInfo {
	out := make([]peerInfo, 0, len(state.Peers))
	for _, p := range state.Peers {
		var k time.Duration
		if p.Spec.PersistentKeepalive != nil && *p.Spec.PersistentKeepalive > 0 {
			k = time.Duration(*p.Spec.PersistentKeepalive) * time.Second
		}
		out = append(out, peerInfo{PublicKey: p.Spec.PublicKey, Keepalive: k, Address: p.Spec.Address})
	}
	return out
}
```

> Add `"github.com/nccloud/wireguard-operator/internal/agent"` to `liveness.go` imports (already used by the package).

- [ ] **Step 6: Build + run all tests**

Run: `go build ./... && go test ./...`
Expected: PASS, binary builds.

- [ ] **Step 7: Verify disabled-mode no-op manually**

Run: `WG_ROUTE_LIVENESS= go test ./internal/wireguard/ -run TestBuildController -v`
Expected: PASS — disabled yields nil controller.

- [ ] **Step 8: Commit**

```bash
git add cmd/agent/main.go internal/wireguard/liveness.go
git commit -m "feat(agent): wire WG_ROUTE_* env → liveness controller; default disabled is a no-op"
```

---

### Task 10: Observability — routes-active metric + transition log

**Files:**
- Modify: `internal/wireguard/liveness.go` (emit metric on transition)
- Modify: `internal/agent/wireguard_metrics.go` (register a gauge) OR add `internal/wireguard/metrics.go`
- Test: `internal/wireguard/liveness_test.go`

- [ ] **Step 1: Write the failing test**

```go
func TestController_SetsRoutesActiveGauge(t *testing.T) {
	clk := ts(1000)
	pass := newPassiveLiveness(3, func() time.Time { return clk })
	pass.setKeepalive("k", 25*time.Second)
	var lastPK string
	var lastVal float64
	c := &LivenessController{
		source: pass,
		reader: fakeReader{peers: []peerStat{{PublicKey: "k", ReceiveBytes: 100}}},
		apply:  func() error { return nil },
		lastUp: map[string]bool{},
		setGauge: func(pk string, v float64) { lastPK = pk; lastVal = v },
	}
	c.tickOnce()
	if lastPK != "k" || lastVal != 1 {
		t.Fatalf("gauge = (%q,%v), want (k,1) on up-transition", lastPK, lastVal)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/wireguard/ -run TestController_SetsRoutesActiveGauge -v`
Expected: FAIL — `LivenessController` has no `setGauge` field.

- [ ] **Step 3: Add the gauge hook + wire a Prometheus gauge**

Add field `setGauge func(publicKey string, value float64)` to `LivenessController`. In `tickOnce`, inside the transition branch (`!ok || prev != up`), after logging add:

```go
			if c.setGauge != nil {
				v := 0.0
				if up {
					v = 1.0
				}
				c.setGauge(s.PublicKey, v)
			}
```

In `BuildController`, register and assign the gauge:

```go
	gauge := routesActiveGauge() // package-level prometheus.GaugeVec, registered once
	ctrl := &LivenessController{ ... , setGauge: func(pk string, v float64) { gauge.WithLabelValues(pk).Set(v) }}
```

Add to `internal/wireguard/metrics.go`:

```go
package wireguard

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	routesActiveOnce sync.Once
	routesActiveVec  *prometheus.GaugeVec
)

func routesActiveGauge() *prometheus.GaugeVec {
	routesActiveOnce.Do(func() {
		routesActiveVec = prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "wireguard_peer_routes_active",
			Help: "1 if a peer's downstream routes are currently installed (liveness-gated), else 0.",
		}, []string{"peer"})
		prometheus.MustRegister(routesActiveVec)
	})
	return routesActiveVec
}
```

- [ ] **Step 4: Run tests to verify pass**

Run: `go test ./internal/wireguard/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/wireguard/liveness.go internal/wireguard/metrics.go
git commit -m "feat(wireguard): wireguard_peer_routes_active gauge + transition logging"
```

---

### Task 11: Operator deployment-template env passthrough (non-CRD delivery)

**Files:**
- Modify: `internal/resources/deployment.go` (agent container env)
- Test: `internal/resources/deployment_test.go` (if present; else add a focused test)

- [ ] **Step 1: Find where the agent container env is built**

Run: `grep -n "Env\|Container{" internal/resources/deployment.go | head`
Expected: locate the agent container's `Env []corev1.EnvVar`.

- [ ] **Step 2: Write the failing test**

```go
func TestAgentDeployment_PassesRouteLivenessEnv(t *testing.T) {
	// Construct the agent deployment via the existing builder with the env knobs
	// set (mechanism mirrors how other agent env is injected in this file).
	dep := /* call the existing deployment builder */
	found := false
	for _, c := range dep.Spec.Template.Spec.Containers {
		for _, e := range c.Env {
			if e.Name == "WG_ROUTE_LIVENESS" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("agent container must surface WG_ROUTE_LIVENESS env")
	}
}
```

> The engineer must adapt the `dep := ...` line to this repo's actual deployment-builder signature (see the top of `deployment.go`).

- [ ] **Step 3: Add the env passthrough**

In the agent container's `Env`, append the four knobs sourced from the operator's own env (so a single operator-level setting flows to every agent), defaulting to empty (⇒ disabled):

```go
	{Name: "WG_ROUTE_LIVENESS", Value: os.Getenv("WG_ROUTE_LIVENESS")},
	{Name: "WG_ROUTE_FAILURE_COUNT", Value: os.Getenv("WG_ROUTE_FAILURE_COUNT")},
	{Name: "WG_ROUTE_CHECK_INTERVAL", Value: os.Getenv("WG_ROUTE_CHECK_INTERVAL")},
	{Name: "WG_ROUTE_PROBE_INTERVAL", Value: os.Getenv("WG_ROUTE_PROBE_INTERVAL")},
```

> Rationale: keeps it a deployment-template-only change (no CRD/spec field). Per-`Wireguard`-CR control would add a spec field + reconcile plumbing — deferred (see spec "Out of scope").

- [ ] **Step 4: Run tests + build**

Run: `go test ./internal/resources/... && go build ./...`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/resources/deployment.go internal/resources/deployment_test.go
git commit -m "feat(operator): surface WG_ROUTE_* env on the agent container (deployment-template passthrough)"
```

---

### Task 12: Full-suite gate + lint + open PR

**Files:** none (CI/PR).

- [ ] **Step 1: Run the full suite + vet + lint**

Run: `go build ./... && go test ./... && go vet ./... && pre-commit run --all-files`
Expected: all green (the repo's pre-commit includes golangci-lint).

- [ ] **Step 2: Manual smoke (disabled = no-op)**

Confirm with `WG_ROUTE_LIVENESS` unset the agent behaves exactly as `noden/main` (no watcher goroutine; `wg.Liveness` nil). Build the agent image per the repo's image build and diff `wg show wg0` / `ip route` against current on a scratch peer set — expect identical.

- [ ] **Step 3: Push + PR**

```bash
git push -u origin feat/liveness-gated-routes
gh pr create --repo node-networks-au/wireguard-operator --base noden/main \
  --title "feat: liveness-gated route failover (disabled/passive/active)" \
  --body "Implements docs/superpowers/specs/2026-06-05-liveness-gated-route-failover-design.md. Off by default (WG_ROUTE_LIVENESS=disabled ⇒ byte-identical)."
```

---

## Downstream (separate, containers repo — NOT this PR)

Once the operator image ships with this feature, enable it for **optimised** in the
`containers` repo (own PR/branch, not the optimised customer branch unless intended):
1. `clusters/noden/tenants/optimised/manifests.yaml`: add the deferred routes
   (`site-dc2 → 10.254.2.0/24`, `oob-dc1 → 172.31.111.0/24`, `oob-dc2 → 172.31.112.0/24`).
2. Re-run `scripts/gen-policyroutes.py` (static superset steering) + parity gate.
3. Set the agent env (`WG_ROUTE_LIVENESS=passive` first, then `active`) via the
   operator deployment / pinned image, validate failover (stop DC2 → `.2.x`
   reverts to DC1 within `N × probe`; restart → re-attaches ≤ check interval).

---

## Self-Review

- **Spec coverage:** modes (T1,T9), gating both layers keeping /32 (T2,T3,T4), passive signal incl. 4 scenarios + handshake-progress (T6), watcher edge-triggered Sync (T7), active probe + N-unanswered + revive (T8), per-peer keepalive window (T6 `downWindow`/`setKeepalive`, T9 `PeerInfos`), config knobs incl. renamed `WG_ROUTE_CHECK_INTERVAL` + `WG_ROUTE_PROBE_INTERVAL=15s` (T9), default-disabled no-op + Disabled-peer invariant (T2/T3 keep the `Disabled` guard first; T9 nil controller), observability (T10), non-CRD delivery (T11), separability precondition (verified in spec; relied on by T2). BFD/BGP explicitly out of scope — no task. ✔
- **Placeholder scan:** the only adapt-to-repo notes are T11's deployment-builder call and main.go ctx-ordering — both are explicit instructions, not silent TODOs; all code steps carry real code.
- **Type consistency:** `LivenessSource.IsLive(string) bool`, `observer` (IsLive+observe), `peerStat{PublicKey,LastHandshakeTime,ReceiveBytes}`, `deviceReader.readPeers`, `passiveLiveness`/`activeLiveness` both implement `observer`, `LivenessController{source,reader,apply,checkInterval,lastUp,setGauge}`, `Config{Mode,FailureCount,CheckInterval,ProbeInterval}`, `peerInfo{PublicKey,Keepalive,Address}` — consistent across tasks. `BuildWgQuickConfig(state,port,src)`, `desiredKernelRoutes(peers,src)`, `peerAllowedIPs(peer,src)`, `syncPeerRoutes(iface,state,src,logger)` updated consistently and call sites fixed in the same task.
