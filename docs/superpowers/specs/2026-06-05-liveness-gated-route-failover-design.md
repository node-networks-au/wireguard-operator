# Liveness-gated WireGuard route failover (agent-side) — design

**Date:** 2026-06-05
**Status:** Accepted (design)
**Repo:** `wireguard-operator` (fork) · branch `feat/liveness-gated-routes` off `noden/main`
**Scope:** agent-side only. **No** controller, CRD, or k8s-API changes.

## Goal

A peer's downstream `routes` are present in `wg0` **only while that peer is
reachable**; when it goes silent they are withdrawn so longest-prefix routing
**fails the traffic over to a broader live peer** automatically, and they are
re-installed when the peer recovers. This makes pre-provisioned / redundant peers
(e.g. a second DC tunnel) safe to declare up front: their routes don't blackhole
while the tunnel is down, and activate the moment it comes up.

Today routes are installed **statically** — declared in `WireguardPeer.spec.routes`
and applied on every reconcile regardless of whether the peer is up. This adds the
**liveness** dimension as a faithful **extension** of that existing path.

## Background — the existing static route path (what we extend)

The fork already implements the upstream route feature
(`nccloud/wireguard-operator#1`, "Phase G") on `noden/main`:

- **AllowedIPs:** `peerAllowedIPs(peer)` builds the `[Peer].AllowedIPs` CSV =
  `address/32` (+ `/128`) **+** `spec.Routes` (+ `spec.RoutesV6`); applied by
  `BuildWgQuickConfig` → `wg syncconf` (which **diffs** peers — removing a CIDR
  from a peer's CSV withdraws it).
- **Kernel routes:** `syncPeerRoutes` installs `desiredKernelRoutes(peers)` as
  netlink routes on `wg0` via `RouteReplace`, **and prunes** routes no longer
  desired via `RouteDel` (leaving the server `/32`/`/128` host routes alone).
- **Shared filter (the seam):** *both* `BuildWgQuickConfig`/`peerAllowedIPs` and
  `desiredKernelRoutes` already **skip `Disabled` / `PublicKey`-less peers** from
  routes. Liveness is one more clause in that same predicate.
- **Reconcile trigger:** `wg.Sync(state)` runs on (a) `state.json` change
  (fsnotify) and (b) **every `/health` probe** (kubelet readiness) — there is no
  dedicated ticker today.

Routing model (why both layers matter): a cluster pod's packet for a downstream
LAN is steered to the WG pod by kube-ovn policyRoutes; inside the pod a **kernel
route** (`<cidr> dev wg0`) delivers it to `wg0`, and WireGuard's **AllowedIPs**
crypto-routing picks the peer (longest-prefix). Failover therefore needs the
withdrawn CIDR gone from *both* the kernel route table and the peer's AllowedIPs —
which the existing `RouteDel` prune + `wg syncconf` diff already do.

## Approach — liveness as one more clause in the existing filter

Add a pluggable **`LivenessSource`** with `IsLive(peer) bool`, consulted by the
route filter. A **not-live peer is treated like a `Disabled` peer *for routes
only*** — with one critical difference:

- `Disabled` removes the **whole** peer from `wg0`.
- **Not-live removes only the peer's `routes`; the `/32`/`/128` base stays**, so
  the peer can still handshake and recover (removing the whole peer would make
  recovery impossible — chicken/egg).

Concretely:
- `peerAllowedIPs(peer, isLive)` — append `Spec.Routes`/`RoutesV6` **only if
  `isLive(peer)`**; base address always retained.
- `desiredKernelRoutes(peers, isLive)` — skip a peer's routes when `!isLive`
  (mirrors the `Disabled` skip).

**No new install/removal code.** A not-live peer's AllowedIPs shrink to its `/32`
→ the existing `wg syncconf` diff updates it; its CIDRs drop out of
`desiredKernelRoutes` → the existing `RouteDel` prune withdraws the kernel route.
Recovery is the exact reverse, automatically.

## Modes — `WG_ROUTE_LIVENESS=disabled|passive|active`

Selected by env (and exposed as the agent's optional liveness arg). The mode picks
the `LivenessSource` implementation:

- **`disabled`** (default) — gating off; `IsLive ≡ true`. Behavior is
  **byte-identical** to today. Safe upgrade; opt-in per deployment.
- **`passive`** — liveness from signals already in the `wgctrl` device read; **no
  added traffic**, server stays responder-only. Recovery of a stuck/keepalive-less
  peer relies on the peer initiating (see preconditions).
- **`active`** — `passive` **plus** a `/32` handshake probe (below) that
  accelerates down-detection *and* actively revives stuck/keepalive-less peers.

`LivenessSource` is an interface so the modes are independently testable and a peer
can be evaluated without root/netlink.

## Liveness signal

The watcher reads each peer's `LastHandshakeTime` **and `ReceiveBytes`** from one
long-lived `wgctrl.Client`. Define **last-progress** = the most recent of
{a `ReceiveBytes` increase observed by the watcher, `LastHandshakeTime`}.

- **`passive`:** a peer is **live** while `age(last-progress) ≤ downWindow`, where
  `downWindow = 3 × spec.PersistentKeepalive` for keepalive peers (≈ **75 s** for
  our 25 s peers — tolerates 2 lost keepalives), falling back to
  `REJECT_AFTER_TIME = 180 s` for peers with no keepalive configured.
  Rationale: WireGuard handshakes are **traffic-driven** and only refresh
  `LastHandshakeTime` ~every `REKEY_AFTER_TIME` (120 s); `ReceiveBytes` advances on
  **every** inbound packet incl. each keepalive (~25 s), so it detects silence
  ~2.4× sooner with zero added traffic. `age > 180 s` is WireGuard's own dead-key
  point (`REJECT_AFTER_TIME`) — the keepalive-less backstop.
- **`active`:** as passive, but when last-progress stalls past `2 × keepalive`
  (~50 s) the agent sends a packet to the peer's **`/32`** (routes via the retained
  base) to **force a handshake**; if no inbound progress after ~3 × `REKEY_TIMEOUT`
  (~15 s) the peer is **down** (≈ 50–65 s, with confirmation). The same probe is
  used to revive a not-live peer with a known endpoint, closing the
  keepalive-less recovery deadlock.

A fresh handshake or any inbound progress → **live on the next tick** (≤ 1 s).
There is **no separate anti-flap margin** — a single threshold; healthy keepalive
peers never approach it.

## Watcher loop

- A dedicated goroutine ticks every **1 s** (measured cost: ~0.5 ms `wgctrl` read
  even at 38 peers — negligible). It refreshes per-peer liveness.
- **Edge-triggered:** only when a peer's live↔not-live state **transitions** does
  it call the existing **`wg.Sync(latestState)`** (idempotent — `syncconf` diff +
  `RouteReplace`/`RouteDel`). Quiet ticks do no writes.
- A **mutex-guarded "latest state" holder** is updated by `onFileChange` (fsnotify)
  and read by the watcher, so config changes and liveness changes compose through
  the one `Sync` path. `Sync` always computes routes as a pure function of
  `(latestState, liveness)`.

## Failover semantics (worked: optimised DC1/DC2)

- DC1 (`10.254.0.0/16` + `192.168.0.0/16`, live) and DC2 (`10.254.2.0/24`).
- DC2 goes silent → after `downWindow` it's **not-live** → its `/24` drops from
  DC2's AllowedIPs *and* the kernel route is pruned → packets for `10.254.2.x`
  match DC1's `/16` (kernel route → `wg0`, AllowedIPs longest-prefix → DC1).
- DC2 recovers → next transition re-installs the `/24` on DC2 → longest-prefix
  moves `.2.x` back to DC2.
- OOB `/24`s (no broader peer) are simply absent while down (correct — reachable
  only via their own tunnel).

## Edge-case behavior (the four scenarios)

| Scenario | `passive` | `active` |
|---|---|---|
| **Never active** (never handshaked) | not-live from t=0; routes never installed; only `/32` in `wg0`. No blackhole. | same |
| **Was active, then stops** (dead/off) | not-live ~`downWindow` after last progress (~75 s keepalive / 180 s not) → failover. | ~50–65 s via probe confirmation. |
| **Active, no keepalive** | live only if real traffic < `downWindow`; if idle between polls (LibreNMS = 300 s > 180 s) → false-down, and server-originated polls can't revive it (route withdrawn) → can stick down. | probe revives it whenever reachable → no stick. |
| **Was active, never keepalived** | false-down ~180 s after last progress; stuck until peer initiates. | probe revives → no stick. |

The fragile cases exist **only for keepalive-less peers** — see preconditions.

## Preconditions

1. **(a) Keepalive is the load-bearing assumption.** Handshake/`ReceiveBytes`
   liveness ≡ reachability *only if the peer keepalives* (or passes traffic
   < `downWindow`). Our managed client configs already set `PersistentKeepalive =
   25 s`, so compliant peers behave correctly in `passive`. Keepalive-less peers
   need `active` to avoid false-downs/stick. **Documented requirement.**
2. **(b) Route separability.** Gating keeps the `/32` while dropping routes, so
   downstream CIDRs **must** arrive via the structured `spec.routes` field (which
   `peerAllowedIPs` appends to the base), **not** baked into the freeform
   `spec.allowedIPs` CSV. **Plan step 0: verify the KRO wireguard RGD renders
   `WireguardPeer.spec.routes` (structured), not an inline `allowedIPs` CSV.**

## Observability

- Gauge `wireguard_peer_routes_active{peer,iface}` (0/1) and
  `wireguard_peer_last_progress_age_seconds` (for alerting/debug).
- **One log line per transition only** — `peer <name> up → install [cidrs]` /
  `down → withdraw [cidrs] (fallback)`. No per-tick logging.

## Testing

- `LivenessSource` and the `gate(peer, isLive)` route filter are pure/injectable —
  table-driven unit tests feed synthetic `LastHandshakeTime`/`ReceiveBytes`
  (the kernel can't be made to fake handshakes), covering all four scenarios per
  mode, hysteresis-free transitions, `/32` retention, and never-handshaked peers.
- Existing `BuildWgQuickConfig`/`desiredKernelRoutes` tests extended with an
  `isLive` arg (default all-live → existing assertions unchanged).
- Prod validation on **optimised**: with `active`, bring DC2 up → confirm
  `10.254.2.0/24` moves to DC2; stop DC2 → confirm fallback to DC1 within
  `downWindow`; restart → confirm re-attach.

## Rollout

1. Operator: implement the modes behind `WG_ROUTE_LIVENESS` (default `disabled`).
2. Manifest (optimised): declare all intended routes (`site-dc2`, `oob-dc1/2`),
   re-run `gen-policyroutes` (static superset steering), set the agent's liveness
   arg — `passive` first, then `active`.
3. Validate on optimised → enable fleet-wide as desired. Gating is benign where no
   fallback peer exists (a down peer's route was already a blackhole), so
   enablement is low-risk; the flag gives staged rollout + instant revert.

## Out of scope

- **BFD / BGP-over-tunnel** (sub-second, learned-route failover) — the correct
  long-term answer for capable multi-DC site routers, but requires per-peer
  customer config + a routing daemon in the WG datapath. Explicitly deferred; the
  `LivenessSource` interface does not preclude a future signal-only integration.
- Controller/CRD `Status` liveness; multi-WG-pod / HA coordination.
- IPv6 failover is covered by the same logic (`RoutesV6`) but validated after IPv4.
