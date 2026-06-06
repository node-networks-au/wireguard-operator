# Noden Fork of wireguard-operator

This fork tracks `github.com/nccloud/wireguard-operator` with additional features required
for the Noden Networks managed-services platform. Our changes are intended to be
upstream-compatible: each feature lives on a `feature/<topic>` branch off `nccloud:main`
and is submitted as a focused PR when stable.

## Branch model

| Branch | Purpose | Push direction |
|--------|---------|----------------|
| `main` | Mirror of `nccloud/wireguard-operator:main` | Synced periodically; no local commits |
| `noden/main` | Integration branch — all features stacked, this is what CI builds | All feature work lands here first |
| `feature/<topic>` | Per-feature branch cherry-picked from `noden/main` off upstream `main` | Submitted as upstream PR |

## Image tags

CI publishes to GHCR on every push to `noden/main`:
- `ghcr.io/node-networks-au/wireguard-operator:<sha>` — immutable, use this in production
- `ghcr.io/node-networks-au/wireguard-operator:noden-vX.Y.Z` — semver-noden release tag
- `ghcr.io/node-networks-au/wireguard-operator:noden-noden-main` — branch tip (development only)

Agent images at `ghcr.io/node-networks-au/wireguard-operator/agent:<same-tags>`.

## Releasing a noden-vX.Y.Z tag

```bash
git checkout noden/main
git pull
git tag -a noden-v2.11.0-noden.1 -m "release: noden-v2.11.0-noden.1"
git push origin noden-v2.11.0-noden.1
```

Wait for CI to publish the tagged image, then update
`node-networks-au/containers/clusters/node-networks-managed/configs/platform/wireguard-operator.yaml`
image reference and commit.

## Upstream sync

When `nccloud/wireguard-operator` cuts a new minor:

```bash
git fetch upstream --tags
git checkout main
git reset --hard upstream/main
git push origin main --force-with-lease

git checkout -b noden/rebase-vX.Y.Z noden/main
git rebase --onto upstream/vX.Y.Z $(git merge-base noden/main main) noden/main
# resolve conflicts; rerun tests
git push origin noden/rebase-vX.Y.Z

# After validation, fast-forward noden/main
git checkout noden/main
git reset --hard noden/rebase-vX.Y.Z
git push origin noden/main --force-with-lease
```

## Submitting an upstream PR

1. Branch off `upstream/main`: `git checkout -b feature/<topic> upstream/main`
2. Cherry-pick the relevant commit(s) from `noden/main`, oldest first: `git cherry-pick <sha> [<sha> ...]`
3. Push to `origin` and open the PR at `nccloud/wireguard-operator`.
4. When merged, rebase `noden/main` to drop the now-upstream commit(s).

## Upstream PR tracker

The fork is 20 commits ahead of `upstream/main`. They group into six upstream-able PRs plus a
fork-only set that stays here. Dependency / submission order: `1 → {2, 3, 4, 5} → 6`
(2 & 3 are independent of 1; 4 & 5 stack on 1; 6 stacks on 1 + 4 + 5).

All six branches are prepared locally (cherry-picked off `upstream/main`, compiled + tested), each
with a `PR_BODY.md` in its worktree. **Nothing has been pushed or opened upstream.**

| PR | Branch | Composition (commits incl. stacked base) |
|----|--------|------------------------------------------|
| 1  | `feature/wg-syncconf`                     | 2 |
| 2  | `feature/agent-listenport-deploystrategy` | 3 |
| 3  | `feature/external-port`                   | 1 |
| 4  | `feature/peer-persistent-keepalive`       | 2 (syncconf) + 1 |
| 5  | `feature/peer-routes`                     | 2 (syncconf) + 2 |
| 6  | `feature/liveness-gated-routes`           | 2 (syncconf) + 2 (routes) + 1 (keepalive) + 1 |

### Upstreaming (6 PRs)

- [ ] **PR 1 — `wg syncconf` config application** (foundational)
  - Commits: `cbf8242`, `7e2589b`
  - Replaces `wgctrl.Configure` with `wg syncconf` so peer `AllowedIPs` survive reconciles;
    syncconf temp file written under `/var/run/wireguard` (writable in the agent rootfs). No API change.
  - Production-observation window (~2 weeks) has elapsed (live since 2026-06-05). Ready to submit.
- [ ] **PR 2 — AgentListenPort + DeploymentStrategy** spec fields
  - Commits: `b612bf9`, `78cae1a`, `9c480b0`
  - Two `Wireguard` spec fields that shape the agent Deployment; `9c480b0` wires both into
    `wireguard-dep`, so they ship together.
- [ ] **PR 3 — ExternalPort** spec field
  - Commit: `7fb6577`
  - Overrides the advertised endpoint port in generated peer/client configs. Self-contained.
- [ ] **PR 4 — PersistentKeepalive on WireguardPeer**
  - Commits: `b2cce97`, `a8f8c58` — squashed on the branch into one client-side-only commit
  - Stacks on PR 1 (the keepalive line is emitted from `BuildWgQuickConfig`). `a8f8c58` drops the
    server-side emit (server is responder-only). Origin: cherry-pick from julianguinard — credit in
    the PR.
- [ ] **PR 5 — WireguardPeer Routes / RoutesV6** (config + kernel routes)
  - Commits: `428ef9e` (AllowedIPs), `7455f27` (kernel-route install via `vishvananda/netlink` v1.3.1)
  - Depends on PR 1. Open our own focused PR; reference the overlapping `PetzJohannes#1` — a
    sprawling, test-deleting branch with a different (server-level) design, but it establishes the
    netlink precedent (at v1.1.0), so our additive per-peer version is the cleaner candidate.
- [ ] **PR 6 — Liveness-gated route failover** (submit squashed)
  - Commits: `baeffe9`, `ba5f12d`, `b805382` — collapse into one squashed PR
  - New `liveness.go` subsystem, agent env wiring, metrics, and `routeLiveness` CRD fields
    (disabled/passive/active; per-peer cascade over instance/cluster default). Stacks on PR 1 + PR 4
    + PR 5 (gates the syncconf/kernel routes; sizes the passive window from `PersistentKeepalive`).
    Branch excludes the internal `docs/superpowers/` planning docs and swaps the AgentListenPort-PR-
    dependent env test for a self-contained one.

### Fork-only — not upstreaming (for now)

- External-peer `<name>-peer` Secret convention + key provenance (`347f8a7`, `3632a46`) —
  ESO-friendly Secret ownership; opinionated, kept as our own thing.
- PSK + client-config default route (`a9d15f0`) — sources the PSK from the `<name>-peer` convention
  above, so it is coupled to it; would need a `presharedKeyRef`-style decoupling before it could
  upstream independently.
- Fork infrastructure: `ci-noden` workflow (`2e03639`, `090808e`) and this `NODEN.md` (`ded906a`).
- `bc98760` pre-commit golangci-lint hook — optional upstream nicety if ever wanted.

Superseded: internal PR #1 (`feat/preshared-key`, `presharedKeyRef`/`publicKeyRef`) — closed;
re-implemented as the convention-based approach above.
