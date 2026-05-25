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

1. Branch off `upstream/main`: `git checkout -b feature/listen-port upstream/main`
2. Cherry-pick the relevant single commit from `noden/main`: `git cherry-pick <sha>`
3. Push to `origin` and open the PR at `nccloud/wireguard-operator`.
4. When merged, rebase `noden/main` to drop the now-upstream commit.

## Open upstream PR status

- [ ] PR #N: AgentListenPort field — not yet submitted (held until cluster validation)
- [ ] PR #N: ExternalPort field — not yet submitted
- [ ] Contribution PR to PetzJohannes#1: WireguardPeer.Routes/RoutesV6 tests — pending (path 2: PR against author's fork branch)
- [ ] PR #N: PersistentKeepalive — not yet submitted (cherry-pick from julianguinard)
- [ ] PR #N: wg-syncconf replacement — not yet submitted (held until ~2 weeks production observation)
