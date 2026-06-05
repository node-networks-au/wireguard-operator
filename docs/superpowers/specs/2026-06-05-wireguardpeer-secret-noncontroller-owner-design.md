# WireguardPeer generated Secret: non-controller owner reference (scope B)

Date: 2026-06-05
Status: Approved (design)
Scope: `wireguard-operator` (noden fork) — `internal/controller/wireguardpeer_controller.go` (`secretForPeer`).
Follows: 2026-06-05-wireguardpeer-key-provenance-design.md (scope A).

## Problem

When the `<peer>-peer` Secret does not exist at first reconcile, the operator mints a
keypair and **creates the Secret with itself as the controller owner**
(`ctrl.SetControllerReference`). external-secrets (ESO, v2.5.0) with
`creationPolicy: Owner` then cannot claim controllership and fails with
`SecretSyncedError: failed to take ownership of target secret`, so it never overwrites the
Secret with the real key. The operator-minted key wins permanently — the wavesquared
`site-nxt-b1` incident (2026-06-05).

ESO's `applyOwnership` uses `metav1.GetControllerOf(target)`: it only refuses a Secret whose
**controller** owner is a *different* resource. Our Secret's controller owner is the
WireguardPeer, which is exactly the block.

## Goal

Stop the operator-generated Secret from blocking ESO ownership, so provisioning is
order-independent: whoever creates the Secret first, the system converges on the external
(ESO/1P) key when one exists, and on the generated key otherwise.

## Design

`secretForPeer` sets a **non-controller** owner reference instead of a controller one:

```go
// before
_ = ctrl.SetControllerReference(m, dep, r.Scheme)
// after
_ = ctrl.SetOwnerReference(m, dep, r.Scheme)
```

Effects:
- The generated Secret carries a plain owner reference to the WireguardPeer (no
  `controller: true`, no `blockOwnerDeletion`). `GetControllerOf` returns nil, so ESO claims
  controllership and overwrites with the real key; scope A's Secret→peer watch then yields the
  server to it. Operator-first and ESO-first orderings both converge.
- **Garbage collection is preserved** — Kubernetes GC cascades on any owner reference, not only
  controller ones, so deleting the peer still deletes the Secret (greenfield case).
- **Scope A is unaffected** — `secretOwnedByPeer` matches on Kind+Name and ignores the
  controller flag, so a generated key is still stamped `origin=generated`.
- Bonus: a later greenfield→ESO migration self-heals (ESO adopts the non-controller Secret,
  operator yields) without manual intervention.

## Scope boundary (deliberate)

- Only **newly created** Secrets are affected. Existing operator-controller-owned Secrets (the
  current superopti / wavesquared-user backlog) are not rewritten and still need the manual
  delete+resync remediation.
- The operator does **not** auto-relinquish controllership on existing Secrets. Those are legacy
  (no provenance annotation), so letting ESO overwrite them would trip scope A's fail-closed →
  error churn — worse than the current stable-but-wrong state.

## Testing (envtest; `make test`)

1. New: a generated `<peer>-peer` Secret has a non-controller owner reference to the peer
   (`metav1.GetControllerOf` returns nil) while the peer is still present in `ownerReferences`
   (GC intact).
2. Regression: scope-A specs stay green (generate still stamps `origin=generated`;
   `secretOwnedByPeer` still detects ownership).

ESO adopting the non-controller Secret is not unit-testable in envtest (no ESO present); it
rests on the verified ESO `applyOwnership`/`GetControllerOf` semantics and is an integration
assumption to confirm on the dev cluster before release.

## Rollout

- No CRD/API change; no manifest change. Behavior change only for newly minted Secrets.
- Existing backlog is unchanged by this PR; remediate manually as before.
