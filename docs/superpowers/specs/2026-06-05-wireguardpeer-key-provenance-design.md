# WireguardPeer key provenance: generated keys yield, hard-set keys fail closed

Date: 2026-06-05
Status: Approved (design)
Scope: `wireguard-operator` (noden fork) — `internal/controller/wireguardpeer_controller.go`, plus a CR-derived metric.

## Problem

`WireguardPeerReconciler.Reconcile` populates `spec.PublicKey` exactly once and then
ignores the peer Secret forever. The key block is gated by `if peer.Spec.PublicKey == ""`
(internal/controller/wireguardpeer_controller.go:121); on every later reconcile the block
is skipped, so the Secret is never re-read.

When the `<peer>-peer` Secret does not yet exist at first reconcile, the operator
**generates a random keypair, creates the Secret itself (with a controller ownerReference),
and patches `spec.PublicKey`**. This is the failure seen in production (managed-wavesquared
`site-nxt-b1`, 2026-06-05): the per-peer Secret is meant to be supplied by external-secrets
(ESO) from 1Password, but the WireguardPeer CR reconciled *before* ESO synced. The operator
minted its own key, the **server** advertised that minted key, and the customer router —
holding the real 1P key — could never complete a handshake. Every device behind that peer
went unreachable with no error (per-peer `rx=0`, no "mismatch" log).

Two distinct defects sit behind this:
1. **(this spec, scope A)** Once a *generated* `spec.PublicKey` is set, it is treated as
   authoritative and never reconciled against the Secret, even after the real key lands.
2. **(scope B, NOT in this spec)** The operator creating the Secret with its own ownerReference
   is what makes ESO fail with `failed to take ownership`, so ESO never overwrites the Secret
   with the real key. Removing that ownership block is deliberately excluded here.

Because scope B is excluded, this change does not by itself prevent the incident; it makes a
generated key **reconcilable** (it will yield to an external Secret the moment that Secret's
key differs), adds the missing fail-closed guard for genuinely hard-set keys, and surfaces a
metric for legacy peers that predate provenance tracking.

## Goals

- A *generated* `spec.PublicKey` is not authoritative: if the peer Secret later yields a
  different key, the operator **re-adopts** the Secret's key (yield/self-heal).
- A *hard-set* `spec.PublicKey` (declared in a manifest, or previously adopted from an external
  Secret) that disagrees with the peer Secret is a real conflict: **fail closed** (error status,
  change nothing) rather than silently picking a side.
- Provenance is explicit and observable; legacy peers (provisioned before this change) are
  identifiable via a metric so they can be annotated out-of-band.

## Non-goals

- Removing the operator's Secret ownership / ESO `failed to take ownership` block (scope B).
- Auto-classifying or auto-annotating legacy peers (the operator cannot safely infer whether a
  consistent legacy key was generated or external).
- Following external Secret *rotations* for already-adopted keys: an adopted key whose Secret
  later changes **fails closed** (chosen behavior — surfaces the change).

## Design

### Provenance annotation

A single annotation records what the operator **did** to establish the key:

`vpn.wireguard-operator.io/key-origin` ∈ `{generated, external}`

Set **only when the operator performs a key action**:

| Action | When | Annotation |
|---|---|---|
| generate | `spec.PublicKey == ""` and no usable Secret → mint key, create Secret | `generated` |
| adopt | `spec.PublicKey == ""` and a usable Secret already exists | `external` |
| yield / re-adopt | `generated` key disagrees with the Secret → take the Secret's key | `external` (flips from `generated`) |

The operator does **not** stamp the annotation on routine, consistent reconciles. A peer the
operator never key-acts on therefore keeps **no annotation** — that absence is the legacy marker.

### Reconcile logic

Add a helper:

```
func (r *WireguardPeerReconciler) secretDerivedPubKey(ctx, peer) (pub string, present bool, err error)
```

Gets `<peer>-peer`; if found with a parseable `privateKey`, returns the derived public key and
`present=true`. `NotFound` → `("", false, nil)`. Parse error / other get error → propagate.

`Reconcile` (after the existing fetch + pending-status init) branches:

1. **First provisioning** — `peer.Spec.PublicKey == ""` (existing behavior, plus the annotation):
   - usable Secret present → adopt: `publicKey = secretPub`, stamp `key-origin=external`.
   - else → generate, create Secret, stamp `key-origin=generated`.
   - Patch `spec.PublicKey` + `spec.privateKeyRef` + the annotation. Requeue.

2. **Disagreement** — `present && secretPub != peer.Spec.PublicKey`:
   - `key-origin == generated` → **yield**: patch `spec.PublicKey = secretPub`, repoint
     `privateKeyRef` at `<peer>-peer`, set `key-origin=external`, log
     `"re-adopting external key over generated key"`. Requeue.
   - otherwise (`external`, or annotation **absent** = legacy/declared) → **fail closed**:
     `updateStatus(Error, "<peer> spec.publicKey <a> disagrees with peer secret-derived key <b>; refusing to change")`,
     return without modifying spec and without rendering.

3. **Consistent, or no usable Secret** → fall through to the existing downstream
   (`wireguardRef` lookup, duplicate-address check, ownerReference) unchanged. A manifest-declared
   pubkey with no Secret (a roaming client) is untouched.

Patches use `client.MergeFrom` as today (do not clobber other field managers — KRO owns labels/
annotations it set, status, etc.). The annotation write is additive.

### Edge cases

- `generated` marker present but Secret deleted → `present=false` → no disagreement → keep the
  current key (no churn).
- After a yield, the marker is `external`, so any *future* Secret change for that peer fails
  closed (the adopted-rotation = fail-closed decision).
- Idempotent: a `generated` key that already equals its Secret-derived key → no patch.
- A peer with `spec.PublicKey` declared and no Secret → renders normally, no annotation written.

### Legacy-backlog metric

A CR-derived gauge, emitted **controller-side** (the existing
`internal/agent/wireguard_metrics.go` collector reads live wg-device state keyed on pubkey and
has no access to CR annotations / `privateKeyRef`, so it is the wrong place):

`wireguard_peer_key_origin{namespace, peer, origin}` — value `1` per peer, `origin` derived as:

| Condition | `origin` |
|---|---|
| annotation `generated` | `generated` |
| annotation `external` | `external` |
| no annotation, `privateKeyRef` **empty** | `declared` (user-supplied pubkey only — not backlog) |
| no annotation, `privateKeyRef` **set** | `unknown` (legacy operator-managed — needs annotating) |

`origin="unknown"` is precisely the actionable legacy backlog; the `privateKeyRef` discriminator
keeps roaming/declared peers out of it. Ops alerts on `count(origin="unknown") > 0`, lists them,
and annotates each (`generated` vs `external`) out-of-band — the operator never guesses from mere
consistency. Implementation should emit via a dedicated collector registered with the
controller-runtime metrics registry that Lists `WireguardPeer`s on scrape (avoids stale series),
or an equivalent that has CR access; exact wiring is left to the plan.

## Testing (envtest suite, `internal/controller/wireguardpeer_controller_test.go`; `make test`)

1. Generated key, Secret's `privateKey` then changes → operator re-adopts (`spec.PublicKey`
   becomes the Secret key, `key-origin` flips to `external`). *(the bug)*
2. Declared `spec.PublicKey` + disagreeing Secret → `Error` status, spec unchanged. *(two hard-set)*
3. Adopted key (Secret pre-existed at create → `external`), Secret later rotates → `Error`.
   *(confirms adopted-rotation = fail closed)*
4. Generated key agreeing with its Secret → no change, no churn. *(idempotency)*
5. Declared pubkey, no Secret → renders normally. *(roaming client unaffected)*
6. First-time generate stamps `generated`; first-time adopt stamps `external`; yield flips
   `generated` → `external`.
7. Metric: legacy peer (no annotation, `privateKeyRef` set) → `origin="unknown"`; declared peer
   (no `privateKeyRef`) → `origin="declared"`; a consistent reconcile of a legacy peer leaves it
   unannotated (stays `unknown`).

## Rollout / compatibility

- Existing peers whose key equals their Secret are unaffected (they never hit the disagreement
  branch). They report `origin="unknown"` (operator-managed) or `origin="declared"` until annotated.
- This change makes a *manual* remediation simpler: after correcting ESO ownership so the Secret
  holds the real key, a `generated`-annotated peer re-adopts automatically — no need to delete the
  WireguardPeer. Legacy peers (no annotation) still require the existing delete-and-reprovision step.
- New annotation and metric only; no CRD schema change.
