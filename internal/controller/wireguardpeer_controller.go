/*
Copyright 2021.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controllers

import (
	"context"
	"fmt"
	"strings"

	"github.com/nccloud/wireguard-operator/api/v1alpha1"

	wgtypes "golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

const (
	// keyOriginAnnotation records how the operator established spec.PublicKey.
	// Its ABSENCE marks a peer provisioned before provenance tracking (legacy)
	// or a user-declared key — surfaced by the key-origin metric.
	keyOriginAnnotation = "vpn.wireguard-operator.io/key-origin"
	// keyOriginGenerated: the operator minted the keypair itself. Not
	// authoritative — yields to an external Secret that later disagrees.
	keyOriginGenerated = "generated"
	// keyOriginExternal: the key came from an external Secret (adopted, or
	// re-adopted from one). Hard-set — a later disagreement fails closed.
	keyOriginExternal = "external"
)

// setKeyOrigin stamps the provenance annotation on a peer (in memory).
func setKeyOrigin(peer *v1alpha1.WireguardPeer, origin string) {
	if peer.Annotations == nil {
		peer.Annotations = map[string]string{}
	}
	peer.Annotations[keyOriginAnnotation] = origin
}

// secretOwnedByPeer reports whether the Secret carries this peer as an owner —
// i.e. the operator created it (secretForPeer sets the controller ref).
// Externally-provided Secrets (e.g. external-secrets) are owned by something
// else, so this is a reliable "did the operator mint this key" signal even when
// a stale-cache reconcile re-enters provisioning and finds the Secret already
// present.
func secretOwnedByPeer(secret *corev1.Secret, peerName string) bool {
	for _, ref := range secret.OwnerReferences {
		if ref.Kind == "WireguardPeer" && ref.Name == peerName {
			return true
		}
	}
	return false
}

// WireguardPeerReconciler reconciles a WireguardPeer object

type WireguardPeerReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

func (r *WireguardPeerReconciler) updateStatus(ctx context.Context, peer *v1alpha1.WireguardPeer, status string, message string) error {
	newPeer := peer.DeepCopy()
	if newPeer.Status.Status != status || newPeer.Status.Message != message {
		newPeer.Status.Status = status
		newPeer.Status.Message = message

		if err := r.Status().Update(ctx, newPeer); err != nil {
			return err
		}
	}
	return nil
}

func (r *WireguardPeerReconciler) secretForPeer(m *v1alpha1.WireguardPeer, privateKey string, publicKey string) *corev1.Secret {
	ls := labelsForWireguard(m.Name)
	dep := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      m.Name + "-peer",
			Namespace: m.Namespace,
			Labels:    ls,
		},
		Data: map[string][]byte{"privateKey": []byte(privateKey), "publicKey": []byte(publicKey)},
	}
	// Set Nodered instance as the owner and controller
	_ = ctrl.SetControllerReference(m, dep, r.Scheme)

	return dep

}

// secretDerivedPubKey returns the public key derived from the <peer>-peer
// Secret's privateKey. present is false when no such Secret exists or it has no
// privateKey; genuine get/parse failures are returned as err.
func (r *WireguardPeerReconciler) secretDerivedPubKey(ctx context.Context, peer *v1alpha1.WireguardPeer) (pub string, present bool, err error) {
	secret := &corev1.Secret{}
	getErr := r.Get(ctx, types.NamespacedName{Name: peer.Name + "-peer", Namespace: peer.Namespace}, secret)
	switch {
	case errors.IsNotFound(getErr):
		return "", false, nil
	case getErr != nil:
		return "", false, fmt.Errorf("get peer secret %s-peer: %w", peer.Name, getErr)
	}
	priv := string(secret.Data["privateKey"])
	if priv == "" {
		return "", false, nil
	}
	parsed, parseErr := wgtypes.ParseKey(priv)
	if parseErr != nil {
		return "", false, fmt.Errorf("parse privateKey for %s-peer: %w", peer.Name, parseErr)
	}
	return parsed.PublicKey().String(), true, nil
}

//+kubebuilder:rbac:groups=vpn.wireguard-operator.io,resources=wireguardpeers,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=vpn.wireguard-operator.io,resources=wireguardpeers/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=vpn.wireguard-operator.io,resources=wireguardpeers/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the WireguardPeer object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.10.0/pkg/reconcile

func (r *WireguardPeerReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := ctrllog.FromContext(ctx)
	peer := &v1alpha1.WireguardPeer{}
	err := r.Get(ctx, req.NamespacedName, peer)
	if err != nil {
		if errors.IsNotFound(err) {
			// Request object not found, could have been deleted after reconcile request.
			// Owned objects are automatically garbage collected. For additional cleanup logic use finalizers.
			// Return and don't requeue
			log.Info("wireguard peer resource not found. Ignoring since object must be deleted")
			return ctrl.Result{}, nil
		}
		// Error reading the object - requeue the request.
		log.Error(err, "Failed to get wireguard peer")
		return ctrl.Result{}, err
	}

	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		log.Error(err, "Failed to generate private key")
		return ctrl.Result{}, err
	}

	newPeer := peer.DeepCopy()
	if newPeer.Status.Status == "" {
		err = r.updateStatus(ctx, newPeer, v1alpha1.Pending, "Waiting for wireguard peer to be created")

		if err != nil {
			return ctrl.Result{}, err
		}

		return ctrl.Result{Requeue: true}, nil
	}

	if peer.Spec.PublicKey == "" {
		secretName := types.NamespacedName{Name: peer.Name + "-peer", Namespace: peer.Namespace}

		var privateKey, publicKey, origin string

		// Try to adopt an existing <peer>-peer Secret first. This is the
		// path hit when ops pre-clone a peer keypair (e.g. for tenant
		// migrations or 1Password-backed key sharing): the Secret exists
		// before the WireguardPeer CR is reconciled. Without this, the
		// reconciler errored with `secrets "<peer>-peer" already exists`
		// at the r.Create call below and never populated
		// spec.publicKey/spec.privateKeyRef on the CR, so wg0 never got
		// the [Peer] block for this peer.
		existing := &corev1.Secret{}
		getErr := r.Get(ctx, secretName, existing)
		switch {
		case getErr == nil:
			privateKey = string(existing.Data["privateKey"])
			parsed, parseErr := wgtypes.ParseKey(privateKey)
			if parseErr != nil {
				log.Error(parseErr, "Failed to parse existing privateKey", "secret.Namespace", secretName.Namespace, "secret.Name", secretName.Name)
				return ctrl.Result{}, fmt.Errorf("parse existing privateKey for %s: %w", secretName.Name, parseErr)
			}
			publicKey = parsed.PublicKey().String()
			// A Secret the operator owns means we minted this key (a stale-cache
			// re-entry after generating); anything else is externally provided.
			if secretOwnedByPeer(existing, peer.Name) {
				origin = keyOriginGenerated
			} else {
				origin = keyOriginExternal
			}
			log.Info("Adopting existing peer secret", "secret.Namespace", secretName.Namespace, "secret.Name", secretName.Name)
		case errors.IsNotFound(getErr):
			privateKey = key.String()
			publicKey = key.PublicKey().String()
			origin = keyOriginGenerated

			secret := r.secretForPeer(peer, privateKey, publicKey)

			log.Info("Creating a new secret", "secret.Namespace", secret.Namespace, "secret.Name", secret.Name)
			if err := r.Create(ctx, secret); err != nil {
				log.Error(err, "Failed to create new secret", "secret.Namespace", secret.Namespace, "secret.Name", secret.Name)
				return ctrl.Result{}, err
			}
		default:
			log.Error(getErr, "Failed to get peer secret", "secret.Namespace", secretName.Namespace, "secret.Name", secretName.Name)
			return ctrl.Result{}, fmt.Errorf("get peer secret %s: %w", secretName.Name, getErr)
		}

		// Patch (not Update) the CR so we don't clobber field-manager
		// ownership of unrelated fields (labels, annotations, status, etc.
		// — KRO and other controllers may own those).
		patch := client.MergeFrom(peer.DeepCopy())
		newPeer.Spec.PublicKey = publicKey
		newPeer.Spec.PrivateKey = v1alpha1.PrivateKey{
			SecretKeyRef: corev1.SecretKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: secretName.Name}, Key: "privateKey"}}
		setKeyOrigin(newPeer, origin)
		if err := r.Patch(ctx, newPeer, patch); err != nil {
			log.Error(err, "Failed to patch peer with public key + secret ref", "secret.Namespace", secretName.Namespace, "secret.Name", secretName.Name)
			return ctrl.Result{}, fmt.Errorf("patch WireguardPeer with public key + secret ref: %w", err)
		}

		return ctrl.Result{Requeue: true}, nil

	}

	// spec.PublicKey is already set. Reconcile it against the peer Secret on
	// every pass. A *generated* key is not authoritative: if the Secret later
	// yields a different key (e.g. external-secrets finally synced the real 1P
	// key after losing the create race) re-adopt it. A *hard-set* key (declared
	// in a manifest, or previously adopted from an external Secret) that
	// disagrees is a genuine two-hard-set-values conflict — fail closed rather
	// than silently pick a side.
	secretPub, present, err := r.secretDerivedPubKey(ctx, peer)
	if err != nil {
		log.Error(err, "Failed to derive public key from peer secret")
		return ctrl.Result{}, err
	}
	if present && secretPub != peer.Spec.PublicKey {
		if peer.Annotations[keyOriginAnnotation] == keyOriginGenerated {
			log.Info("Re-adopting external key over previously generated key",
				"peer", peer.Name, "from", peer.Spec.PublicKey, "to", secretPub)
			patch := client.MergeFrom(peer.DeepCopy())
			newPeer.Spec.PublicKey = secretPub
			newPeer.Spec.PrivateKey = v1alpha1.PrivateKey{
				SecretKeyRef: corev1.SecretKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: peer.Name + "-peer"}, Key: "privateKey"}}
			setKeyOrigin(newPeer, keyOriginExternal)
			if err := r.Patch(ctx, newPeer, patch); err != nil {
				log.Error(err, "Failed to re-adopt external key")
				return ctrl.Result{}, fmt.Errorf("re-adopt external key for %s: %w", peer.Name, err)
			}
			return ctrl.Result{Requeue: true}, nil
		}
		msg := fmt.Sprintf("spec.publicKey %s disagrees with peer secret-derived key %s; refusing to change", peer.Spec.PublicKey, secretPub)
		log.Error(fmt.Errorf("public key conflict"), msg, "peer", peer.Name)
		if err := r.updateStatus(ctx, newPeer, v1alpha1.Error, msg); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	wireguard := &v1alpha1.Wireguard{}
	err = r.Get(ctx, types.NamespacedName{Name: newPeer.Spec.WireguardRef, Namespace: newPeer.Namespace}, wireguard)

	if err != nil {
		if errors.IsNotFound(err) {
			err = r.updateStatus(ctx, newPeer, v1alpha1.Error, fmt.Sprintf("Waiting for wireguard resource '%s' to be created", newPeer.Spec.WireguardRef))

			if err != nil {
				return ctrl.Result{}, err
			}

			return ctrl.Result{}, nil
		}

		log.Error(err, "Failed to get wireguard")

		return ctrl.Result{}, err

	}

	if wireguard.Status.Status != v1alpha1.Ready {
		log.Info("Waiting for wireguard to be ready")

		err = r.updateStatus(ctx, newPeer, v1alpha1.Error, fmt.Sprintf("Waiting for %s to be ready", wireguard.Name))

		if err != nil {
			return ctrl.Result{}, err
		}

		return ctrl.Result{}, nil
	}

	if msg, err := r.checkDuplicateAddress(ctx, req.Namespace, newPeer); err != nil {
		return ctrl.Result{}, err
	} else if msg != "" {
		log.Error(fmt.Errorf("duplicate peer address"), msg)
		if err := r.updateStatus(ctx, newPeer, v1alpha1.Error, msg); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	wireguardSecret := &corev1.Secret{}
	_ = r.Get(ctx, types.NamespacedName{Name: newPeer.Spec.WireguardRef, Namespace: newPeer.Namespace}, wireguardSecret)

	if len(newPeer.OwnerReferences) == 0 {
		log.Info("Waiting for owner reference to be set " + wireguard.Name + " " + newPeer.Name)
		if err := ctrl.SetControllerReference(wireguard, newPeer, r.Scheme); err != nil {
			log.Error(err, "Failed to set controller reference")
			return ctrl.Result{}, err
		}

		if err := r.Update(ctx, newPeer); err != nil {
			log.Error(err, "Failed to update peer with controller reference")
			return ctrl.Result{}, err
		}

		return ctrl.Result{Requeue: true}, nil
	}

	// No longer wait for a config in status; peer configs are stored in a Secret

	return ctrl.Result{}, nil
}

// checkDuplicateAddress checks whether the peer's address or addressV6 is already
// used by another peer on the same wireguardRef. Returns a non-empty message
// describing the conflict, or "" if no duplicate is found.
func (r *WireguardPeerReconciler) checkDuplicateAddress(ctx context.Context, namespace string, peer *v1alpha1.WireguardPeer) (string, error) {
	if peer.Spec.Address == "" && peer.Spec.AddressV6 == "" {
		return "", nil
	}

	allPeers := &v1alpha1.WireguardPeerList{}
	if err := r.List(ctx, allPeers, client.InNamespace(namespace)); err != nil {
		return "", err
	}
	for _, other := range allPeers.Items {
		if other.Name == peer.Name || other.Spec.WireguardRef != peer.Spec.WireguardRef {
			continue
		}
		if peer.Spec.Address != "" && other.Spec.Address == peer.Spec.Address {
			return fmt.Sprintf("Duplicate address %s: already used by peer %s", peer.Spec.Address, other.Name), nil
		}
		if peer.Spec.AddressV6 != "" && other.Spec.AddressV6 == peer.Spec.AddressV6 {
			return fmt.Sprintf("Duplicate IPv6 address %s: already used by peer %s", peer.Spec.AddressV6, other.Name), nil
		}
	}
	return "", nil
}

// peerForSecret maps a <peer>-peer Secret back to its WireguardPeer so that an
// external change to the key material (e.g. external-secrets syncing the real
// key) re-triggers reconciliation and the provenance check.
func (r *WireguardPeerReconciler) peerForSecret(_ context.Context, obj client.Object) []reconcile.Request {
	const suffix = "-peer"
	name := obj.GetName()
	if !strings.HasSuffix(name, suffix) || name == suffix {
		return nil
	}
	return []reconcile.Request{{NamespacedName: types.NamespacedName{
		Name:      strings.TrimSuffix(name, suffix),
		Namespace: obj.GetNamespace(),
	}}}
}

// SetupWithManager sets up the controller with the Manager.
func (r *WireguardPeerReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if err := RegisterKeyOriginCollector(mgr.GetClient()); err != nil {
		return err
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.WireguardPeer{}).
		Watches(&corev1.Secret{}, handler.EnqueueRequestsFromMapFunc(r.peerForSecret)).
		Complete(r)
}
