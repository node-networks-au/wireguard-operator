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
	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"
)

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

		var privateKey, publicKey string

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
			privateKey = strings.TrimSpace(string(existing.Data["privateKey"]))
			storedPub := strings.TrimSpace(string(existing.Data["publicKey"]))
			switch {
			case privateKey != "":
				// We hold the private key: the public key is its curve25519
				// derivation. If the Secret ALSO carries a publicKey, it must
				// match — fail closed on a mismatched/swapped pair.
				parsed, parseErr := wgtypes.ParseKey(privateKey)
				if parseErr != nil {
					log.Error(parseErr, "Failed to parse existing privateKey", "secret.Namespace", secretName.Namespace, "secret.Name", secretName.Name)
					return ctrl.Result{}, fmt.Errorf("parse existing privateKey for %s: %w", secretName.Name, parseErr)
				}
				publicKey = parsed.PublicKey().String()
				if storedPub != "" && storedPub != publicKey {
					msg := fmt.Sprintf("secret %s: stored publicKey %s does not match the key %s derived from privateKey; refusing to configure peer", secretName.Name, storedPub, publicKey)
					log.Error(fmt.Errorf("peer public/private key mismatch"), msg)
					_ = r.updateStatus(ctx, newPeer, v1alpha1.Error, msg)
					return ctrl.Result{}, fmt.Errorf("%s", msg)
				}
				log.Info("Adopting existing peer secret (private key)", "secret.Namespace", secretName.Namespace, "secret.Name", secretName.Name)
			case storedPub != "":
				// External / public-key-only peer: the customer holds the private
				// key, we only have the public key (e.g. carried from a legacy
				// stack and supplied via 1Password). Validate it parses, adopt it,
				// and leave privateKeyRef unset.
				if _, parseErr := wgtypes.ParseKey(storedPub); parseErr != nil {
					msg := fmt.Sprintf("secret %s: stored publicKey is not a valid WireGuard key: %v", secretName.Name, parseErr)
					log.Error(parseErr, msg)
					_ = r.updateStatus(ctx, newPeer, v1alpha1.Error, msg)
					return ctrl.Result{}, fmt.Errorf("%s", msg)
				}
				publicKey = storedPub
				log.Info("Adopting existing peer secret (public key only / external)", "secret.Namespace", secretName.Namespace, "secret.Name", secretName.Name)
			default:
				// Secret exists but has no key material yet (e.g. an ExternalSecret
				// target mid-sync). Requeue until it is populated.
				log.Info("Peer secret present but has no key material yet; requeueing", "secret.Name", secretName.Name)
				return ctrl.Result{Requeue: true}, nil
			}
		case errors.IsNotFound(getErr):
			privateKey = key.String()
			publicKey = key.PublicKey().String()

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
		// Only point privateKeyRef at the Secret when we actually hold a private
		// key. External (public-key-only) peers leave it unset — there is no
		// private key to reference, and a downloadable client config can't (and
		// shouldn't) be generated for a key the customer already holds.
		if privateKey != "" {
			newPeer.Spec.PrivateKey = v1alpha1.PrivateKey{
				SecretKeyRef: corev1.SecretKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: secretName.Name}, Key: "privateKey"}}
		}
		if err := r.Patch(ctx, newPeer, patch); err != nil {
			log.Error(err, "Failed to patch peer with public key + secret ref", "secret.Namespace", secretName.Namespace, "secret.Name", secretName.Name)
			return ctrl.Result{}, fmt.Errorf("patch WireguardPeer with public key + secret ref: %w", err)
		}

		return ctrl.Result{Requeue: true}, nil

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

// SetupWithManager sets up the controller with the Manager.
func (r *WireguardPeerReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.WireguardPeer{}).
		Complete(r)
}
