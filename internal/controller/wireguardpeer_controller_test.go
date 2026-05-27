package controllers

import (
	"context"
	"time"

	"github.com/nccloud/wireguard-operator/api/v1alpha1"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	wgtypes "golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var _ = Describe("wireguardpeer controller — existing-Secret adoption", func() {
	const (
		wgName      = "vpn-adopt"
		wgNamespace = "default"
		Timeout     = time.Second * 10
		Interval    = time.Millisecond * 250
	)

	BeforeEach(func() {
		var listOpts []client.ListOption

		wgList := &v1alpha1.WireguardList{}
		Expect(k8sClient.List(context.Background(), wgList, listOpts...)).Should(Succeed())
		for _, wg := range wgList.Items {
			Expect(k8sClient.Delete(context.Background(), &wg)).Should(Succeed())
		}
		peerList := &v1alpha1.WireguardPeerList{}
		Expect(k8sClient.List(context.Background(), peerList, listOpts...)).Should(Succeed())
		for _, peer := range peerList.Items {
			Expect(k8sClient.Delete(context.Background(), &peer)).Should(Succeed())
		}
		svcList := &corev1.ServiceList{}
		Expect(k8sClient.List(context.Background(), svcList, listOpts...)).Should(Succeed())
		for _, svc := range svcList.Items {
			Expect(k8sClient.Delete(context.Background(), &svc)).Should(Succeed())
		}
		secretList := &corev1.SecretList{}
		Expect(k8sClient.List(context.Background(), secretList, listOpts...)).Should(Succeed())
		for _, secret := range secretList.Items {
			Expect(k8sClient.Delete(context.Background(), &secret)).Should(Succeed())
		}
		cList := &corev1.ConfigMapList{}
		Expect(k8sClient.List(context.Background(), cList, listOpts...)).Should(Succeed())
		for _, c := range cList.Items {
			Expect(k8sClient.Delete(context.Background(), &c)).Should(Succeed())
		}

		// kube-dns service for the WG controller
		dnsService := &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "kube-dns",
				Namespace: "kube-system",
			},
			Spec: corev1.ServiceSpec{
				ClusterIP: "10.0.0.42",
				Ports:     []corev1.ServicePort{{Name: "dns", Protocol: corev1.ProtocolUDP, Port: 53}},
			},
		}
		Expect(k8sClient.Create(context.Background(), dnsService)).Should(Succeed())
	})

	It("adopts a pre-existing <peer>-peer Secret instead of erroring", func() {
		// Pre-create the wireguard server CR (so the peer controller has its reference)
		wg := &v1alpha1.Wireguard{
			ObjectMeta: metav1.ObjectMeta{
				Name:      wgName,
				Namespace: wgNamespace,
			},
			Spec: v1alpha1.WireguardSpec{
				ServiceType: corev1.ServiceTypeClusterIP,
				Address:     "10.0.0.10",
			},
		}
		Expect(k8sClient.Create(context.Background(), wg)).Should(Succeed())

		// Pre-create the <peer>-peer Secret with a known keypair (simulating
		// a 1Password-clone or an operator that pre-clones across tenants).
		peerName := "adopt-peer-1"
		knownPriv, err := wgtypes.GeneratePrivateKey()
		Expect(err).ToNot(HaveOccurred())
		expectedPub := knownPriv.PublicKey().String()
		expectedPriv := knownPriv.String()

		Expect(k8sClient.Create(context.Background(), &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      peerName + "-peer",
				Namespace: wgNamespace,
			},
			Data: map[string][]byte{
				"privateKey": []byte(expectedPriv),
				"publicKey":  []byte(expectedPub),
			},
		})).Should(Succeed())

		// Create the WireguardPeer WITHOUT publicKey or privateKeyRef set —
		// this is the path KRO renders from spec.
		peer := &v1alpha1.WireguardPeer{
			ObjectMeta: metav1.ObjectMeta{
				Name:      peerName,
				Namespace: wgNamespace,
			},
			Spec: v1alpha1.WireguardPeerSpec{
				WireguardRef: wgName,
			},
		}
		Expect(k8sClient.Create(context.Background(), peer)).Should(Succeed())

		peerKey := types.NamespacedName{Name: peerName, Namespace: wgNamespace}

		// The reconciler must adopt the existing Secret and populate
		// spec.publicKey + spec.privateKeyRef on the CR.
		Eventually(func(g Gomega) {
			got := &v1alpha1.WireguardPeer{}
			g.Expect(k8sClient.Get(context.Background(), peerKey, got)).To(Succeed())
			g.Expect(got.Spec.PublicKey).To(Equal(expectedPub))
			g.Expect(got.Spec.PrivateKey.SecretKeyRef.Name).To(Equal(peerName + "-peer"))
			g.Expect(got.Spec.PrivateKey.SecretKeyRef.Key).To(Equal("privateKey"))
		}, Timeout, Interval).Should(Succeed())

		// The Secret data MUST be unchanged (operator must not overwrite
		// a pre-existing key).
		s := &corev1.Secret{}
		Expect(k8sClient.Get(context.Background(),
			types.NamespacedName{Name: peerName + "-peer", Namespace: wgNamespace}, s)).To(Succeed())
		Expect(string(s.Data["privateKey"])).To(Equal(expectedPriv))
		Expect(string(s.Data["publicKey"])).To(Equal(expectedPub))
	})

	It("falls back to generating a fresh keypair when no <peer>-peer Secret exists", func() {
		// Pre-create the wireguard server CR.
		wg := &v1alpha1.Wireguard{
			ObjectMeta: metav1.ObjectMeta{
				Name:      wgName,
				Namespace: wgNamespace,
			},
			Spec: v1alpha1.WireguardSpec{
				ServiceType: corev1.ServiceTypeClusterIP,
				Address:     "10.0.0.10",
			},
		}
		Expect(k8sClient.Create(context.Background(), wg)).Should(Succeed())

		// Create the WireguardPeer with NO pre-existing Secret — operator
		// must generate a fresh keypair (the existing fresh-path behavior).
		peerName := "fresh-peer-1"
		peer := &v1alpha1.WireguardPeer{
			ObjectMeta: metav1.ObjectMeta{
				Name:      peerName,
				Namespace: wgNamespace,
			},
			Spec: v1alpha1.WireguardPeerSpec{
				WireguardRef: wgName,
			},
		}
		Expect(k8sClient.Create(context.Background(), peer)).Should(Succeed())

		peerKey := types.NamespacedName{Name: peerName, Namespace: wgNamespace}
		secretKey := types.NamespacedName{Name: peerName + "-peer", Namespace: wgNamespace}

		// Operator should create the Secret and populate the CR.
		Eventually(func(g Gomega) {
			s := &corev1.Secret{}
			g.Expect(k8sClient.Get(context.Background(), secretKey, s)).To(Succeed())
			g.Expect(s.Data["privateKey"]).ToNot(BeEmpty())
			g.Expect(s.Data["publicKey"]).ToNot(BeEmpty())
		}, Timeout, Interval).Should(Succeed())

		Eventually(func(g Gomega) {
			got := &v1alpha1.WireguardPeer{}
			g.Expect(k8sClient.Get(context.Background(), peerKey, got)).To(Succeed())
			g.Expect(got.Spec.PublicKey).ToNot(BeEmpty())
			g.Expect(got.Spec.PrivateKey.SecretKeyRef.Name).To(Equal(peerName + "-peer"))
			g.Expect(got.Spec.PrivateKey.SecretKeyRef.Key).To(Equal("privateKey"))

			// Derived pubkey must match Secret data
			s := &corev1.Secret{}
			g.Expect(k8sClient.Get(context.Background(), secretKey, s)).To(Succeed())
			parsed, perr := wgtypes.ParseKey(string(s.Data["privateKey"]))
			g.Expect(perr).ToNot(HaveOccurred())
			g.Expect(got.Spec.PublicKey).To(Equal(parsed.PublicKey().String()))
		}, Timeout, Interval).Should(Succeed())
	})
})
