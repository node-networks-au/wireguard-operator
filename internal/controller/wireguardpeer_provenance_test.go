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
)

// Annotation literal kept independent of the production const so the test
// pins the on-wire contract, not the implementation symbol.
const keyOriginAnno = "vpn.wireguard-operator.io/key-origin"

var _ = Describe("wireguardpeer controller — key provenance", func() {
	const (
		wgNamespace = "default"
		Timeout     = time.Second * 10
		Interval    = time.Millisecond * 250
	)
	ctx := context.Background()

	BeforeEach(func() {
		wgList := &v1alpha1.WireguardList{}
		Expect(k8sClient.List(ctx, wgList)).Should(Succeed())
		for i := range wgList.Items {
			Expect(k8sClient.Delete(ctx, &wgList.Items[i])).Should(Succeed())
		}
		peerList := &v1alpha1.WireguardPeerList{}
		Expect(k8sClient.List(ctx, peerList)).Should(Succeed())
		for i := range peerList.Items {
			Expect(k8sClient.Delete(ctx, &peerList.Items[i])).Should(Succeed())
		}
		secretList := &corev1.SecretList{}
		Expect(k8sClient.List(ctx, secretList)).Should(Succeed())
		for i := range secretList.Items {
			Expect(k8sClient.Delete(ctx, &secretList.Items[i])).Should(Succeed())
		}
		svcList := &corev1.ServiceList{}
		Expect(k8sClient.List(ctx, svcList)).Should(Succeed())
		for i := range svcList.Items {
			Expect(k8sClient.Delete(ctx, &svcList.Items[i])).Should(Succeed())
		}
		Expect(k8sClient.Create(ctx, &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Name: "kube-dns", Namespace: "kube-system"},
			Spec: corev1.ServiceSpec{
				ClusterIP: "10.0.0.42",
				Ports:     []corev1.ServicePort{{Name: "dns", Protocol: corev1.ProtocolUDP, Port: 53}},
			},
		})).Should(Succeed())
	})

	mkWireguard := func(name string) {
		Expect(k8sClient.Create(ctx, &v1alpha1.Wireguard{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: wgNamespace},
			Spec:       v1alpha1.WireguardSpec{ServiceType: corev1.ServiceTypeClusterIP, Address: "10.0.0.10"},
		})).Should(Succeed())
	}
	mkPeer := func(name, wgRef, declaredPub string) {
		Expect(k8sClient.Create(ctx, &v1alpha1.WireguardPeer{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: wgNamespace},
			Spec:       v1alpha1.WireguardPeerSpec{WireguardRef: wgRef, PublicKey: declaredPub},
		})).Should(Succeed())
	}
	mkSecret := func(name, priv, pub string) {
		Expect(k8sClient.Create(ctx, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: wgNamespace},
			Data:       map[string][]byte{"privateKey": []byte(priv), "publicKey": []byte(pub)},
		})).Should(Succeed())
	}
	genKey := func() (priv, pub string) {
		k, err := wgtypes.GeneratePrivateKey()
		Expect(err).ToNot(HaveOccurred())
		return k.String(), k.PublicKey().String()
	}
	getPeer := func(name string) *v1alpha1.WireguardPeer {
		got := &v1alpha1.WireguardPeer{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: name, Namespace: wgNamespace}, got)).To(Succeed())
		return got
	}
	updateSecretKey := func(name, priv, pub string) {
		Eventually(func(g Gomega) {
			s := &corev1.Secret{}
			g.Expect(k8sClient.Get(ctx, types.NamespacedName{Name: name, Namespace: wgNamespace}, s)).To(Succeed())
			s.Data["privateKey"] = []byte(priv)
			s.Data["publicKey"] = []byte(pub)
			g.Expect(k8sClient.Update(ctx, s)).To(Succeed())
		}, Timeout, Interval).Should(Succeed())
	}

	// 1 — the bug: a generated key must yield to a differing Secret key.
	It("re-adopts the Secret key when a generated key disagrees, flipping origin to external", func() {
		mkWireguard("vpn-prov-1")
		peerName := "prov-generated-1"
		mkPeer(peerName, "vpn-prov-1", "") // no Secret yet → operator generates

		var generatedPub string
		Eventually(func(g Gomega) {
			got := getPeer(peerName)
			g.Expect(got.Spec.PublicKey).ToNot(BeEmpty())
			g.Expect(got.Annotations).To(HaveKeyWithValue(keyOriginAnno, "generated"))
			generatedPub = got.Spec.PublicKey
		}, Timeout, Interval).Should(Succeed())

		// simulate ESO landing the real key into the Secret
		newPriv, newPub := genKey()
		updateSecretKey(peerName+"-peer", newPriv, newPub)

		Eventually(func(g Gomega) {
			got := getPeer(peerName)
			g.Expect(got.Spec.PublicKey).To(Equal(newPub))
			g.Expect(got.Annotations).To(HaveKeyWithValue(keyOriginAnno, "external"))
		}, Timeout, Interval).Should(Succeed())
		Expect(generatedPub).ToNot(Equal(newPub))
	})

	// 2 — two hard-set values: declared spec.PublicKey vs disagreeing Secret → fail closed.
	It("fails closed when a declared publicKey disagrees with its Secret", func() {
		mkWireguard("vpn-prov-2")
		peerName := "prov-declared-2"
		sPriv, sPub := genKey()
		mkSecret(peerName+"-peer", sPriv, sPub)
		_, declaredPub := genKey()
		mkPeer(peerName, "vpn-prov-2", declaredPub)

		Eventually(func(g Gomega) {
			got := getPeer(peerName)
			g.Expect(got.Status.Status).To(Equal(v1alpha1.Error))
			g.Expect(got.Status.Message).To(ContainSubstring("disagrees with peer secret"))
		}, Timeout, Interval).Should(Succeed())
		got := getPeer(peerName)
		Expect(got.Spec.PublicKey).To(Equal(declaredPub)) // unchanged
		Expect(got.Annotations).ToNot(HaveKey(keyOriginAnno))
	})

	// 3 — adopted key whose Secret later rotates → fail closed (chosen behavior).
	It("fails closed when an adopted key's Secret later rotates", func() {
		mkWireguard("vpn-prov-3")
		peerName := "prov-adopted-3"
		k1Priv, k1Pub := genKey()
		mkSecret(peerName+"-peer", k1Priv, k1Pub)
		mkPeer(peerName, "vpn-prov-3", "") // adopt the pre-existing Secret

		Eventually(func(g Gomega) {
			got := getPeer(peerName)
			g.Expect(got.Spec.PublicKey).To(Equal(k1Pub))
			g.Expect(got.Annotations).To(HaveKeyWithValue(keyOriginAnno, "external"))
		}, Timeout, Interval).Should(Succeed())

		k2Priv, k2Pub := genKey()
		updateSecretKey(peerName+"-peer", k2Priv, k2Pub)

		Eventually(func(g Gomega) {
			got := getPeer(peerName)
			g.Expect(got.Status.Status).To(Equal(v1alpha1.Error))
			g.Expect(got.Status.Message).To(ContainSubstring("disagrees with peer secret"))
		}, Timeout, Interval).Should(Succeed())
		Expect(getPeer(peerName).Spec.PublicKey).To(Equal(k1Pub)) // unchanged
	})

	// 4 — idempotency: a generated key that still matches its Secret is left alone.
	It("leaves a generated key untouched while it still matches its Secret", func() {
		mkWireguard("vpn-prov-4")
		peerName := "prov-idem-4"
		mkPeer(peerName, "vpn-prov-4", "")

		var pub string
		Eventually(func(g Gomega) {
			got := getPeer(peerName)
			g.Expect(got.Annotations).To(HaveKeyWithValue(keyOriginAnno, "generated"))
			pub = got.Spec.PublicKey
		}, Timeout, Interval).Should(Succeed())

		// poke a reconcile via a label change; provenance must not churn
		Eventually(func(g Gomega) {
			got := getPeer(peerName)
			got.Labels = map[string]string{"poke": "1"}
			g.Expect(k8sClient.Update(ctx, got)).To(Succeed())
		}, Timeout, Interval).Should(Succeed())
		Consistently(func(g Gomega) {
			got := getPeer(peerName)
			g.Expect(got.Spec.PublicKey).To(Equal(pub))
			g.Expect(got.Annotations).To(HaveKeyWithValue(keyOriginAnno, "generated"))
		}, time.Second*2, Interval).Should(Succeed())
	})

	// 5 — declared pubkey with no Secret (roaming client) is untouched by provenance logic.
	It("leaves a declared publicKey with no Secret untouched", func() {
		mkWireguard("vpn-prov-5")
		peerName := "prov-roaming-5"
		_, declaredPub := genKey()
		mkPeer(peerName, "vpn-prov-5", declaredPub)

		Consistently(func(g Gomega) {
			got := getPeer(peerName)
			g.Expect(got.Spec.PublicKey).To(Equal(declaredPub))
			g.Expect(got.Annotations).ToNot(HaveKey(keyOriginAnno))
			g.Expect(got.Status.Message).ToNot(ContainSubstring("disagrees with peer secret"))
		}, time.Second*3, Interval).Should(Succeed())
	})

	// 6 — first-time adopt stamps external (generate→generated is covered by 1 & 4).
	It("stamps origin=external when adopting a pre-existing Secret", func() {
		mkWireguard("vpn-prov-6")
		peerName := "prov-adopt-6"
		sPriv, sPub := genKey()
		mkSecret(peerName+"-peer", sPriv, sPub)
		mkPeer(peerName, "vpn-prov-6", "")

		Eventually(func(g Gomega) {
			got := getPeer(peerName)
			g.Expect(got.Spec.PublicKey).To(Equal(sPub))
			g.Expect(got.Annotations).To(HaveKeyWithValue(keyOriginAnno, "external"))
		}, Timeout, Interval).Should(Succeed())
	})

	// 7 (scope B) — the generated Secret must NOT be controller-owned by the peer,
	// so external-secrets can claim controllership; the peer stays a plain owner
	// so garbage collection still cascades.
	It("creates the generated Secret with a non-controller owner reference", func() {
		mkWireguard("vpn-prov-7")
		peerName := "prov-noncontroller-7"
		mkPeer(peerName, "vpn-prov-7", "") // no Secret → operator generates + creates it

		secretKey := types.NamespacedName{Name: peerName + "-peer", Namespace: wgNamespace}
		Eventually(func(g Gomega) {
			s := &corev1.Secret{}
			g.Expect(k8sClient.Get(ctx, secretKey, s)).To(Succeed())
			peerIsOwner := false
			for _, o := range s.GetOwnerReferences() {
				if o.Kind == "WireguardPeer" && o.Name == peerName {
					peerIsOwner = true
				}
			}
			g.Expect(peerIsOwner).To(BeTrue())              // GC intact
			g.Expect(metav1.GetControllerOf(s)).To(BeNil()) // not controller-owned
		}, Timeout, Interval).Should(Succeed())
	})
})
