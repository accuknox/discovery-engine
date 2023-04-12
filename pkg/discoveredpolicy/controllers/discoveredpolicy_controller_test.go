package controllers

import (
	"context"
	"encoding/json"
	"testing"

	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	kspv1 "github.com/kubearmor/KubeArmor/pkg/KubeArmorController/api/security.kubearmor.com/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	networkingv1 "k8s.io/api/networking/v1"
	v1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	securityv1 "github.com/accuknox/auto-policy-discovery/pkg/discoveredpolicy/api/security.kubearmor.com/v1"
)

// ==============================
// === KubeArmor Policy Tests ===
// ==============================

func TestControllerReconcileForInactiveKsp(t *testing.T) {
	s := scheme.Scheme

	err := securityv1.AddToScheme(s)
	require.NoError(t, err)

	// Create a fake MyCRD object and add it to the clientset
	mycrd := &securityv1.DiscoveredPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-mycrd",
			Namespace: "default",
		},
		Spec: securityv1.DiscoveredPolicySpec{
			PolicyStatus: "Inactive",
			Policy: &v1.JSON{
				Raw: json.RawMessage(`{"apiversion":"security.kubearmor.com/v1", "kind": "KubeArmorPolicy",
					"metadata": {"name": "test-mycrd","namespace": "default"}}`),
			},
		},
	}

	cl := fake.NewFakeClientWithScheme(s, mycrd)
	// Create a fake event recorder and controller instance
	controller := &DiscoveredPolicyReconciler{
		Client: cl,
		Scheme: s,
	}

	// Create a fake reconcile request for the MyCRD object
	req := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-mycrd",
			Namespace: "default",
		},
	}

	// Call the reconcile function of the controller
	res, err := controller.Reconcile(context.TODO(), req)
	require.NoError(t, err)
	assert.False(t, res.Requeue)

	mycrd = &securityv1.DiscoveredPolicy{}
	err = cl.Get(context.TODO(), client.ObjectKeyFromObject(&securityv1.DiscoveredPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-mycrd",
			Namespace: "default",
		},
	}), mycrd)
	require.NoError(t, err)

	// Check that the status field has been updated
	assert.Equal(t, securityv1.PolicyPhaseType("Success"), mycrd.Status.PolicyPhase)
	assert.Equal(t, "KubeArmorPolicy", mycrd.Status.PolicyKind)

	// Verify that KubeArmor policy shouldn't be deployed
	ksp := &kspv1.KubeArmorPolicy{}
	err = cl.Get(context.TODO(), client.ObjectKeyFromObject(&kspv1.KubeArmorPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-mycrd",
			Namespace: "default",
		},
	}), ksp)
	require.Error(t, err)

}

func TestControllerReconcileForInactiveExistingKsp(t *testing.T) {
	s := scheme.Scheme

	err := securityv1.AddToScheme(s)
	require.NoError(t, err)

	// Create a fake MyCRD object and add it to the clientset
	mycrd := &securityv1.DiscoveredPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-mycrd",
			Namespace: "default",
		},
		Spec: securityv1.DiscoveredPolicySpec{
			PolicyStatus: "Inactive",
			Policy: &v1.JSON{
				Raw: json.RawMessage(`{"apiversion":"security.kubearmor.com/v1", "kind": "KubeArmorPolicy",
					"metadata": {"name": "test-mycrd","namespace": "default"}}`),
			},
		},
	}

	cl := fake.NewFakeClientWithScheme(s, mycrd)
	// Create a fake event recorder and controller instance
	controller := &DiscoveredPolicyReconciler{
		Client: cl,
		Scheme: s,
	}

	// Create a ksp with same namespaced name as dsp
	existingKsp := &kspv1.KubeArmorPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-mycrd",
			Namespace: "default",
		},
	}

	err = cl.Create(context.TODO(), existingKsp)
	require.NoError(t, err)

	// Create a fake reconcile request for the MyCRD object
	req := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-mycrd",
			Namespace: "default",
		},
	}

	// Call the reconcile function of the controller
	res, err := controller.Reconcile(context.TODO(), req)
	require.NoError(t, err)
	assert.False(t, res.Requeue)

	mycrd = &securityv1.DiscoveredPolicy{}
	err = cl.Get(context.TODO(), client.ObjectKeyFromObject(&securityv1.DiscoveredPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-mycrd",
			Namespace: "default",
		},
	}), mycrd)
	require.NoError(t, err)

	// Check that the status field has been updated
	assert.Equal(t, securityv1.PolicyPhaseType("Success"), mycrd.Status.PolicyPhase)
	assert.Equal(t, "KubeArmorPolicy", mycrd.Status.PolicyKind)

	// Verify that KubeArmor policy shouldn't be deployed
	ksp := &kspv1.KubeArmorPolicy{}
	err = cl.Get(context.TODO(), client.ObjectKeyFromObject(&kspv1.KubeArmorPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-mycrd",
			Namespace: "default",
		},
	}), ksp)
	require.Error(t, err)

}

func TestControllerReconcileForInvalidKsp(t *testing.T) {
	s := scheme.Scheme

	err := securityv1.AddToScheme(s)
	require.NoError(t, err)

	// Create a fake MyCRD object and add it to the clientset
	mycrd := &securityv1.DiscoveredPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-mycrd",
			Namespace: "default",
		},
		Spec: securityv1.DiscoveredPolicySpec{
			PolicyStatus: "Inactive",
			Policy: &v1.JSON{
				Raw: json.RawMessage(`{"apiversion":"security.kubearmor.com/v1", "kind": "KubeArmorPolicy",
					"metadata": {"name": "test-mycrd-invalid","namespace": "default"}}`),
			},
		},
	}

	cl := fake.NewFakeClientWithScheme(s, mycrd)
	// Create a fake event recorder and controller instance
	controller := &DiscoveredPolicyReconciler{
		Client: cl,
		Scheme: s,
	}

	// Create a fake reconcile request for the MyCRD object
	req := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-mycrd",
			Namespace: "default",
		},
	}

	// Call the reconcile function of the controller
	res, err := controller.Reconcile(context.TODO(), req)
	require.NoError(t, err)
	assert.False(t, res.Requeue)

	mycrd = &securityv1.DiscoveredPolicy{}
	err = cl.Get(context.TODO(), client.ObjectKeyFromObject(&securityv1.DiscoveredPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-mycrd",
			Namespace: "default",
		},
	}), mycrd)
	require.NoError(t, err)

	// Check that the status field has been updated
	assert.Equal(t, securityv1.PolicyPhaseType("Failed"), mycrd.Status.PolicyPhase)
	assert.Equal(t, "KubeArmorPolicy", mycrd.Status.PolicyKind)
	assert.Equal(t, ValidationFailed, mycrd.Status.Message)
	assert.Equal(t, ValidationFailedReason, mycrd.Status.Reason)

}

func TestControllerReconcileForActiveKsp(t *testing.T) {
	s := scheme.Scheme

	err := securityv1.AddToScheme(s)
	require.NoError(t, err)

	// Create a fake MyCRD object and add it to the clientset
	mycrd := &securityv1.DiscoveredPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-mycrd",
			Namespace: "default",
		},
		Spec: securityv1.DiscoveredPolicySpec{
			PolicyStatus: "Active",
			Policy: &v1.JSON{
				Raw: json.RawMessage(`{"apiversion":"security.kubearmor.com/v1", "kind": "KubeArmorPolicy",
					"metadata": {"name": "test-mycrd","namespace": "default"}}`),
			},
		},
	}

	cl := fake.NewFakeClientWithScheme(s, mycrd)
	// Create a fake event recorder and controller instance
	controller := &DiscoveredPolicyReconciler{
		Client: cl,
		Scheme: s,
	}

	// Create a fake reconcile request for the MyCRD object
	req := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-mycrd",
			Namespace: "default",
		},
	}

	// Call the reconcile function of the controller
	res, err := controller.Reconcile(context.TODO(), req)
	require.NoError(t, err)
	assert.False(t, res.Requeue)

	mycrd = &securityv1.DiscoveredPolicy{}
	err = cl.Get(context.TODO(), client.ObjectKeyFromObject(&securityv1.DiscoveredPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-mycrd",
			Namespace: "default",
		},
	}), mycrd)
	require.NoError(t, err)

	// Check that the status field has been updated
	assert.Equal(t, securityv1.PolicyPhaseType("Success"), mycrd.Status.PolicyPhase)
	assert.Equal(t, "KubeArmorPolicy", mycrd.Status.PolicyKind)
	assert.Equal(t, Activated, mycrd.Status.Message)
	assert.Equal(t, "", mycrd.Status.Reason)

	// Verify that KubeArmor policy get deployed
	ksp := &kspv1.KubeArmorPolicy{}
	err = cl.Get(context.TODO(), client.ObjectKeyFromObject(&kspv1.KubeArmorPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-mycrd",
			Namespace: "default",
		},
	}), ksp)
	require.NoError(t, err)

}

// ===========================
// === Nework Policy Tests ===
// ===========================

func TestControllerReconcileForInactiveNetworkPolicy(t *testing.T) {
	s := scheme.Scheme

	err := securityv1.AddToScheme(s)
	require.NoError(t, err)

	// Create a fake MyCRD object and add it to the clientset
	mycrd := &securityv1.DiscoveredPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-mycrd",
			Namespace: "default",
		},
		Spec: securityv1.DiscoveredPolicySpec{
			PolicyStatus: "Inactive",
			Policy: &v1.JSON{
				Raw: json.RawMessage(`{"apiversion":"networking.k8s.io/v1", "kind": "NetworkPolicy",
					"metadata": {"name": "test-mycrd","namespace": "default"}}`),
			},
		},
	}

	cl := fake.NewFakeClientWithScheme(s, mycrd)
	// Create a fake event recorder and controller instance
	controller := &DiscoveredPolicyReconciler{
		Client: cl,
		Scheme: s,
	}

	// Create a fake reconcile request for the MyCRD object
	req := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-mycrd",
			Namespace: "default",
		},
	}

	// Call the reconcile function of the controller
	res, err := controller.Reconcile(context.TODO(), req)
	require.NoError(t, err)
	assert.False(t, res.Requeue)

	mycrd = &securityv1.DiscoveredPolicy{}
	err = cl.Get(context.TODO(), client.ObjectKeyFromObject(&securityv1.DiscoveredPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-mycrd",
			Namespace: "default",
		},
	}), mycrd)
	require.NoError(t, err)

	// Check that the status field has been updated
	assert.Equal(t, securityv1.PolicyPhaseType("Success"), mycrd.Status.PolicyPhase)
	assert.Equal(t, "NetworkPolicy", mycrd.Status.PolicyKind)

	// Verify that Network Policy shouldn't be deployed
	np := &networkingv1.NetworkPolicy{}
	err = cl.Get(context.TODO(), client.ObjectKeyFromObject(&networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-mycrd",
			Namespace: "default",
		},
	}), np)
	require.Error(t, err)

}

func TestControllerReconcileForInactiveExistingNetworkPolicy(t *testing.T) {
	s := scheme.Scheme

	err := securityv1.AddToScheme(s)
	require.NoError(t, err)

	// Create a fake MyCRD object and add it to the clientset
	mycrd := &securityv1.DiscoveredPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-mycrd",
			Namespace: "default",
		},
		Spec: securityv1.DiscoveredPolicySpec{
			PolicyStatus: "Inactive",
			Policy: &v1.JSON{
				Raw: json.RawMessage(`{"apiversion":"networking.k8s.io/v1", "kind": "NetworkPolicy",
					"metadata": {"name": "test-mycrd","namespace": "default"}}`),
			},
		},
	}

	cl := fake.NewFakeClientWithScheme(s, mycrd)
	// Create a fake event recorder and controller instance
	controller := &DiscoveredPolicyReconciler{
		Client: cl,
		Scheme: s,
	}

	// Create a Netowrk Policy with same NamespacedName as dsp
	existingNp := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-mycrd",
			Namespace: "default",
		},
	}

	err = cl.Create(context.TODO(), existingNp)
	require.NoError(t, err)

	// Create a fake reconcile request for the MyCRD object
	req := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-mycrd",
			Namespace: "default",
		},
	}

	// Call the reconcile function of the controller
	res, err := controller.Reconcile(context.TODO(), req)
	require.NoError(t, err)
	assert.False(t, res.Requeue)

	mycrd = &securityv1.DiscoveredPolicy{}
	err = cl.Get(context.TODO(), client.ObjectKeyFromObject(&securityv1.DiscoveredPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-mycrd",
			Namespace: "default",
		},
	}), mycrd)
	require.NoError(t, err)

	// Check that the status field has been updated
	assert.Equal(t, securityv1.PolicyPhaseType("Success"), mycrd.Status.PolicyPhase)
	assert.Equal(t, "NetworkPolicy", mycrd.Status.PolicyKind)

	// Verify that Network Policy shouldn't be deployed
	np := &networkingv1.NetworkPolicy{}
	err = cl.Get(context.TODO(), client.ObjectKeyFromObject(&networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-mycrd",
			Namespace: "default",
		},
	}), np)
	require.Error(t, err)

}

func TestControllerReconcileForActiveNetworkPolicy(t *testing.T) {
	s := scheme.Scheme

	err := securityv1.AddToScheme(s)
	require.NoError(t, err)

	// Create a fake MyCRD object and add it to the clientset
	mycrd := &securityv1.DiscoveredPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-mycrd",
			Namespace: "default",
		},
		Spec: securityv1.DiscoveredPolicySpec{
			PolicyStatus: "Active",
			Policy: &v1.JSON{
				Raw: json.RawMessage(`{"apiversion":"networking.k8s.io/v1", "kind": "NetworkPolicy",
					"metadata": {"name": "test-mycrd","namespace": "default"}}`),
			},
		},
	}

	cl := fake.NewFakeClientWithScheme(s, mycrd)
	// Create a fake event recorder and controller instance
	controller := &DiscoveredPolicyReconciler{
		Client: cl,
		Scheme: s,
	}

	// Create a fake reconcile request for the MyCRD object
	req := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-mycrd",
			Namespace: "default",
		},
	}

	// Call the reconcile function of the controller
	res, err := controller.Reconcile(context.TODO(), req)
	require.NoError(t, err)
	assert.False(t, res.Requeue)

	mycrd = &securityv1.DiscoveredPolicy{}
	err = cl.Get(context.TODO(), client.ObjectKeyFromObject(&securityv1.DiscoveredPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-mycrd",
			Namespace: "default",
		},
	}), mycrd)
	require.NoError(t, err)

	// Check that the status field has been updated
	assert.Equal(t, securityv1.PolicyPhaseType("Success"), mycrd.Status.PolicyPhase)
	assert.Equal(t, "NetworkPolicy", mycrd.Status.PolicyKind)

	// Verify that Network policy get deployed
	np := &networkingv1.NetworkPolicy{}
	err = cl.Get(context.TODO(), client.ObjectKeyFromObject(&networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-mycrd",
			Namespace: "default",
		},
	}), np)
	require.NoError(t, err)

}

// ==================================
// === Cilium Nework Policy Tests ===
// ==================================

func TestControllerReconcileForInactiveCiliumPolicy(t *testing.T) {
	s := scheme.Scheme

	err := securityv1.AddToScheme(s)
	require.NoError(t, err)

	// Create a fake MyCRD object and add it to the clientset
	mycrd := &securityv1.DiscoveredPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-mycrd",
			Namespace: "default",
		},
		Spec: securityv1.DiscoveredPolicySpec{
			PolicyStatus: "Inactive",
			Policy: &v1.JSON{
				Raw: json.RawMessage(`{"apiversion":"cilium.io/v2", "kind": "CiliumNetworkPolicy",
					"metadata": {"name": "test-mycrd","namespace": "default"}}`),
			},
		},
	}

	cl := fake.NewFakeClientWithScheme(s, mycrd)
	// Create a fake event recorder and controller instance
	controller := &DiscoveredPolicyReconciler{
		Client: cl,
		Scheme: s,
	}

	// Create a fake reconcile request for the MyCRD object
	req := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-mycrd",
			Namespace: "default",
		},
	}

	// Call the reconcile function of the controller
	res, err := controller.Reconcile(context.TODO(), req)
	require.NoError(t, err)
	assert.False(t, res.Requeue)

	mycrd = &securityv1.DiscoveredPolicy{}
	err = cl.Get(context.TODO(), client.ObjectKeyFromObject(&securityv1.DiscoveredPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-mycrd",
			Namespace: "default",
		},
	}), mycrd)
	require.NoError(t, err)

	// Check that the status field has been updated
	assert.Equal(t, securityv1.PolicyPhaseType("Success"), mycrd.Status.PolicyPhase)
	assert.Equal(t, "CiliumNetworkPolicy", mycrd.Status.PolicyKind)

	// Verify that Cilium Network Policy shouldn't be deployed
	cnp := &ciliumv2.CiliumNetworkPolicy{}
	err = cl.Get(context.TODO(), client.ObjectKeyFromObject(&ciliumv2.CiliumNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-mycrd",
			Namespace: "default",
		},
	}), cnp)
	require.Error(t, err)

}

func TestControllerReconcileForInactiveExistingCiliumPolicy(t *testing.T) {
	s := scheme.Scheme

	err := securityv1.AddToScheme(s)
	require.NoError(t, err)

	// Create a fake MyCRD object and add it to the clientset
	mycrd := &securityv1.DiscoveredPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-mycrd",
			Namespace: "default",
		},
		Spec: securityv1.DiscoveredPolicySpec{
			PolicyStatus: "Inactive",
			Policy: &v1.JSON{
				Raw: json.RawMessage(`{"apiversion":"cilium.io/v2", "kind": "CiliumNetworkPolicy",
					"metadata": {"name": "test-mycrd","namespace": "default"}}`),
			},
		},
	}

	cl := fake.NewFakeClientWithScheme(s, mycrd)
	// Create a fake event recorder and controller instance
	controller := &DiscoveredPolicyReconciler{
		Client: cl,
		Scheme: s,
	}

	// Create a Cilium Policy with same Namespacedname as dsp
	existingCnp := ciliumv2.CiliumNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-mycrd",
			Namespace: "default",
		},
	}

	err = cl.Create(context.TODO(), &existingCnp)
	require.NoError(t, err)

	// Create a fake reconcile request for the MyCRD object
	req := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-mycrd",
			Namespace: "default",
		},
	}

	// Call the reconcile function of the controller
	res, err := controller.Reconcile(context.TODO(), req)
	require.NoError(t, err)
	assert.False(t, res.Requeue)

	mycrd = &securityv1.DiscoveredPolicy{}
	err = cl.Get(context.TODO(), client.ObjectKeyFromObject(&securityv1.DiscoveredPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-mycrd",
			Namespace: "default",
		},
	}), mycrd)
	require.NoError(t, err)

	// Check that the status field has been updated
	assert.Equal(t, securityv1.PolicyPhaseType("Success"), mycrd.Status.PolicyPhase)
	assert.Equal(t, "CiliumNetworkPolicy", mycrd.Status.PolicyKind)

	// Verify that Cilium Network Policy shouldn't be deployed
	cnp := &ciliumv2.CiliumNetworkPolicy{}
	err = cl.Get(context.TODO(), client.ObjectKeyFromObject(&ciliumv2.CiliumNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-mycrd",
			Namespace: "default",
		},
	}), cnp)
	require.Error(t, err)

}

func TestControllerReconcileForActiveCiliumPolicy(t *testing.T) {
	s := scheme.Scheme

	err := securityv1.AddToScheme(s)
	require.NoError(t, err)

	// Create a fake MyCRD object and add it to the clientset
	mycrd := &securityv1.DiscoveredPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-mycrd",
			Namespace: "default",
		},
		Spec: securityv1.DiscoveredPolicySpec{
			PolicyStatus: "Active",
			Policy: &v1.JSON{
				Raw: json.RawMessage(`{"apiversion":"cilium.io/v2", "kind": "CiliumNetworkPolicy",
					"metadata": {"name": "test-mycrd","namespace": "default"}}`),
			},
		},
	}

	cl := fake.NewFakeClientWithScheme(s, mycrd)
	// Create a fake event recorder and controller instance
	controller := &DiscoveredPolicyReconciler{
		Client: cl,
		Scheme: s,
	}

	// Create a fake reconcile request for the MyCRD object
	req := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-mycrd",
			Namespace: "default",
		},
	}

	// Call the reconcile function of the controller
	res, err := controller.Reconcile(context.TODO(), req)
	require.NoError(t, err)
	assert.False(t, res.Requeue)

	mycrd = &securityv1.DiscoveredPolicy{}
	err = cl.Get(context.TODO(), client.ObjectKeyFromObject(&securityv1.DiscoveredPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-mycrd",
			Namespace: "default",
		},
	}), mycrd)
	require.NoError(t, err)

	// Check that the status field has been updated
	assert.Equal(t, securityv1.PolicyPhaseType("Success"), mycrd.Status.PolicyPhase)
	assert.Equal(t, "CiliumNetworkPolicy", mycrd.Status.PolicyKind)

	// Verify that Network policy get deployed
	cnp := &ciliumv2.CiliumNetworkPolicy{}
	err = cl.Get(context.TODO(), client.ObjectKeyFromObject(&ciliumv2.CiliumNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-mycrd",
			Namespace: "default",
		},
	}), cnp)
	require.NoError(t, err)

}
