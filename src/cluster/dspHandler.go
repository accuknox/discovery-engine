package cluster

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"

	dspv1 "github.com/accuknox/auto-policy-discovery/pkg/discoveredpolicy/api/security.kubearmor.com/v1"
	dsp "github.com/accuknox/auto-policy-discovery/pkg/discoveredpolicy/client/clientset/versioned/typed/security.kubearmor.com/v1"
	"github.com/accuknox/auto-policy-discovery/src/types"
	networkv1 "k8s.io/api/networking/v1"
	apiextv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	patchTypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/discovery"
	ctrl "sigs.k8s.io/controller-runtime"
)

var (
	// IsCiliumPolicyAvailable defines if CiliumNetworkPolicy resource exists
	IsCiliumPolicyAvailable bool
)

// CreateClient func
func CreateClient() *dsp.SecurityV1Client {
	config, err := ctrl.GetConfig()
	if err != nil {
		Logr.Error().Msg(err.Error())
		return nil
	}
	client, err := dsp.NewForConfig(config)
	if err != nil {
		Logr.Error().Msg(err.Error())
		return nil
	}

	return client
}

// CreateDsp func
func CreateDsp(name, namespace, policyType string, pol []byte) error {
	client := CreateClient()
	if client == nil {
		return fmt.Errorf("failed to create DiscoveredPolicy client")
	}
	// define a dsp with given name and namespace
	dsp := &dspv1.DiscoveredPolicy{}
	dsp.Name = name
	dsp.Namespace = namespace
	dsp.Spec.PolicyStatus = "Inactive"

	polSpec := apiextv1.JSON{
		Raw: pol,
	}

	dsp.Spec.Policy = &polSpec

	// deploy dsp
	Logr.Info().Msgf("namespace %s dsp.namespace %s", namespace, dsp.Namespace)
	res, err := client.DiscoveredPolicies(namespace).Create(context.TODO(), dsp, metav1.CreateOptions{})
	if err != nil {
		if errors.IsAlreadyExists(err) {
			// update exising dsp if new rules are added
			return UpdateExisting(name, namespace, policyType, &pol)
		}
		Logr.Error().Msgf("Error Creating DiscoveredPolicy %s", err)
		return err
	}
	Logr.Info().Msgf("Created Discovered Policy %s in namespace %s", res.Name, res.Namespace)
	return nil
}

// UpdateExisting func
func UpdateExisting(name, namespace, policyType string, pol *[]byte) error {
	client := CreateClient()
	if client == nil {
		return fmt.Errorf("failed to create DiscoveredPolicy client")
	}
	dsp, err := client.DiscoveredPolicies(namespace).Get(context.TODO(), name, metav1.GetOptions{})
	if err != nil {
		Logr.Error().Msgf("Error getting dsp %s", err)
		return err
	}
	var newPolicy, existingPolicy interface{}
	switch policyType {
	case "KubeArmorPolicy":
		newPolicy = &types.KubeArmorPolicy{}
		existingPolicy = &types.KubeArmorPolicy{}
	case "CiliumNetworkPolicy":
		newPolicy = &types.CiliumNetworkPolicy{}
		existingPolicy = &types.CiliumNetworkPolicy{}
	case "K8sNetworkPolicy":
		newPolicy = &networkv1.NetworkPolicy{}
		existingPolicy = &networkv1.NetworkPolicy{}
	}

	if err = json.Unmarshal(*pol, newPolicy); err != nil {
		Logr.Error().Msgf("Error unmarshalling policy %s", err)
	}

	if err = json.Unmarshal(dsp.Spec.Policy.Raw, existingPolicy); err != nil {
		Logr.Error().Msgf("Error unmarshalling policy %s", err)
	}

	if AreRulesSame(existingPolicy, newPolicy, policyType) {
		Logr.Info().Msgf("policy %s is already having updated rules", dsp.Name)
		return nil
	}

	var newStatus string
	switch dsp.Spec.PolicyStatus {
	case "Active", "active":
		// update status to PendingUpdates
		newStatus = "PendingUpdates"
	default:
		newStatus = string(dsp.Spec.PolicyStatus)
	}

	patchData := fmt.Sprintf(`{"spec":{"policy":%s, "status":"%s"}}`, *pol, newStatus)
	patchByte := []byte(patchData)

	res, err := client.DiscoveredPolicies(namespace).Patch(context.TODO(), name, patchTypes.MergePatchType, patchByte, metav1.PatchOptions{})
	if err != nil {
		Logr.Error().Msgf("Error Updating The Policy %s", err)
		return err
	}
	Logr.Info().Msgf("Updated Policy %s with policy %s", res.Name, res.Spec.Policy)
	return nil
}

// AreRulesSame func
func AreRulesSame(policyA, policyB interface{}, policyType string) bool {
	switch policyType {
	case "KubeArmorPolicy":
		return reflect.DeepEqual(policyA.(*types.KubeArmorPolicy).Spec, policyB.(*types.KubeArmorPolicy).Spec)
	case "CiliumNetworkPolicy":
		return reflect.DeepEqual(policyA.(*types.CiliumNetworkPolicy).Spec, policyB.(*types.CiliumNetworkPolicy).Spec)
	case "NetworkPolicy":
		return reflect.DeepEqual(policyA.(*networkv1.NetworkPolicy).Spec, policyB.(*networkv1.NetworkPolicy).Spec)
	}
	return false
}

// IsAPIResourceAvailable func
func IsAPIResourceAvailable(gvr schema.GroupVersionResource) bool {
	// create a discovery client for the given config
	config, err := ctrl.GetConfig()
	if err != nil {
		Logr.Error().Msg(err.Error())
		return false
	}
	dc, err := discovery.NewDiscoveryClientForConfig(config)
	if err != nil {
		Logr.Error().Msgf("Error creating discovery client: %v\n", err)
		return false
	}
	apiResources, err := dc.ServerResourcesForGroupVersion(gvr.GroupVersion().String())
	if err != nil {
		Logr.Error().Msgf("Error getting server resources: %s\t%v\n", gvr.Resource, err)
		return false
	}

	// check if the ciliumnetworkpolicies resource is available
	for _, resource := range apiResources.APIResources {
		if resource.Name == gvr.Resource {
			Logr.Info().Msgf("%s api resource is available\n", gvr.Resource)
			return true
		}
	}

	return false
}

func init() {
	IsCiliumPolicyAvailable = IsAPIResourceAvailable(schema.GroupVersionResource{
		Group:    "cilium.io",
		Version:  "v2",
		Resource: "ciliumnetworkpolicies",
	})
}
