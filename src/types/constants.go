package types

import cu "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/utils"

const (
	// KubeArmor VM
	PolicyDiscoveryVMNamespace = "accuknox-vm-namespace"
	PolicyDiscoveryVMPodName   = "accuknox-vm-podname"

	// KubeArmor container
	PolicyDiscoveryContainerNamespace = "container_namespace"
	PolicyDiscoveryContainerPodName   = "container_podname"

	// KubeArmor k8s
	PreConfiguredKubearmorRule = "/lib/x86_64-linux-gnu/"

	// RecordSeparator - DB separator flag
	RecordSeparator = "^^"

	// Network Policy
	KindKnoxNetworkPolicy     = "KnoxNetworkPolicy"
	KindKnoxHostNetworkPolicy = "KnoxHostNetworkPolicy"

	// Cilium Policy
	KindCiliumNetworkPolicy            = cu.ResourceTypeCiliumNetworkPolicy
	KindCiliumClusterwideNetworkPolicy = cu.ResourceTypeCiliumClusterwideNetworkPolicy

	// Kubernetes Policy
	KindK8sNetworkPolicy = "NetworkPolicy"

	// KubeArmor Policy
	KindKubeArmorPolicy     = "KubeArmorPolicy"
	KindKubeArmorHostPolicy = "KubeArmorHostPolicy"

	PolicyTypeSystem                     = "system"
	PolicyTypeNetwork                    = "network"
	PolicyTypeAdmissionController        = "admission-controller"
	PolicyTypeAdmissionControllerGeneric = "admission-controller-generic"

	// Hardening policy
	HardeningPolicy = "harden"

	// Binary Name Filters
	FilterBinaryKnoxAutoPolicy = "knoxAutoPolicy"

	// K8sNetworkPolicy
	K8sNwPolicyAPIVersion = "networking.k8s.io/v1"
	K8sNwPolicyKind       = "NetworkPolicy"

	// max no. of tries to connect to kubearmor-relay
	Maxtries = 6

	// RecommendedPolicyTagsAnnotation is the annotation used to store the tags of the recommended policy.
	// This annotation is used to identify the tags associated with a policy by kubearmor-client.
	RecommendedPolicyTagsAnnotation = "recommended-policies.accuknox.com/tags"

	// RecommendedPolicyTitleAnnotation is the annotation used to store the title of the recommended policy.
	// This annotation is used to identify the title associated with a policy by kubearmor-client.
	RecommendedPolicyTitleAnnotation = "policies.kyverno.io/title"

	// RecommendedPolicyDescriptionAnnotation is the annotation used to store the description of the recommended policy.
	// This annotation is used to identify the description associated with a policy by kubearmor-client.
	RecommendedPolicyDescriptionAnnotation = "policies.kyverno.io/description"
)
