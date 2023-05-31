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
)
