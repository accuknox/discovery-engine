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

	PolicyTypeSystem  = "system"
	PolicyTypeNetwork = "network"

	// Binary Name Filters
	FilterBinaryKnoxAutoPolicy = "knoxAutoPolicy"
)
