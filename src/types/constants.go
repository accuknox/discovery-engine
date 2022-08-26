package types

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

	// Cilium constants
	KindKnoxNetworkPolicy     = "KnoxNetworkPolicy"
	KindKnoxHostNetworkPolicy = "KnoxHostNetworkPolicy"
)
