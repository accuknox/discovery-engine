package v1

// +kubebuilder:validation:Enum=Validated;Success;Failed;Unknown
type PolicyPhaseType string

// +kubebuilder:validation:Enum=KubeArmorPolicy;CiliumNetworkPolicy;NetworkPolicy
type PolicyType string

// +kubebuilder:validation:Enum=Inactive;inactive;Active;active;PendingUpdates
type PolicyStatusType string
