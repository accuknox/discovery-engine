package v1

import (
	apiextv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// DiscoveredPolicySpec defines the desired state of DiscoveredPolicy
type DiscoveredPolicySpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// +kubebuilder:default:="Inactive"
	PolicyStatus PolicyStatusType `json:"status,omptempty"`
	Policy       *apiextv1.JSON   `json:"policy,omitempty"`
}

// DiscoveredPolicyStatus defines the observed state of DiscoveredPolicy
type DiscoveredPolicyStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// +kubebuilder:validation:optional
	PolicyPhase PolicyPhaseType `json:"phase,omitempty"`

	// +kubebuilder:validation:optional
	PolicyKind string `json:"kind,omitempty"`

	// +kubebuilder:validation:optional
	LastUpdatedTime metav1.Time `json:"lastUpdatedTime,omitempty"`

	// +kubebuilder:validation:optional
	Message string `json:"message,omitempty"`

	// +kubebuilder:validation:optional
	Reason string `json:"reason,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +genclient
// +kubebuilder:resource:shortName=dsp
// +kubebuilder:printcolumn:name="Status",type="string",JSONPath=".status.phase"
// +kubebuilder:printcolumn:name="Policy_Status",type="string",JSONPath=".spec.status"
// +kubebuilder:printcolumn:name="Policy_Type",type="string",JSONPath=".status.kind"
// DiscoveredPolicy is the Schema for the discoveredpolicies API
type DiscoveredPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   DiscoveredPolicySpec   `json:"spec,omitempty"`
	Status DiscoveredPolicyStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// DiscoveredPolicyList contains a list of DiscoveredPolicy
type DiscoveredPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []DiscoveredPolicy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&DiscoveredPolicy{}, &DiscoveredPolicyList{})
}
