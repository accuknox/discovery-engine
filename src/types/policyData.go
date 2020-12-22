package types

// ========================= //
// == Knox Network Policy == //
// ========================= //

// SpecCIDR Structure
type SpecCIDR struct {
	CIDRs  []string `json:"cidrs,omitempty" yaml:"cidrs,omitempty" bson:"cidrs,omitempty"`
	Except []string `json:"except,omitempty" yaml:"except,omitempty" bson:"except,omitempty"`
}

// SpecPort Structure
type SpecPort struct {
	Port     string `json:"port,omitempty" yaml:"port,omitempty" bson:"port,omitempty"`
	Protocol string `json:"protocol,omitempty" yaml:"protocol,omitempty" bson:"protocol,omitempty"`
}

// SpecService Structure
type SpecService struct {
	ServiceName string `json:"serviceName,omitempty" yaml:"serviceName,omitempty" bson:"serviceName,omitempty"`
	Namespace   string `json:"namespace,omitempty" yaml:"namespace,omitempty" bson:"namespace,omitempty"`
}

// SpecFQDN Structure
type SpecFQDN struct {
	MatchNames []string `json:"matchNames,omitempty" yaml:"matchNames,omitempty" bson:"matchNames,omitempty"`
}

// SpecHTTP Structure
type SpecHTTP struct {
	Method     string `json:"method,omitempty" yaml:"method,omitempty" bson:"method,omitempty"`
	Path       string `json:"path,omitempty" yaml:"path,omitempty" bson:"path,omitempty"`
	Aggregated bool   `json:"aggregated,omitempty" yaml:"aggregated,omitempty" bson:"aggregated,omitempty"`
}

// Selector Structure
type Selector struct {
	MatchLabels map[string]string `json:"matchLabels,omitempty" yaml:"matchLabels,omitempty" bson:"matchLabels,omitempty"`
}

// Ingress Structure
type Ingress struct {
	MatchLabels map[string]string `json:"matchLabels,omitempty" yaml:"matchLabels,omitempty" bson:"matchLabels,omitempty"`
	ToPorts     []SpecPort        `json:"toPorts,omitempty" yaml:"toPorts,omitempty" bson:"toPorts,omitempty"`
	ToHTTPs     []SpecHTTP        `json:"toHTTPs,omitempty" yaml:"toHTTPs,omitempty" bson:"toHTTPs,omitempty"`

	FromCIDRs    []SpecCIDR `json:"fromCIDRs,omitempty" yaml:"fromCIDRs,omitempty" bson:"fromCIDRs,omitempty"`
	FromEntities []string   `json:"fromEntities,omitempty" yaml:"fromEntities,omitempty" bson:"fromEntities,omitempty"`
}

// Egress Structure
type Egress struct {
	MatchLabels map[string]string `json:"matchLabels,omitempty" yaml:"matchLabels,omitempty" bson:"matchLabels,omitempty"`
	ToPorts     []SpecPort        `json:"toPorts,omitempty" yaml:"toPorts,omitempty" bson:"toPorts,omitempty"`

	ToCIDRs     []SpecCIDR    `json:"toCIDRs,omitempty" yaml:"toCIDRs,omitempty" bson:"toCIDRs,omitempty"`
	ToEndtities []string      `json:"toEntities,omitempty" yaml:"toEntities,omitempty" bson:"toEntities,omitempty"`
	ToServices  []SpecService `json:"toServices,omitempty" yaml:"toServices,omitempty" bson:"toServices,omitempty"`
	ToFQDNs     []SpecFQDN    `json:"toFQDNs,omitempty" yaml:"toFQDNs,omitempty" bson:"toFQDNs,omitempty"`
	ToHTTPs     []SpecHTTP    `json:"toHTTPs,omitempty" yaml:"toHTTPs,omitempty" bson:"toHTTPs,omitempty"`
}

// Spec Structure
type Spec struct {
	Selector Selector `json:"selector,omitempty" yaml:"selector,omitempty" bson:"selector,omitempty"`

	Egress  []Egress  `json:"egress,omitempty" yaml:"egress,omitempty" bson:"egress,omitempty"`
	Ingress []Ingress `json:"ingress,omitempty" yaml:"ingress,omitempty" bson:"ingress,omitempty"`

	Action string `json:"action,omitempty" yaml:"action,omitempty" bson:"action,omitempty"`
}

// KnoxNetworkPolicy Structure
type KnoxNetworkPolicy struct {
	APIVersion string            `json:"apiVersion,omitempty" yaml:"apiVersion,omitempty" bson:"apiVersion,omitempty"`
	Kind       string            `json:"kind,omitempty" yaml:"kind,omitempty" bson:"kind,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty" yaml:"metadata,omitempty" bson:"metadata,omitempty"`
	Outdated   string            `json:"outdated,omitempty" yaml:"outdated,omitempty" bson:"outdated,omitempty"`

	Spec Spec `json:"spec,omitempty" yaml:"spec,omitempty" bson:"spec,omitempty"`

	GeneratedTime int64 `json:"generatedTime,omitempty" yaml:"generatedTime,omitempty" bson:"generatedTime,omitempty"`
}

// =========================== //
// == Cilium Network Policy == //
// =========================== //

// CiliumCIDRSet Structure
type CiliumCIDRSet struct {
	CIDR   string   `json:"cidr" yaml:"cidr"`
	Except []string `json:"except,omitempty" yaml:"except,omitempty" bson:"except,omitempty"`
}

// CiliumPort Structure
type CiliumPort struct {
	Port     string `json:"port,omitempty" yaml:"port,omitempty"`
	Protocol string `json:"protocol" yaml:"protocol"`
}

// SubRule ...
type SubRule map[string]string

// CiliumFQDN ...
type CiliumFQDN map[string]string

// CiliumPortList Structure
type CiliumPortList struct {
	Ports []CiliumPort         `json:"ports,omitempty" yaml:"ports,omitempty"`
	Rules map[string][]SubRule `json:"rules,omitempty" yaml:"rules,omitempty"`
}

// CiliumEndpoint Structure
type CiliumEndpoint struct {
	MatchLabels map[string]string `json:"matchLabels,omitempty" yaml:"matchLabels,omitempty"`
}

// CiliumK8sService Structure
type CiliumK8sService struct {
	ServiceName string `json:"serviceName,omitempty" yaml:"serviceName,omitempty"`
	Namespace   string `json:"namespace,omitempty" yaml:"namespace,omitempty"`
}

// CiliumService Structure
type CiliumService struct {
	K8sService CiliumK8sService `json:"k8sService,omitempty" yaml:"k8sService,omitempty"`
}

// CiliumEgress Structure
type CiliumEgress struct {
	ToEndpoints []CiliumEndpoint `json:"toEndpoints,omitempty" yaml:"toEndpoints,omitempty"`
	ToPorts     []CiliumPortList `json:"toPorts,omitempty" yaml:"toPorts,omitempty"`

	ToCIDRs    []string        `json:"toCIDR,omitempty" yaml:"toCIDR,omitempty"`
	ToEntities []string        `json:"toEntities,omitempty" yaml:"toEntities,omitempty"`
	ToServices []CiliumService `json:"toServices,omitempty" yaml:"toServices,omitempty"`
	ToFQDNs    []CiliumFQDN    `json:"toFQDNs,omitempty" yaml:"toFQDNs,omitempty"`
}

// CiliumIngress Structure
type CiliumIngress struct {
	FromEndpoints []CiliumEndpoint `json:"fromEndpoints,omitempty" yaml:"fromEndpoints,omitempty"`
	ToPorts       []CiliumPortList `json:"toPorts,omitempty" yaml:"toPorts,omitempty"`

	FromCIDRs    []string `json:"fromCIDR,omitempty" yaml:"fromCIDR,omitempty"`
	FromEntities []string `json:"fromEntities,omitempty" yaml:"fromEntities,omitempty"`
}

// CiliumSpec Structure
type CiliumSpec struct {
	Selector Selector `json:"endpointSelector,omitempty" yaml:"endpointSelector,omitempty"`

	Egress  []CiliumEgress  `json:"egress,omitempty" yaml:"egress,omitempty"`
	Ingress []CiliumIngress `json:"ingress,omitempty" yaml:"ingress,omitempty"`
}

// CiliumNetworkPolicy Structure
type CiliumNetworkPolicy struct {
	APIVersion string            `json:"apiVersion,omitempty" yaml:"apiVersion,omitempty"`
	Kind       string            `json:"kind,omitempty" yaml:"kind,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty" yaml:"metadata,omitempty"`
	Spec       CiliumSpec        `json:"spec" yaml:"spec"`
}
