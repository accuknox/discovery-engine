package types

// ========================= //
// == Knox Network Policy == //
// ========================= //

// SpecCIDR Structure
type SpecCIDR struct {
	CIDRs  []string   `json:"cidr,omitempty" yaml:"cidr,omitempty" bson:"cidr,omitempty"`
	Except []string   `json:"except,omitempty" yaml:"except,omitempty" bson:"except,omitempty"`
	Ports  []SpecPort `json:"Ports,omitempty" yaml:"Ports,omitempty" bson:"Ports,omitempty"`
}

// SpecPort Structure
type SpecPort struct {
	Ports    string `json:"ports,omitempty" yaml:"ports,omitempty" bson:"ports,omitempty"`
	Protocol string `json:"protocol,omitempty" yaml:"protocol,omitempty" bson:"protocol,omitempty"`
}

// SpecService Structure
type SpecService struct {
	ServiceName string `json:"service_name,omitempty" yaml:"service_name,omitempty" bson:"service_name,omitempty"`
	Namespace   string `json:"namespace,omitempty" yaml:"namespace,omitempty" bson:"namespace,omitempty"`
}

// SpecFQDN Structure
type SpecFQDN struct {
	MatchNames []string   `json:"matchNames,omitempty" yaml:"matchNames,omitempty" bson:"matchNames,omitempty"`
	ToPorts    []SpecPort `json:"toPorts,omitempty" yaml:"toPorts,omitempty" bson:"toPorts,omitempty"`
}

// SpecHTTP Structure
type SpecHTTP struct {
	Method string `json:"method,omitempty" yaml:"method,omitempty" bson:"method,omitempty"`
	Path   string `json:"path,omitempty" yaml:"path,omitempty" bson:"path,omitempty"`
}

// Selector Structure
type Selector struct {
	MatchLabels map[string]string `json:"matchLabels,omitempty" yaml:"matchLabels,omitempty" bson:"matchLabels,omitempty"`
}

// Ingress Structure
type Ingress struct {
	MatchLabels map[string]string `json:"matchLabels,omitempty" yaml:"matchLabels,omitempty" bson:"matchLabels,omitempty"`

	FromCIDRs    []SpecCIDR `json:"fromCIDRs,omitempty" yaml:"fromCIDRs,omitempty" bson:"fromCIDRs,omitempty"`
	FromEntities []string   `json:"fromEntities,omitempty" yaml:"fromEntities,omitempty" bson:"fromEntities,omitempty"`

	ToPorts []SpecPort `json:"toPorts,omitempty" yaml:"toPorts,omitempty" bson:"toPorts,omitempty"`
}

// Egress Structure
type Egress struct {
	MatchLabels map[string]string `json:"matchLabels,omitempty" yaml:"matchLabels,omitempty" bson:"matchLabels,omitempty"`

	ToCIDRs     []SpecCIDR `json:"toCIDRs,omitempty" yaml:"toCIDRs,omitempty" bson:"toCIDRs,omitempty"`
	ToEndtities []string   `json:"toEntities,omitempty" yaml:"toEntities,omitempty" bson:"toEntities,omitempty"`

	ToPorts    []SpecPort    `json:"toPorts,omitempty" yaml:"toPorts,omitempty" bson:"toPorts,omitempty"`
	ToServices []SpecService `json:"toServices,omitempty" yaml:"toServices,omitempty" bson:"toServices,omitempty"`
	ToFQDNs    []SpecFQDN    `json:"toFQDNs,omitempty" yaml:"toFQDNs,omitempty" bson:"toFQDNs,omitempty"`
	ToHTTPs    []SpecHTTP    `json:"toHTTPs,omitempty" yaml:"toHTTPs,omitempty" bson:"toHTTPs,omitempty"`
}

// Spec Structure
type Spec struct {
	Selector Selector `json:"selector,omitempty" yaml:"selector,omitempty" bson:"selector,omitempty"`

	Ingress []Ingress `json:"ingress,omitempty" yaml:"ingress,omitempty" bson:"ingress,omitempty"`
	Egress  []Egress  `json:"egress,omitempty" yaml:"egress,omitempty" bson:"egress,omitempty"`

	Action string `json:"action,omitempty" yaml:"action,omitempty" bson:"action,omitempty"`
}

// KnoxNetworkPolicy Structure
type KnoxNetworkPolicy struct {
	APIVersion    string            `json:"apiVersion,omitempty" yaml:"apiVersion,omitempty" bson:"apiVersion,omitempty"`
	Kind          string            `json:"kind,omitempty" yaml:"kind,omitempty" bson:"kind,omitempty"`
	Metadata      map[string]string `json:"metadata,omitempty" yaml:"metadata,omitempty" bson:"metadata,omitempty"`
	Overlapped    []string          `json:"overlapped,omitempty" yaml:"overlapped,omitempty" bson:"overlapped,omitempty"`
	Spec          Spec              `json:"spec,omitempty" yaml:"spec,omitempty" bson:"spec,omitempty"`
	GeneratedTime int64             `json:"generated_time,omitempty" yaml:"generated_time,omitempty" bson:"generated_time,omitempty"`
}

// =========================== //
// == Cilium Network Policy == //
// =========================== //

// CiliumCIDRSet Structure
type CiliumCIDRSet struct {
	CIDR    []string         `json:"cidr" yaml:"cidr"`
	ToPorts []CiliumPortList `json:"toPorts,omitempty" yaml:"toPorts,omitempty"`
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

	ToCIDRs     []string `json:"toCIDR,omitempty" yaml:"toCIDR,omitempty"`
	ToEndtities []string `json:"toEntities,omitempty" yaml:"toEntities,omitempty"`

	ToPorts    []CiliumPortList `json:"toPorts,omitempty" yaml:"toPorts,omitempty"`
	ToServices []CiliumService  `json:"toServices,omitempty" yaml:"toServices,omitempty"`
	ToFQDNs    []CiliumFQDN     `json:"toFQDNs,omitempty" yaml:"toFQDNs,omitempty"`
}

// CiliumIngress Structure
type CiliumIngress struct {
	FromEndpoints []CiliumEndpoint `json:"fromEndpoints,omitempty" yaml:"fromEndpoints,omitempty"`

	FromCIDRs    []string `json:"fromCIDR,omitempty" yaml:"fromCIDR,omitempty"`
	FromEntities []string `json:"fromEntities,omitempty" yaml:"fromEntities,omitempty"`

	ToPorts []CiliumPortList `json:"toPorts,omitempty" yaml:"toPorts,omitempty"`
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

// ========================== //
// == Service Chain Policy == //
// ========================== //

// ServiceChainSpec Structure
type ServiceChainSpec struct {
	Chains []string `json:"chains,omitempty" yaml:"chains,omitempty"`
}

// ServiceChainPolicy Structure
type ServiceChainPolicy struct {
	UpdatedTime string `json:"updated_time" yaml:"updated_time"`

	ID uint32 `json:"id,omitempty" yaml:"id,omitempty"`

	APIVersion string            `json:"apiVersion,omitempty" yaml:"apiVersion,omitempty"`
	Kind       string            `json:"kind,omitempty" yaml:"kind,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty" yaml:"metadata,omitempty"`
	Priority   int               `json:"priority" yaml:"priority"`
	Spec       ServiceChainSpec  `json:"spec" yaml:"spec"`
}

// =================== //
// == System Policy == //
// =================== //

// Process Structure
type Process struct {
	MatchNames []string `json:"matchNames,omitempty" yaml:"matchNames,omitempty"`
	MatchPaths []string `json:"matchPaths,omitempty" yaml:"matchPaths,omitempty"`
}

// File Structure
type File struct {
	MatchNames       []string `json:"matchNames,omitempty" yaml:"matchNames,omitempty"`
	MatchPaths       []string `json:"matchPaths,omitempty" yaml:"matchPaths,omitempty"`
	MatchDirectories []string `json:"matchDirectories,omitempty" yaml:"matchDirectories,omitempty"`
}

// SystemSpec Structure
type SystemSpec struct {
	Selector Selector `json:"selector" yaml:"selector"`
	Process  Process  `json:"process" yaml:"process"`
	File     File     `json:"file" yaml:"file"`

	Action string `json:"action,omitempty" yaml:"action,omitempty"`
}

// SystemPolicy Structure
type SystemPolicy struct {
	UpdatedTime string `json:"updated_time" yaml:"updated_time"`

	ID uint32 `json:"id,omitempty" yaml:"id,omitempty"`

	APIVersion string            `json:"apiVersion,omitempty" yaml:"apiVersion,omitempty"`
	Kind       string            `json:"kind,omitempty" yaml:"kind,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty" yaml:"metadata,omitempty"`
	Priority   int               `json:"priority" yaml:"priority"`
	Spec       SystemSpec        `json:"spec" yaml:"spec"`

	PolicyType int // set in system monitor
}
