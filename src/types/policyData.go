package types

import kyvernov1 "github.com/kyverno/kyverno/api/kyverno/v1"

// LabelMap stores the label of an endpoint
type LabelMap = map[string]string

// ========================= //
// == Knox Network Policy == //
// ========================= //

// SpecCIDR Structure
type SpecCIDR struct {
	CIDRs  []string `json:"cidrs,omitempty" yaml:"cidrs,omitempty" bson:"cidrs,omitempty"`
	Except []string `json:"except,omitempty" yaml:"except,omitempty" bson:"except,omitempty"`
}

// SpecICMP Structure
type SpecICMP struct {
	Family string `json:"family,omitempty" yaml:"family,omitempty" bson:"family,omitempty"`
	Type   uint8  `json:"type" yaml:"type,omitempty" bson:"type,omitempty"`
}

func (x SpecICMP) Equal(y SpecICMP) bool {
	return x.Family == y.Family && x.Type == y.Type
}

// SpecPort Structure
type SpecPort struct {
	Port     string `json:"port,omitempty" yaml:"port,omitempty" bson:"port,omitempty"`
	Protocol string `json:"protocol,omitempty" yaml:"protocol,omitempty" bson:"protocol,omitempty"`
}

func (x SpecPort) Equal(y SpecPort) bool {
	return x.Port == y.Port && x.Protocol == y.Protocol
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
	ICMPs       []SpecICMP        `json:"icmps,omitempty" yaml:"icmps,omitempty" bson:"icmps,omitempty"`
	ToPorts     []SpecPort        `json:"toPorts,omitempty" yaml:"toPorts,omitempty" bson:"toPorts,omitempty"`
	ToHTTPs     []SpecHTTP        `json:"toHTTPs,omitempty" yaml:"toHTTPs,omitempty" bson:"toHTTPs,omitempty"`

	FromCIDRs    []SpecCIDR `json:"fromCIDRs,omitempty" yaml:"fromCIDRs,omitempty" bson:"fromCIDRs,omitempty"`
	FromEntities []string   `json:"fromEntities,omitempty" yaml:"fromEntities,omitempty" bson:"fromEntities,omitempty"`
}

// Egress Structure
type Egress struct {
	MatchLabels map[string]string `json:"matchLabels,omitempty" yaml:"matchLabels,omitempty" bson:"matchLabels,omitempty"`
	ICMPs       []SpecICMP        `json:"icmps,omitempty" yaml:"icmps,omitempty" bson:"icmps,omitempty"`
	ToPorts     []SpecPort        `json:"toPorts,omitempty" yaml:"toPorts,omitempty" bson:"toPorts,omitempty"`

	ToCIDRs    []SpecCIDR    `json:"toCIDRs,omitempty" yaml:"toCIDRs,omitempty" bson:"toCIDRs,omitempty"`
	ToEntities []string      `json:"toEntities,omitempty" yaml:"toEntities,omitempty" bson:"toEntities,omitempty"`
	ToServices []SpecService `json:"toServices,omitempty" yaml:"toServices,omitempty" bson:"toServices,omitempty"`
	ToFQDNs    []SpecFQDN    `json:"toFQDNs,omitempty" yaml:"toFQDNs,omitempty" bson:"toFQDNs,omitempty"`
	ToHTTPs    []SpecHTTP    `json:"toHTTPs,omitempty" yaml:"toHTTPs,omitempty" bson:"toHTTPs,omitempty"`
}

type L47Rule interface {
	GetICMPRules() []SpecICMP
	GetPortRules() []SpecPort
	GetHTTPRules() []SpecHTTP
}

func (x Ingress) GetICMPRules() []SpecICMP {
	return x.ICMPs
}

func (x Ingress) GetPortRules() []SpecPort {
	return x.ToPorts
}

func (x Ingress) GetHTTPRules() []SpecHTTP {
	return x.ToHTTPs
}

func (x Egress) GetICMPRules() []SpecICMP {
	return x.ICMPs
}

func (x Egress) GetPortRules() []SpecPort {
	return x.ToPorts
}

func (x Egress) GetHTTPRules() []SpecHTTP {
	return x.ToHTTPs
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
	FlowIDs    []int             `json:"flow_ids,omitempty" yaml:"flow_ids,omitempty" bson:"flow_ids,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty" yaml:"metadata,omitempty" bson:"metadata,omitempty"`
	Outdated   string            `json:"outdated,omitempty" yaml:"outdated,omitempty" bson:"outdated,omitempty"`

	Spec Spec `json:"spec,omitempty" yaml:"spec,omitempty" bson:"spec,omitempty"`

	GeneratedTime int64 `json:"generatedTime,omitempty" yaml:"generatedTime,omitempty" bson:"generatedTime,omitempty"`
	UpdatedTime   int64 `json:"updatedTime,omitempty" yaml:"updatedTime,omitempty" bson:"updatedTime,omitempty"`
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

// CiliumICMP Structure
type CiliumICMP struct {
	Fields []CiliumICMPField `json:"fields,omitempty" yaml:"fields,omitempty"`
}

// CiliumICMPField Structure
type CiliumICMPField struct {
	Family string `json:"family,omitempty" yaml:"family,omitempty"`
	Type   uint8  `json:"type" yaml:"type,omitempty"`
}

// CiliumEgress Structure
type CiliumEgress struct {
	ToEndpoints []CiliumEndpoint `json:"toEndpoints,omitempty" yaml:"toEndpoints,omitempty"`
	ToPorts     []CiliumPortList `json:"toPorts,omitempty" yaml:"toPorts,omitempty"`
	ICMPs       []CiliumICMP     `json:"icmps,omitempty" yaml:"icmps,omitempty"`
	ToCIDRs     []string         `json:"toCIDR,omitempty" yaml:"toCIDR,omitempty"`
	ToEntities  []string         `json:"toEntities,omitempty" yaml:"toEntities,omitempty"`
	ToServices  []CiliumService  `json:"toServices,omitempty" yaml:"toServices,omitempty"`
	ToFQDNs     []CiliumFQDN     `json:"toFQDNs,omitempty" yaml:"toFQDNs,omitempty"`
}

// CiliumIngress Structure
type CiliumIngress struct {
	FromEndpoints []CiliumEndpoint `json:"fromEndpoints,omitempty" yaml:"fromEndpoints,omitempty"`
	ToPorts       []CiliumPortList `json:"toPorts,omitempty" yaml:"toPorts,omitempty"`
	ICMPs         []CiliumICMP     `json:"icmps,omitempty" yaml:"icmps,omitempty"`
	FromCIDRs     []string         `json:"fromCIDR,omitempty" yaml:"fromCIDR,omitempty"`
	FromEntities  []string         `json:"fromEntities,omitempty" yaml:"fromEntities,omitempty"`
}

// CiliumSpec Structure
type CiliumSpec struct {
	NodeSelector     Selector `json:"nodeSelector,omitempty" yaml:"nodeSelector,omitempty"`
	EndpointSelector Selector `json:"endpointSelector,omitempty" yaml:"endpointSelector,omitempty"`

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

// ======================== //
// == Knox System Policy == //
// ======================== //

// KnoxFromSource Structure
type KnoxFromSource struct {
	Path string `json:"path,omitempty" yaml:"path,omitempty"`
	Dir  string `json:"dir,omitempty" yaml:"dir,omitempty"`
}

// KnoxMatchPaths Structure
type KnoxMatchPaths struct {
	Path       string           `json:"path,omitempty" yaml:"path,omitempty"`
	ReadOnly   bool             `json:"readOnly,omitempty" yaml:"readOnly,omitempty"`
	OwnerOnly  bool             `json:"ownerOnly,omitempty" yaml:"ownerOnly,omitempty"`
	FromSource []KnoxFromSource `json:"fromSource,omitempty" yaml:"fromSource,omitempty"`
}

// KnoxMatchDirectories Structure
type KnoxMatchDirectories struct {
	Dir        string           `json:"dir,omitempty" yaml:"dir,omitempty"`
	Recursive  bool             `json:"recursive,omitempty" yaml:"recursive,omitempty"`
	ReadOnly   bool             `json:"readOnly,omitempty" yaml:"readOnly,omitempty"`
	OwnerOnly  bool             `json:"ownerOnly,omitempty" yaml:"ownerOnly,omitempty"`
	FromSource []KnoxFromSource `json:"fromSource,omitempty" yaml:"fromSource,omitempty"`
}

// KnoxMatchProtocols Structure
type KnoxMatchProtocols struct {
	Protocol   string           `json:"protocol,omitempty" yaml:"protocol,omitempty"`
	FromSource []KnoxFromSource `json:"fromSource,omitempty" yaml:"fromSource,omitempty"`
}

// KnoxSys Structure
type KnoxSys struct {
	MatchPaths       []KnoxMatchPaths       `json:"matchPaths,omitempty" yaml:"matchPaths,omitempty"`
	MatchDirectories []KnoxMatchDirectories `json:"matchDirectories,omitempty" yaml:"matchDirectories,omitempty"`
}

// NetworkRule Structure
type NetworkRule struct {
	MatchProtocols []KnoxMatchProtocols `json:"matchProtocols,omitempty" yaml:"matchProtocols,omitempty"`
}

// KnoxSystemSpec Structure
type KnoxSystemSpec struct {
	Severity int      `json:"severity,omitempty" yaml:"severity,omitempty"`
	Tags     []string `json:"tags,omitempty" yaml:"tags,omitempty"`
	Message  string   `json:"message,omitempty" yaml:"message,omitempty"`

	Selector Selector `json:"selector,omitempty" yaml:"selector,omitempty"`

	Process KnoxSys     `json:"process,omitempty" yaml:"process,omitempty"`
	File    KnoxSys     `json:"file,omitempty" yaml:"file,omitempty"`
	Network NetworkRule `json:"network,omitempty" yaml:"network,omitempty"`

	Action string `json:"action,omitempty" yaml:"action,omitempty"`
}

// KnoxSystemPolicy Structure
type KnoxSystemPolicy struct {
	APIVersion string `json:"apiVersion,omitempty" yaml:"apiVersion,omitempty" bson:"apiVersion,omitempty"`
	Kind       string `json:"kind,omitempty" yaml:"kind,omitempty" bson:"kind,omitempty"`
	// LogIDs     []int             `json:"log_ids,omitempty" yaml:"log_ids,omitempty" bson:"log_ids,omitempty"`
	Metadata map[string]string `json:"metadata,omitempty" yaml:"metadata,omitempty" bson:"metadata,omitempty"`
	Outdated string            `json:"outdated,omitempty" yaml:"outdated,omitempty" bson:"outdated,omitempty"`

	Spec KnoxSystemSpec `json:"spec,omitempty" yaml:"spec,omitempty" bson:"spec,omitempty"`

	GeneratedTime int64 `json:"generatedTime,omitempty" yaml:"generatedTime,omitempty" bson:"generatedTime,omitempty"`
	UpdatedTime   int64 `json:"updatedTime,omitempty" yaml:"updatedTime,omitempty" bson:"updatedTime,omitempty"`
	Latest        bool  `json:"latest,omitempty" yaml:"latest,omitempty" bson:"latest,omitempty"`
}

// ============================= //
// == KubeArmor System Policy == //
// ============================= //

// KubeArmorPolicy Structure
type KubeArmorPolicy struct {
	APIVersion string            `json:"apiVersion,omitempty" yaml:"apiVersion,omitempty"`
	Kind       string            `json:"kind,omitempty" yaml:"kind,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty" yaml:"metadata,omitempty"`

	Spec KnoxSystemSpec `json:"spec,omitempty" yaml:"spec,omitempty"`
}

// PolicyFilter is used for GetFlow RPC in Discovery Service.
type PolicyFilter struct {
	Cluster   string
	Namespace string
	Labels    LabelMap
}

// PolicyYaml stores a policy in YAML format along with its metadata
type PolicyYaml struct {
	Type        string   `json:"type,omitempty"`
	Kind        string   `json:"kind,omitempty"`
	Name        string   `json:"name,omitempty"`
	Namespace   string   `json:"namespace,omitempty"`
	Cluster     string   `json:"cluster,omitempty"`
	ClusterId   int32    `json:"cluster_id,omitempty"`
	WorkspaceId int32    `json:"workspace_id,omitempty"`
	Labels      LabelMap `json:"labels,omitempty"`
	Yaml        []byte   `json:"yaml,omitempty"`
}

// ============================= //
// == KubeArmor Recommended Policy == //
// ============================= //

// MatchSpec spec to match for defining policy
type MatchSpec struct {
	Name              string                     `json:"name" yaml:"name"`
	Precondition      []string                   `json:"precondition" yaml:"precondition"`
	Description       Description                `json:"description" yaml:"description"`
	Yaml              string                     `json:"yaml" yaml:"yaml"`
	Spec              KnoxSystemSpec             `json:"spec,omitempty" yaml:"spec,omitempty"`
	Kind              string                     `json:"kind,omitempty" yaml:"kind,omitempty" bson:"kind,omitempty"`
	KyvernoPolicy     *kyvernov1.PolicyInterface `json:"kyvernoPolicy,omitempty" yaml:"kyvernoPolicy,omitempty"`
	KyvernoPolicyTags []string                   `json:"kyvernoPolicyTags,omitempty" yaml:"kyvernoPolicyTags,omitempty"`
}

// Ref for the policy rules
type Ref struct {
	Name string   `json:"name" yaml:"name"`
	URL  []string `json:"url" yaml:"url"`
}

// Description detailed description for the policy rule
type Description struct {
	Refs     []Ref  `json:"refs" yaml:"refs"`
	Tldr     string `json:"tldr" yaml:"tldr"`
	Detailed string `json:"detailed" yaml:"detailed"`
}
