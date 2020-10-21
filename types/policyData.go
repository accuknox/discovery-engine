package types

import "time"

// ==================== //
// == Network Policy == //
// ==================== //

// FromCIDR Structure
type FromCIDR struct {
	CIDR   string   `json:"cidr" yaml:"cidr"`
	Except []string `json:"except" yaml:"except"`
}

// FromPort Structure
type FromPort struct {
	Ports    string `json:"ports" yaml:"ports"`
	Protocol string `json:"protocol" yaml:"protocol"`
}

// Service Structure
type Service struct {
	Protocol string `json:"protocol" yaml:"protocol"`
	IP       string `json:"ip" yaml:"ip"`
	Port     int    `json:"port" yaml:"port"`
}

// ToCIDR Structure
type ToCIDR struct {
	CIDR   string   `json:"cidr" yaml:"cidr"`
	Except []string `json:"except,omitempty" yaml:"except,omitempty"`
}

// ToPort Structure
type ToPort struct {
	Ports    string `json:"ports,omitempty" yaml:"ports,omitempty"`
	Protocol string `json:"protocol" yaml:"protocol"`
}

// ToFQDN Structure
type ToFQDN struct {
	Name string `json:"name" yaml:"name"`
}

// ToHTTP Structure
type ToHTTP struct {
	Method string `json:"method" yaml:"method"`
	Path   string `json:"path" yaml:"path"`
}

// PolicyNetwork Structure
type PolicyNetwork struct {
	HostIP string `json:"host_ip" yaml:"host_ip"`

	BridgeIP  string `json:"bridge_ip" yaml:"bridge_ip"`
	BridgeMac string `json:"bridge_mac" yaml:"bridge_mac"`

	IP      string `json:"ip" yaml:"ip"`
	Mac     string `json:"mac" yaml:"mac"`
	VEthIdx int    `json:"veth_idx" yaml:"veth_idx"`
}

// Selector Structure
type Selector struct {
	MatchNames  map[string]string `json:"matchNames,omitempty" yaml:"matchNames,omitempty"`
	MatchLabels map[string]string `json:"matchLabels,omitempty" yaml:"matchLabels,omitempty"`

	Identities []string        `json:"identities,omitempty" yaml:"identities,omitempty"`
	Networks   []PolicyNetwork `json:"networks,omitempty" yaml:"networks,omitempty"`
}

// Ingress Structure
type Ingress struct {
	MatchLabels map[string]string `json:"matchLabels,omitempty" yaml:"matchLabels,omitempty"`

	FromEntities []string `json:"fromEntities,omitempty" yaml:"fromEntities,omitempty"`

	FromCIDRs []FromCIDR `json:"fromCIDRs,omitempty" yaml:"fromCIDRs,omitempty"`
	FromPorts []FromPort `json:"fromPorts,omitempty" yaml:"fromPorts,omitempty"`
}

// Egress Structure
type Egress struct {
	MatchLabels map[string]string `json:"matchLabels,omitempty" yaml:"matchLabels,omitempty"`

	ToEndtities []string `json:"toEntities,omitempty" yaml:"toEntities,omitempty"`

	ToCIDRs []ToCIDR `json:"toCIDRs,omitempty" yaml:"toCIDRs,omitempty"`
	ToPorts []ToPort `json:"toPorts,omitempty" yaml:"toPorts,omitempty"`
	ToFQDNs []ToFQDN `json:"toFQDNs,omitempty" yaml:"toFQDNs,omitempty"`
	ToHTTPs []ToHTTP `json:"toHTTPs,omitempty" yaml:"toHTTPs,omitempty"`
}

// SSCFunction Structure
type SSCFunction struct {
	FunctionName string         `json:"function_name" yaml:"function_name"`
	HostVEths    map[string]int `json:"host_veths" yaml:"host_veths"`
}

// Spec Structure
type Spec struct {
	Selector Selector `json:"selector,omitempty" yaml:"selector,omitempty"`
	Ingress  Ingress  `json:"ingress,omitempty" yaml:"ingress,omitempty"`
	Egress   Egress   `json:"egress,omitempty" yaml:"egress,omitempty"`

	Action string `json:"action,omitempty" yaml:"action,omitempty"`
}

// KnoxNetworkPolicy Structure
type KnoxNetworkPolicy struct {
	APIVersion string            `json:"apiVersion,omitempty" yaml:"apiVersion,omitempty"`
	Kind       string            `json:"kind,omitempty" yaml:"kind,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty" yaml:"metadata,omitempty"`
	Spec       Spec              `json:"spec" yaml:"spec"`
}

// =========================== //
// == Cilium Network Policy == //
// =========================== //

// CiliumCIDRSet Structure
type CiliumCIDRSet struct {
	CIDR   string   `json:"cidr" yaml:"cidr"`
	Except []string `json:"except,omitempty" yaml:"except,omitempty"`
}

// CiliumPort Structure
type CiliumPort struct {
	Port     string `json:"port,omitempty" yaml:"port,omitempty"`
	Protocol string `json:"protocol" yaml:"protocol"`
}

// CiliumPortList Structure
type CiliumPortList struct {
	Ports []CiliumPort `json:"ports,omitempty" yaml:"ports,omitempty"`
}

// CiliumEndpoints Structure
type CiliumEndpoints struct {
	MatchLabels map[string]string `json:"matchLabels,omitempty" yaml:"matchLabels,omitempty"`
}

// CiliumEgress Structure
type CiliumEgress struct {
	ToEndpoints []CiliumEndpoints `json:"toEndpoints,omitempty" yaml:"toEndpoints,omitempty"`
	ToEndtities []string          `json:"toEntities,omitempty" yaml:"toEntities,omitempty"`

	ToPorts []CiliumPortList `json:"toPorts,omitempty" yaml:"toPorts,omitempty"`
	ToCIDRs []string         `json:"toCIDRs,omitempty" yaml:"toCIDRs,omitempty"`
}

// CiliumIngress Structure
type CiliumIngress struct {
	FromEndpoints []CiliumEndpoints `json:"fromEndpoints,omitempty" yaml:"fromEndpoints,omitempty"`
	FromEntities  []string          `json:"fromEntities,omitempty" yaml:"fromEntities,omitempty"`

	FromPorts []CiliumPortList `json:"fromPorts,omitempty" yaml:"fromPorts,omitempty"`
	FromCIDRs []string         `json:"fromCIDRs,omitempty" yaml:"fromCIDRs,omitempty"`
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

// host pid -> process node
type PidMap map[uint32]PidNode

// PidNode Structure
type PidNode struct {
	Policy SystemPolicy

	PidId uint32
	MntId uint32

	HostPid uint32
	Ppid    uint32
	Pid     uint32
	Tid     uint32

	Comm     string
	ExecPath string

	EventId   uint32
	Monitored bool

	Exited     bool
	ExitedTime time.Time
}

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

// ==================== //
// == Runtime Policy == //
// ==================== //

// RuntimeProcess Structure
type RuntimeProcess struct {
	MatchPaths []string `json:"matchPaths,omitempty" yaml:"matchPaths,omitempty"`
}

// RuntimeFile Structure
type RuntimeFile struct {
	MatchPaths       []string `json:"matchPaths,omitempty" yaml:"matchPaths,omitempty"`
	MatchDirectories []string `json:"matchDirectories,omitempty" yaml:"matchDirectories,omitempty"`
}

// RuntimeSpec Structure
type RuntimeSpec struct {
	Selector Selector       `json:"selector" yaml:"selector"`
	Process  RuntimeProcess `json:"process" yaml:"process"`
	File     RuntimeFile    `json:"file" yaml:"file"`

	Action string `json:"action,omitempty" yaml:"action,omitempty"`
}

// RuntimePolicy Structure
type RuntimePolicy struct {
	UpdatedTime string `json:"updated_time" yaml:"updated_time"`

	ID string `json:"id,omitempty" yaml:"id,omitempty"`

	APIVersion string            `json:"apiVersion,omitempty" yaml:"apiVersion,omitempty"`
	Kind       string            `json:"kind,omitempty" yaml:"kind,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty" yaml:"metadata,omitempty"`
	Priority   int               `json:"priority" yaml:"priority"`
	Spec       RuntimeSpec       `json:"spec" yaml:"spec"`
}

// ====================== //
// == AppArmor Profile == //
// ====================== //

// AppArmorProfile Structure
type AppArmorProfile struct {
	Name           string `json:"profile_name" yaml:"profile_name"`
	ReferenceCount int    `json:"reference_count" yaml:"reference_count"`
}

// =================== //
// == Suricata Rule == //
// =================== //

// SuricataRule Structure
type SuricataRule struct {
	ID   string `json:"id,omitempty" yaml:"id,omitempty"`
	Rule string `json:"rule,omitempty" yaml:"rule,omitempty"`
}
