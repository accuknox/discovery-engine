package types

import "time"

// ==================== //
// == Network Policy == //
// ==================== //

// FromCIDR Structure
type FromCIDR struct {
	CIDR   string   `json:"cidr" bson:"cidr"`
	Except []string `json:"except" bson:"except"`
}

// FromPort Structure
type FromPort struct {
	Ports    string `json:"ports" bson:"ports"`
	Protocol string `json:"protocol" bson:"protocol"`
}

// Service Structure
type Service struct {
	Protocol string `json:"protocol" bson:"protocol"`
	IP       string `json:"ip" bson:"ip"`
	Port     int    `json:"port" bson:"port"`
}

// ToCIDR Structure
type ToCIDR struct {
	CIDR   string   `json:"cidr" bson:"cidr"`
	Except []string `json:"except" bson:"except"`
}

// ToPort Structure
type ToPort struct {
	Ports    string `json:"ports,omitempty" bson:"ports,omitempty"`
	Protocol string `json:"protocol" bson:"protocol"`
}

// ToFQDN Structure
type ToFQDN struct {
	Name string `json:"name" bson:"name"`
}

// ToHTTP Structure
type ToHTTP struct {
	Method string `json:"method" bson:"method"`
	Path   string `json:"path" bson:"path"`
}

// PolicyNetwork Structure
type PolicyNetwork struct {
	HostIP string `json:"host_ip" bson:"host_ip"`

	BridgeIP  string `json:"bridge_ip" bson:"bridge_ip"`
	BridgeMac string `json:"bridge_mac" bson:"bridge_mac"`

	IP      string `json:"ip" bson:"ip"`
	Mac     string `json:"mac" bson:"mac"`
	VEthIdx int    `json:"veth_idx" bson:"veth_idx"`
}

// Selector Structure
type Selector struct {
	MatchNames  map[string]string `json:"matchNames,omitempty" bson:"matchNames,omitempty"`
	MatchLabels map[string]string `json:"matchLabels,omitempty" bson:"matchLabels,omitempty"`

	Identities []string        `json:"identities,omitempty" bson:"identities,omitempty"`
	Networks   []PolicyNetwork `json:"networks,omitempty" bson:"networks,omitempty"`
}

// Ingress Structure
type Ingress struct {
	MatchNames  map[string]string `json:"matchNames,omitempty" bson:"matchNames,omitempty"`
	MatchLabels map[string]string `json:"matchLabels,omitempty" bson:"matchLabels,omitempty"`

	Identities []string        `json:"identities,omitempty" bson:"identities,omitempty"`
	Networks   []PolicyNetwork `json:"networks,omitempty" bson:"networks,omitempty"`

	FromCIDRs []FromCIDR `json:"fromCIDRs,omitempty" bson:"fromCIDRs,omitempty"`
	FromPorts []FromPort `json:"fromPorts,omitempty" bson:"fromPorts,omitempty"`
}

// Egress Structure
type Egress struct {
	MatchNames  map[string]string `json:"matchNames,omitempty" bson:"matchNames,omitempty"`
	MatchLabels map[string]string `json:"matchLabels,omitempty" bson:"matchLabels,omitempty"`

	Identities []string        `json:"identities,omitempty" bson:"identities,omitempty"`
	Networks   []PolicyNetwork `json:"networks,omitempty" bson:"networks,omitempty"`
	Services   []Service       `json:"services,omitempty" bson:"services,omitempty"`

	ToCIDRs []ToCIDR `json:"toCIDRs,omitempty" bson:"toCIDRs,omitempty"`
	ToPorts []ToPort `json:"toPorts,omitempty" bson:"toPorts,omitempty"`
	ToFQDNs []ToFQDN `json:"toFQDNs,omitempty" bson:"toFQDNs,omitempty"`
	ToHTTPs []ToHTTP `json:"toHTTPs,omitempty" bson:"toHTTPs,omitempty"`
}

// SSCFunction Structure
type SSCFunction struct {
	FunctionName string         `json:"function_name" bson:"function_name"`
	HostVEths    map[string]int `json:"host_veths" bson:"host_veths"`
}

// Spec Structure
type Spec struct {
	Selector Selector `json:"selector" bson:"selector"`
	Ingress  Ingress  `json:"ingress" bson:"ingress"`
	Egress   Egress   `json:"egress" bson:"egress"`

	SSC          string        `json:"ssc,omitempty" bson:"ssc,omitempty"`
	SSCFunctions []SSCFunction `json:"ssc_functions,omitempty" bson:"ssc_functions,omitempty"`

	Action  string            `json:"action,omitempty" bson:"action,omitempty"`
	Actions map[string]string `json:"actions,omitempty" bson:"actions,omitempty"`
}

// NetworkPolicy Structure
type NetworkPolicy struct {
	UpdatedTime string `json:"updated_time" bson:"updated_time"`

	ID uint32 `json:"id,omitempty" bson:"id,omitempty"`

	APIVersion string            `json:"apiVersion,omitempty" bson:"apiVersion,omitempty"`
	Kind       string            `json:"kind,omitempty" bson:"kind,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty" bson:"metadata,omitempty"`
	Priority   int               `json:"priority" bson:"priority"`
	Spec       Spec              `json:"spec" bson:"spec"`
}

// ========================== //
// == Service Chain Policy == //
// ========================== //

// ServiceChainSpec Structure
type ServiceChainSpec struct {
	Chains []string `json:"chains,omitempty" bson:"chains,omitempty"`
}

// ServiceChainPolicy Structure
type ServiceChainPolicy struct {
	UpdatedTime string `json:"updated_time" bson:"updated_time"`

	ID uint32 `json:"id,omitempty" bson:"id,omitempty"`

	APIVersion string            `json:"apiVersion,omitempty" bson:"apiVersion,omitempty"`
	Kind       string            `json:"kind,omitempty" bson:"kind,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty" bson:"metadata,omitempty"`
	Priority   int               `json:"priority" bson:"priority"`
	Spec       ServiceChainSpec  `json:"spec" bson:"spec"`
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
	MatchNames []string `json:"matchNames,omitempty" bson:"matchNames,omitempty"`
	MatchPaths []string `json:"matchPaths,omitempty" bson:"matchPaths,omitempty"`
}

// File Structure
type File struct {
	MatchNames       []string `json:"matchNames,omitempty" bson:"matchNames,omitempty"`
	MatchPaths       []string `json:"matchPaths,omitempty" bson:"matchPaths,omitempty"`
	MatchDirectories []string `json:"matchDirectories,omitempty" bson:"matchDirectories,omitempty"`
}

// SystemSpec Structure
type SystemSpec struct {
	Selector Selector `json:"selector" bson:"selector"`
	Process  Process  `json:"process" bson:"process"`
	File     File     `json:"file" bson:"file"`

	Action string `json:"action,omitempty" bson:"action,omitempty"`
}

// SystemPolicy Structure
type SystemPolicy struct {
	UpdatedTime string `json:"updated_time" bson:"updated_time"`

	ID uint32 `json:"id,omitempty" bson:"id,omitempty"`

	APIVersion string            `json:"apiVersion,omitempty" bson:"apiVersion,omitempty"`
	Kind       string            `json:"kind,omitempty" bson:"kind,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty" bson:"metadata,omitempty"`
	Priority   int               `json:"priority" bson:"priority"`
	Spec       SystemSpec        `json:"spec" bson:"spec"`

	PolicyType int // set in system monitor
}

// ==================== //
// == Runtime Policy == //
// ==================== //

// RuntimeProcess Structure
type RuntimeProcess struct {
	MatchPaths []string `json:"matchPaths,omitempty" bson:"matchPaths,omitempty"`
}

// RuntimeFile Structure
type RuntimeFile struct {
	MatchPaths       []string `json:"matchPaths,omitempty" bson:"matchPaths,omitempty"`
	MatchDirectories []string `json:"matchDirectories,omitempty" bson:"matchDirectories,omitempty"`
}

// RuntimeSpec Structure
type RuntimeSpec struct {
	Selector Selector       `json:"selector" bson:"selector"`
	Process  RuntimeProcess `json:"process" bson:"process"`
	File     RuntimeFile    `json:"file" bson:"file"`

	Action string `json:"action,omitempty" bson:"action,omitempty"`
}

// RuntimePolicy Structure
type RuntimePolicy struct {
	UpdatedTime string `json:"updated_time" bson:"updated_time"`

	ID string `json:"id,omitempty" bson:"id,omitempty"`

	APIVersion string            `json:"apiVersion,omitempty" bson:"apiVersion,omitempty"`
	Kind       string            `json:"kind,omitempty" bson:"kind,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty" bson:"metadata,omitempty"`
	Priority   int               `json:"priority" bson:"priority"`
	Spec       RuntimeSpec       `json:"spec" bson:"spec"`
}

// ====================== //
// == AppArmor Profile == //
// ====================== //

// AppArmorProfile Structure
type AppArmorProfile struct {
	Name           string `json:"profile_name" bson:"profile_name"`
	ReferenceCount int    `json:"reference_count" bson:"reference_count"`
}

// =================== //
// == Suricata Rule == //
// =================== //

// SuricataRule Structure
type SuricataRule struct {
	ID   string `json:"id,omitempty" bson:"id,omitempty"`
	Rule string `json:"rule,omitempty" bson:"rule,omitempty"`
}
