package types

// KubeArmor - Structure for KubeArmor Logs Flow
type KubeArmor struct {
	ClusterName   string `json:"cluster_name,omitempty"`
	HostName      string `json:"host_name,omitempty"`
	NamespaceName string `json:"namespace_name,omitempty"`
	PodName       string `json:"pod_name,omitempty"`
	ContainerID   string `json:"container_id,omitempty"`
	ContainerName string `json:"container_name,omitempty"`
	UID           int32  `json:"uid,omitempty"`
	Type          string `json:"type,omitempty"`
	Source        string `json:"source,omitempty"`
	Operation     string `json:"operation,omitempty"`
	Resource      string `json:"resource,omitempty"`
	Data          string `json:"data,omitempty"`
	StartTime     int64  `json:"start_time,omitempty"`
	UpdatedTime   int64  `json:"updated_time,omitempty"`
	Result        string `json:"result,omitempty"`
	Total         int64  `json:"total,omitempty"`
}

// Cilium - Structure for Hubble Log Flow
type CiliumLog struct {
	Verdict                     string `json:"verdict,omitempty"`
	IpSource                    string `json:"ip_source,omitempty"`
	IpDestination               string `json:"ip_destination,omitempty"`
	IpVersion                   string `json:"ip_version,omitempty"`
	IpEncrypted                 bool   `json:"ip_encrypted,omitempty"`
	L4TCPSourcePort             uint32 `json:"l4_tcp_source_port,omitempty"`
	L4TCPDestinationPort        uint32 `json:"l4_tcp_destination_port,omitempty"`
	L4UDPSourcePort             uint32 `json:"l4_udp_source_port,omitempty"`
	L4UDPDestinationPort        uint32 `json:"l4_udp_destination_port,omitempty"`
	L4ICMPv4Type                uint32 `json:"l4_icmpv4_type,omitempty"`
	L4ICMPv4Code                uint32 `json:"l4_icmpv4_code,omitempty"`
	L4ICMPv6Type                uint32 `json:"l4_icmpv6_type,omitempty"`
	L4ICMPv6Code                uint32 `json:"l4_icmpv6_code,omitempty"`
	SourceNamespace             string `json:"source_namespace,omitempty"`
	SourceLabels                string `json:"source_labels,omitempty"`
	SourcePodName               string `json:"source_pod_name,omitempty"`
	DestinationNamespace        string `json:"destination_namespace,omitempty"`
	DestinationLabels           string `json:"destination_labels,omitempty"`
	DestinationPodName          string `json:"destination_pod_name,omitempty"`
	Type                        string `json:"type,omitempty"`
	NodeName                    string `json:"node_name,omitempty"`
	L7Type                      string `json:"l7_type,omitempty"`
	L7DnsCnames                 string `json:"l7_dns_cnames,omitempty"`
	L7DnsObservationsource      string `json:"l7_dns_observation_source,omitempty"`
	L7HttpCode                  uint32 `json:"l7_http_code,omitempty"`
	L7HttpMethod                string `json:"l7_http_method,omitempty"`
	L7HttpUrl                   string `json:"l7_http_url,omitempty"`
	L7HttpProtocol              string `json:"l7_http_protocol,omitempty"`
	L7HttpHeaders               string `json:"l7_http_headers,omitempty"`
	EventTypeType               int32  `json:"event_type_type,omitempty"`
	EventTypeSubType            int32  `json:"event_type_sub_type,omitempty"`
	SourceServiceName           string `json:"source_service_name,omitempty"`
	SourceServiceNamespace      string `json:"source_service_namespace,omitempty"`
	DestinationServiceName      string `json:"destination_service_name,omitempty"`
	DestinationServiceNamespace string `json:"destination_service_namespace,omitempty"`
	TrafficDirection            string `json:"traffic_direction,omitempty"`
	TraceObservationPoint       string `json:"trace_observation_point,omitempty"`
	DropReasonDesc              string `json:"drop_reason_desc,omitempty"`
	IsReply                     bool   `json:"is_reply,omitempty"`
	StartTime                   int64  `json:"start_time,omitempty"`
	UpdatedTime                 int64  `json:"updated_time,omitempty"`
	Total                       int64  `json:"total,omitempty"`
}

type KubeArmorFilter struct {
	Operation []string `json:"Operation"`
	Namespace string   `json:"Namespace"`
}

type CiliumFilter struct {
	Type      string `json:"Type"`
	Verdict   string `json:"Verdict"`
	Direction string `json:"Direction"`
}

type NetworkSummary struct {
	Verdict              string `json:"Verdict,omitempty"`
	DestinationLabels    string `json:"DestinationLabels,omitempty"`
	DestinationNamespace string `json:"DestinationNamespace,omitempty"`
	Type                 string `json:"Type,omitempty"`
	L4TCPSourcePort      uint32 `json:"L4TCPSourcePort,omitempty"`
	L4TCPDestinationPort uint32 `json:"L4TCPDestinationPort,omitempty"`
	L4UDPSourcePort      uint32 `json:"L4UDPSourcePort,omitempty"`
	L4UDPDestinationPort uint32 `json:"L4UDPDestinationPort,omitempty"`
	L4ICMPv4Code         uint32 `json:"L4ICMPv4Code,omitempty"`
	L4ICMPv6Code         uint32 `json:"L4ICMPv6Code,omitempty"`
	L7DnsCnames          string `json:"L7DnsCnames,omitempty"`
	L7HttpMethod         string `json:"L7HttpMethod,omitempty"`
	TrafficDirection     string `json:"TrafficDirection,omitempty"`
	UpdatedTime          int64  `json:"UpdatedTime,omitempty"`
	Count                int32  `json:"Count,omitempty"`
}
type Workload struct {
	Type string `json:"Type,omitempty"`
	Name string `json:"Name,omitempty"`
}

type SystemSummary struct {
	ClusterName    string   `json:"ClusterName,omitempty"`
	ClusterId      int32    `json:"ClusterId,omitempty"`
	NamespaceName  string   `json:"Namespace,omitempty"`
	NamespaceId    int32    `json:"NamespaceId,omitempty"`
	ContainerName  string   `json:"ContainerName,omitempty"`
	ContainerImage string   `json:"ContainerImage,omitempty"`
	ContainerID    string   `json:"ContainerID,omitempty"`
	PodName        string   `json:"PodName,omitempty"`
	PodId          int32    `json:"PodId,omitempty"`
	Operation      string   `json:"Operation,omitempty"`
	Labels         string   `json:"Labels,omitempty"`
	Deployment     string   `json:"Deployment,omitempty"`
	Source         string   `json:"Source,omitempty"`
	Destination    string   `json:"Resource,omitempty"`
	DestNamespace  string   `json:"DestNamespace,omitempty"`
	DestLabels     string   `json:"DestLabels,omitempty"`
	NwType         string   `json:"Type,omitempty"`
	IP             string   `json:"IP,omitempty"`
	Port           int32    `json:"Port,omitempty"`
	Protocol       string   `json:"Protocol,omitempty"`
	Action         string   `json:"Action,omitempty"`
	Count          int32    `json:"Count,omitempty"`
	UpdatedTime    int64    `json:"UpdatedTime,omitempty"`
	WorkspaceId    int32    `json:"WorkspaceId,omitempty"`
	BindPort       string   `json:"BindPort,omitempty"`
	BindAddress    string   `json:"BindAddress,omitempty"`
	Severity       string   `json:"Severity,omitempty"`
	Tags           string   `json:"Tags,omitempty"`
	Message        string   `json:"Message,omitempty"`
	Enforcer       string   `json:"Enforcer,omitempty"`
	PolicyName     string   `json:"PolicyName,omitempty"`
	Workload       Workload `json:"Workload,omitempty"`
}

type SysSummaryTimeCount struct {
	Count       int32 `json:"Count,omitempty"`
	UpdatedTime int64 `json:"UpdatedTime,omitempty"`
}

type KubeArmorLog struct {
	Timestamp         int64  `json:"Timestamp,omitempty"`
	UpdatedTime       int64  `json:"UpdatedTime,omitempty"`
	ClusterName       string `json:"ClusterName,omitempty"`
	HostName          string `json:"HostName,omitempty"`
	NamespaceName     string `json:"NamespaceName,omitempty"`
	PodName           string `json:"PodName,omitempty"`
	Labels            string `json:"Labels,omitempty"`
	ContainerID       string `json:"ContainerID,omitempty"`
	ContainerName     string `json:"ContainerName,omitempty"`
	ContainerImage    string `json:"ContainerImage,omitempty"`
	ParentProcessName string `json:"ParentProcessName,omitempty"`
	ProcessName       string `json:"ProcessName,omitempty"`
	HostPPID          int32  `json:"HostPPID,omitempty"`
	HostPID           int32  `json:"HostPID,omitempty"`
	PPID              int32  `json:"PPID,omitempty"`
	PID               int32  `json:"PID,omitempty"`
	UID               int32  `json:"UID,omitempty"`
	Type              string `json:"Type,omitempty"`
	Source            string `json:"Source,omitempty"`
	Operation         string `json:"Operation,omitempty"`
	Resource          string `json:"Resource,omitempty"`
	Data              string `json:"Data,omitempty"`
	Action            string `json:"Action,omitempty"`
	Result            string `json:"Result,omitempty"`
	Category          string `json:"Category,omitempty"`
}

// NEW DATA
// ObsPodDetail -- Type to store observability Pod info/detail
type ObsPodDetail struct {
	PodName       string
	Namespace     string
	ClusterName   string
	ContainerName string
	Labels        string
	DeployName    string
}

type SysObsProcFileData struct {
	Source      string
	Destination string
	Status      string
	Count       uint32
	UpdatedTime string
}

type SysObsNwData struct {
	NetType     string
	Protocol    string
	Command     string
	PodSvcIP    string
	ServerPort  string
	Namespace   string
	Labels      string
	Count       uint32
	UpdatedTime string
	BindPort    string
	BindAddress string
}

type NwObsIngressEgressData struct {
	SrcPodName           string
	DestPodName          string
	DestinationNamespace string
	DestinationLabel     string
	Protocol             string
	Port                 string
	Status               string
	Count                string
	UpdatedTime          string
}

type SysObsProcFileMapKey struct {
	Source      string
	Destination string
	Status      string
}

type SysObsProcFileMapValue struct {
	Count       uint32
	UpdatedTime string
}

type BindPortConnectionData struct {
	SysBind     string
	Protocol    string
	Command     string
	PodSvcIP    string
	BindPort    string
	BindAddress string
	Namespace   string
	Labels      string
	Count       uint32
	UpdatedTime string
}
