package types

// KnoxEventType Structure
type KnoxEventType struct {
	Type    int64 `json:"type,omitempty"`
	SubType int64 `json:"sub_type,omitempty"`
}

// KnoxUDP Structure
type KnoxUDP struct {
	SourcePort      int64 `json:"source_port,omitempty"`
	DestinationPort int64 `json:"destination_port,omitempty"`
}

// KnoxTCP Structure
type KnoxTCP struct {
	Flags           map[string]bool `json:"flags,omitempty"`
	SourcePort      int64           `json:"source_port,omitempty"`
	DestinationPort int64           `json:"destination_port,omitempty"`
}

// KnoxL4 Structure
type KnoxL4 struct {
	TCP KnoxTCP `json:"TCP,omitempty"`
	UDP KnoxUDP `json:"UDP,omitempty"`
}

// KnoxService Structure
type KnoxService struct {
	Name      string `json:"pod_name,omitempty"`
	Namespace string `json:"namespace,omitempty"`
}

// KnoxEndpoint Structure
type KnoxEndpoint struct {
	Labelds   []string `json:"labels,omitempty"`
	Identity  int64    `json:"identity,omitempty"`
	PodName   string   `json:"pod_name,omitempty"`
	Namespace string   `json:"namespace,omitempty"`
}

// KnoxIP Structure
type KnoxIP struct {
	Source      string `json:"source,omitempty"`
	Destination string `json:"destination,omitempty"`
}

// KnoxEthernet Structure
type KnoxEthernet struct {
	Source      string `json:"source,omitempty"`
	Destination string `json:"destination,omitempty"`
}

// NetworkTraffic Structure
type NetworkTraffic struct {
	ID   int    `json:"id,omitempty"`
	Time string `json:"time,omitempty"`

	Verdict    string `json:"verdict,omitempty"` // 1: FORWARDED
	DropReason int    `json:"drop_reason,omitempty"`

	Ethernet KnoxEthernet           `json:"ethernet,omitempty"`
	IP       KnoxIP                 `json:"ip,omitempty"`
	L4       KnoxL4                 `json:"l4,omitempty"`
	L7       map[string]interface{} `json:"l7,omitempty"`

	Reply int `json:"reply,omitempty"`

	Source      KnoxEndpoint `json:"source,omitempty"`
	Destination KnoxEndpoint `json:"destination,omitempty"`

	Type int `json:"type,omitempty"`

	SrcClusterName string        `json:"src_cluster_name,omitempty"`
	DstClusterName string        `json:"dest_cluster_name,omitempty"`
	SrcPodName     string        `json:"src_pod_name,omitempty"`
	DstPodName     string        `json:"dest_pod_name,omitempty"`
	NodeName       string        `json:"node_name,omitempty"`
	EventType      KnoxEventType `json:"event_type,omitempty"`

	SourceService      KnoxService `json:"source_service,omitempty"`
	DestinationService KnoxService `json:"destination_service,omitempty"`

	TrafficDirection      int `json:"traffic_direction,omitempty"` // 1: INGRESS, 2: EGRESS (0: OVERAY?)
	PolicyMatchType       int `json:"policy_match_type,omitempty"`
	TraceObservationPoint int `json:"trace_observation_point,omitempty"` // 101: TO_ENDPOINT, 4: TO_OVERLAY

	Summary string `json:"summary,omitempty"`
}
