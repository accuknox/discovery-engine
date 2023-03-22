package types

// KnoxNetworkLog Structure
type KnoxNetworkLog struct {
	FlowID int `json:"flow_id,omitempty" bson:"flow_id"`

	ClusterName   string `json:"cluster_name,omitempty" bson:"cluster_name"`
	ContainerName string `json:"container_name,omitempty" bson:"container_name"`

	SrcNamespace      string   `json:"src_namespace,omitempty" bson:"src_namespace"`
	SrcReservedLabels []string `json:"src_reserved_labels,omitempty" bson:"src_reserved_labels"`
	SrcPodName        string   `json:"src_pod_name,omitempty" bson:"src_pod_name"`

	DstNamespace      string   `json:"dst_namespace,omitempty" bson:"dst_namespace"`
	DstReservedLabels []string `json:"dst_reserved_labels,omitempty" bson:"dst_reserved_labels"`
	DstPodName        string   `json:"dst_pod_name,omitempty" bson:"dst_pod_name"`

	EtherType int `json:"ether_type,omitempty" bson:"ether_type"` // not used, we assume all the ipv4

	Protocol int    `json:"protocol,omitempty" bson:"protocol"`
	SrcIP    string `json:"src_ip,omitempty" bson:"src_ip"`
	DstIP    string `json:"dst_ip,omitempty" bson:"dst_ip"`
	SrcPort  int    `json:"src_port,omitempty" bson:"src_port"`
	DstPort  int    `json:"dst_port,omitempty" bson:"dst_port"`
	ICMPType int    `json:"icmp_type,omitempty" bson:"icmp_type"`

	SynFlag bool `json:"syn_flag,omitempty" bson:"syn_flag"` // for tcp
	IsReply bool `json:"is_reply,omitempty" bson:"is_reply"` // is_reply

	L7Protocol string `json:"l7_protocol,omitempty" bson:"l7_protocol"`

	DNSQuery  string   `json:"dns_query,omitempty" bson:"dns_query"`       // for L7 dns
	DNSRes    string   `json:"dns_response,omitempty" bson:"dns_response"` // for L7 dns
	DNSResIPs []string `json:"dns_res_ips,omitempty" bson:"dns_res_ips"`   // for L7 dns

	HTTPMethod string `json:"http_method,omitempty" bson:"http_method"` // for L7 http
	HTTPPath   string `json:"http_path,omitempty" bson:"http_path"`     // for L7 http

	Direction string `json:"direction,omitempty" bson:"direction"` // ingress or egress

	Action string `json:"action,omitempty" bson:"action"`
}

// KnoxSystemLog Structure
type KnoxSystemLog struct {
	LogID int `json:"id,omitempty"`

	ClusterName string `json:"cluster_name,omitempty"`

	HostName      string `json:"host_name,omitempty"`
	Namespace     string `json:"namespace_name,omitempty"`
	ContainerName string `json:"container_name,omitempty"`
	PodName       string `json:"pod_name,omitempty"`

	SourceOrigin string `json:"source_origin,omitempty"` // if source origin "/usr/bin/iperf3 -s -p 5101"
	Source       string `json:"source,omitempty"`        // --> source: "/usr/bin/iperf3"

	Operation string `json:"operation,omitempty"`

	ResourceOrigin string `json:"resource_origin,omitempty"`
	Resource       string `json:"resource,omitempty"`
	Data           string `json:"data,omitempty"`

	ReadOnly bool `json:"read_only,omitempty"`

	Result string `json:"result,omitempty"`
}
