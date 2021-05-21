package types

// KnoxNetworkLog Structure
type KnoxNetworkLog struct {
	FlowID int `json:"flow_id,omitempty" bson:"flow_id"`

	CluserName string `json:"cluster_name,omitempty" bson:"cluster_name"`

	SrcNamespace string `json:"src_namespace,omitempty" bson:"src_namespace"`
	SrcPodName   string `json:"src_pod_name,omitempty" bson:"src_pod_name"`

	DstNamespace string `json:"dst_namespace,omitempty" bson:"dst_namespace"`
	DstPodName   string `json:"dst_pod_name,omitempty" bson:"dst_pod_name"`

	EtherType int `json:"ether_type,omitempty" bson:"ether_type"` // not used, we assume all the ipv4

	Protocol int    `json:"protocol,omitempty" bson:"protocol"`
	SrcIP    string `json:"src_ip,omitempty" bson:"src_ip"`
	DstIP    string `json:"dst_ip,omitempty" bson:"dst_ip"`
	SrcPort  int    `json:"src_port,omitempty" bson:"src_port"`
	DstPort  int    `json:"dst_port,omitempty" bson:"dst_port"`

	SynFlag bool `json:"syn_flag,omitempty" bson:"syn_flag"` // for tcp

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

	HostName  string `json:"host_name,omitempty"`
	Namespace string `json:"namespace_name,omitempty"`
	PodName   string `json:"pod_name,omitempty"`

	Source    string `json:"source,omitempty"`
	Operation string `json:"operation,omitempty"`
	Resource  string `json:"resource,omitempty"`
	Data      string `json:"data,omitempty"`

	Result string `json:"result,omitempty"`
}
