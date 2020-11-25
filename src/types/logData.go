package types

// KnoxNetworkLog Structure
type KnoxNetworkLog struct {
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

	DNSQuery string `json:"dns_query,omitempty" bson:"dns_query"` // for L7 dns

	HTTPMethod string `json:"http_method,omitempty" bson:"http_method"` // for L7 http
	HTTPPath   string `json:"http_path,omitempty" bson:"http_path"`     // for L7 http

	Direction string `json:"direction,omitempty" bson:"direction"` // ingress or egress

	Action string `json:"action,omitempty" bson:"action"`
}
