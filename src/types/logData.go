package types

// NetworkLog Structure
type NetworkLog struct {
	SrcMicroserviceName   string `json:"src_microservice_name,omitempty" bson:"src_microservice_name"`
	SrcContainerGroupName string `json:"src_container_group_name,omitempty" bson:"src_container_group_name"`

	DstMicroserviceName   string `json:"dst_microservice_name,omitempty" bson:"dst_microservice_name"`
	DstContainerGroupName string `json:"dst_container_group_name,omitempty" bson:"dst_container_group_name"`

	EtherType int `json:"ether_type,omitempty" bson:"ether_type"` // not used, we assume ipv4

	SrcMac string `json:"src_mac,omitempty" bson:"src_mac"`
	DstMac string `json:"dst_mac,omitempty" bson:"dst_mac"`

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
	Action    string `json:"action,omitempty" bson:"action"`
}
