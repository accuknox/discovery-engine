package types

// BridgeMap Structure
type BridgeMap struct {
	BridgeName string   `json:"bridge_name" bson:"bridge_name"`
	IP         string   `json:"ip" bson:"ip"`
	Mac        string   `json:"mac" bson:"mac"`
	CIDRbits   int      `json:"cidr_bits" bson:"cidr_bits"`
	Index      int      `json:"idx" bson:"idx"`
	Interfaces []string `json:"interfaces" bson:"interfaces"`
}

// Interface Structure
type Interface struct {
	InterfaceName string `json:"interface_name" bson:"interface_name"`
	Mac           string `json:"mac" bson:"mac"`
}

// NetworkMap Structure
type NetworkMap struct {
	MicroserviceName   string   `json:"microservice_name" bson:"microservice_name"`
	ContainerGroupName string   `json:"container_group_name" bson:"container_group_name"`
	Identities         []string `json:"identities" bson:"identities"`

	IP      string `json:"ip" bson:"ip"`
	Mac     string `json:"mac" bson:"mac"`
	VEthIdx int    `json:"veth_idx" bson:"veth_idx"`

	BridgeIP  string `json:"bridge_ip" bson:"bridge_ip"`
	BridgeMac string `json:"bridge_mac" bson:"bridge_mac"`

	HostIP string `json:"host_ip" bson:"host_ip"`
}

// SecurityStack Structure
type SecurityStack struct {
	MicroserviceName   string `json:"microservice_name" bson:"microservice_name"`
	ContainerGroupName string `json:"container_group_name" bson:"container_group_name"`

	Status string `json:"status" bson:"status"`

	HostID   string `json:"host_id" bson:"host_id"`
	HostName string `json:"host_name" bson:"host_name"`

	NetworkName string `json:"network_name" bson:"network_name"`
	VEthName    string `json:"veth_name" bson:"veth_name"`
	IP          string `json:"ip" bson:"ip"`
	Mac         string `json:"mac" bson:"mac"`
	Gateway     string `json:"gateway" bson:"gateway"`
	CIDRbits    int    `json:"cidr_bits" bson:"cidr_bits"`

	CreatedTime string `json:"created_time" bson:"created_time"`
	RemovedTime string `json:"removed_time" bson:"removed_time"`

	UpdatedTime string `json:"updated_time" bson:"updated_time"`
}

// SecurityService Structure
type SecurityService struct {
	MicroserviceName    string `json:"microservice_name" bson:"microservice_name"`
	SecurityServiceName string `json:"security_service_name" bson:"security_service_name"`

	Status string `json:"status" bson:"status"`

	HostID   string `json:"host_id" bson:"host_id"`
	HostName string `json:"host_name" bson:"host_name"`

	ContainerID  string `json:"container_id,omitempty" bson:"container_id,omitempty"`
	ContainerPID int    `json:"container_pid,omitempty" bson:"container_pid,omitempty"`

	Networks []Network `json:"networks,omitempty" bson:"networks,omitempty"`

	NetworkName string `json:"network_name" bson:"network_name"`
	VEthName    string `json:"veth_name" bson:"veth_name"`
	VEthIdx     int    `json:"veth_idx" bson:"veth_idx"`
	IP          string `json:"ip" bson:"ip"`
	Mac         string `json:"mac" bson:"mac"`
	Gateway     string `json:"gateway" bson:"gateway"`
	CIDRbits    int    `json:"cidr_bits" bson:"cidr_bits"`

	SSCVEth1Name string `json:"veth_in" bson:"veth_in"`
	SSCVEth1Idx  int    `json:"veth_in_idx" bson:"veth_in_idx"`

	SSCVEth2Name string `json:"veth_out" bson:"veth_out"`
	SSCVEth2Idx  int    `json:"veth_out_idx" bson:"veth_out_idx"`

	NetworkPolicies          []NetworkPolicy `json:"network_policies" bson:"network_policies"`
	DependentNetworkPolicies []NetworkPolicy `json:"dependent_network_policies" bson:"dependent_network_policies"`

	CreatedTime string `json:"created_time" bson:"created_time"`
	RemovedTime string `json:"removed_time" bson:"removed_time"`

	UpdatedTime string `json:"updated_time" bson:"updated_time"`
}
