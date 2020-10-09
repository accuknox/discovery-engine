package types

// ================================================================= //

// DataActive Structure
type DataActive struct {
	Active bool `json:"active" bson:"active"`
}

// ================================================================= //

// DataDaemonConfig Structure
type DataDaemonConfig struct {
	Key   string      `json:"key" bson:"key"`
	Value interface{} `json:"value" bson:"value"`
}

// DataSystemMonitorConfig Structure
type DataSystemMonitorConfig struct {
	Key   string      `json:"key" bson:"key"`
	Value interface{} `json:"value" bson:"value"`
}

// DataDefaultActionConfig Structure
type DataDefaultActionConfig struct {
	Key   string `json:"key" bson:"key"`
	Value string `json:"value" bson:"value"`
}

// ================================================================= //

// DataNetworkPolicies Structure
type DataNetworkPolicies struct {
	NetworkPolicies []NetworkPolicy `json:"network_policies" bson:"network_policies"`
}

// DataNetworkPolicy Structure
type DataNetworkPolicy struct {
	NetworkPolicy NetworkPolicy `json:"network_policy" bson:"network_policy"`
}

// ================================================================= //

// DataServiceChainPolicies Structure
type DataServiceChainPolicies struct {
	ServiceChainPolicies []ServiceChainPolicy `json:"service_chain_policies" bson:"service_chain_policies"`
}

// DataServiceChainPolicy Structure
type DataServiceChainPolicy struct {
	ServiceChainPolicy ServiceChainPolicy `json:"service_chain_policy" bson:"service_chain_policy"`
}

// ================================================================= //

// DataSystemPolicies Structure
type DataSystemPolicies struct {
	SystemPolicies []SystemPolicy `json:"system_policies" bson:"system_policies"`
}

// DataSystemPolicy Structure
type DataSystemPolicy struct {
	SystemPolicy SystemPolicy `json:"system_policy" bson:"system_policy"`
}

// ================================================================= //

// DataRuntimePolicies Structure
type DataRuntimePolicies struct {
	RuntimePolicies []RuntimePolicy `json:"runtime_policies" bson:"runtime_policies"`
}

// DataRuntimePolicy Structure
type DataRuntimePolicy struct {
	RuntimePolicy RuntimePolicy `json:"runtime_policy" bson:"runtime_policy"`
}

// ================================================================= //

// PutHosts Structure
type PutHosts struct {
	Hosts []Host `json:"hosts" bson:"hosts"`
}

// PutHost Structure
type PutHost struct {
	Host Host `json:"host" bson:"host"`
}

// ================================================================= //

// PutMicroservices Structure
type PutMicroservices struct {
	Microservices []Microservice `json:"microservices" bson:"microservices"`
}

// PutMicroservice Structure
type PutMicroservice struct {
	Microservice Microservice `json:"microservice" bson:"microservice"`
}

// ================================================================= //

// PutContainerGroup Structure
type PutContainerGroup struct {
	ContainerGroup ContainerGroup `json:"container_group" bson:"container_group"`
}

// PutContainerGroups Structure
type PutContainerGroups struct {
	ContainerGroups []ContainerGroup `json:"container_groups" bson:"container_groups"`
}

// ================================================================= //

// PutContainer Structure
type PutContainer struct {
	Container Container `json:"container" bson:"container"`
}

// PutContainers Structure
type PutContainers struct {
	Containers []Container `json:"containers" bson:"containers"`
}

// ================================================================= //

// PutImage Structure
type PutImage struct {
	Image Image `json:"image" bson:"image"`
}

// PutImages Structure
type PutImages struct {
	Images []Image `json:"images" bson:"images"`
}

// ================================================================= //

// PutSecurityStack Structure
type PutSecurityStack struct {
	SecurityStack SecurityStack `json:"security_stack" bson:"security_stack"`
}

// PutSecurityStacks Structure
type PutSecurityStacks struct {
	SecurityStacks []SecurityStack `json:"security_stacks" bson:"security_stacks"`
}

// ================================================================= //

// PutSecurityService Structure
type PutSecurityService struct {
	SecurityService SecurityService `json:"security_service" bson:"security_service"`
}

// PutSecurityServices Structure
type PutSecurityServices struct {
	SecurityServices []SecurityService `json:"security_services" bson:"security_services"`
}

// ================================================================= //

// PutNetworkMap Structure
type PutNetworkMap struct {
	NetworkMap NetworkMap `json:"network_map" bson:"network_map"`
}

// PutNetworkMaps Structure
type PutNetworkMaps struct {
	NetworkMaps []NetworkMap `json:"network_maps" bson:"network_maps"`
}

// ================================================================= //

// PutService Structure
type PutService struct {
	Service K8sService `json:"service" bson:"service"`
}

// PutServices Structure
type PutServices struct {
	Services []K8sService `json:"services" bson:"services"`
}

// ================================================================= //

// PutEndpoint Structure
type PutEndpoint struct {
	Endpoint K8sEndpoint `json:"endpoint" bson:"endpoint"`
}

// PutEndpoints Structure
type PutEndpoints struct {
	Endpoints []K8sEndpoint `json:"endpoints" bson:"endpoints"`
}

// ================================================================= //

// GetLogsData Structure
type GetLogsData struct {
	Options   map[string]interface{} `json:"options" bson:"options"`
	Sort      string                 `json:"sort" bson:"sort"`
	Limit     interface{}            `json:"limit" bson:"limit"`
	Direction string                 `json:"direction" bson:"direction"`
}

// DataLogs Structure
type DataLogs struct {
	Logs []map[string]interface{} `json:"logs" bson:"logs"`
}

// ================================================================= //

// DataSuricataRules Structure
type DataSuricataRules struct {
	SuricataRules []SuricataRule `json:"suricata_rules" bson:"suricata_rules"`
}

// DataSuricataRule Structure
type DataSuricataRule struct {
	SuricataRule SuricataRule `json:"suricata_rule" bson:"suricata_rule"`
}

// ================================================================= //
