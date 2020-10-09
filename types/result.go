package types

// ================================================================= //

// ResMap Structure
type ResMap struct {
	Result map[string]interface{} `json:"result"`
}

// ResMaps Structure
type ResMaps struct {
	Result  []map[string]interface{} `json:"result"`
	Message string                   `json:"error"`
}

// ResStrMaps Structure
type ResStrMaps struct {
	Result []map[string]string `json:"result"`
}

// ================================================================= //

// ResNetPolicies Structure
type ResNetPolicies struct {
	Result  []NetworkPolicy `json:"result"`
	Message string          `json:"error"`
}

// ResNetPolicy Structure
type ResNetPolicy struct {
	Result  NetworkPolicy `json:"result"`
	Message string        `json:"error"`
}

// ================================================================= //

// ResServiceChainPolicies Structure
type ResServiceChainPolicies struct {
	Result  []ServiceChainPolicy `json:"result"`
	Message string               `json:"error"`
}

// ResServiceChainPolicy Structure
type ResServiceChainPolicy struct {
	Result  ServiceChainPolicy `json:"result"`
	Message string             `json:"error"`
}

// ================================================================= //

// ResSystemPolicies Structure
type ResSystemPolicies struct {
	Result  []SystemPolicy `json:"result"`
	Message string         `json:"error"`
}

// ResSystemPolicy Structure
type ResSystemPolicy struct {
	Result  SystemPolicy `json:"result"`
	Message string       `json:"error"`
}

// ================================================================= //

// ResRuntimePolicies Structure
type ResRuntimePolicies struct {
	Result  []RuntimePolicy `json:"result"`
	Message string          `json:"error"`
}

// ResRuntimePolicy Structure
type ResRuntimePolicy struct {
	Result  RuntimePolicy `json:"result"`
	Message string        `json:"error"`
}

// ================================================================= //

// ResHosts Structure
type ResHosts struct {
	Result  []Host `json:"result"`
	Message string `json:"error"`
}

// ResHost Structure
type ResHost struct {
	Result  Host   `json:"result"`
	Message string `json:"error"`
}

// ================================================================= //

// ResMicroservices Structure
type ResMicroservices struct {
	Result  []Microservice `json:"result"`
	Message string         `json:"error"`
}

// ResMicroservice Structure
type ResMicroservice struct {
	Result  Microservice `json:"result"`
	Message string       `json:"error"`
}

// ================================================================= //

// ResContainerGroups Structure
type ResContainerGroups struct {
	Result  []ContainerGroup `json:"result"`
	Message string           `json:"error"`
}

// ResContainerGroup Structure
type ResContainerGroup struct {
	Result  ContainerGroup `json:"result"`
	Message string         `json:"error"`
}

// ================================================================= //

// ResContainers Structure
type ResContainers struct {
	Result  []Container `json:"result"`
	Message string      `json:"error"`
}

// ResContainer Structure
type ResContainer struct {
	Result  Container `json:"result"`
	Message string    `json:"error"`
}

// ================================================================= //

// ResImages Structure
type ResImages struct {
	Result  []Image `json:"result"`
	Message string  `json:"error"`
}

// ResImage Structure
type ResImage struct {
	Result  Image  `json:"result"`
	Message string `json:"error"`
}

// ================================================================= //

// ResSecurityStacks Structure
type ResSecurityStacks struct {
	Result  []SecurityStack `json:"result"`
	Message string          `json:"error"`
}

// ResSecurityStack Structure
type ResSecurityStack struct {
	Result  SecurityStack `json:"result"`
	Message string        `json:"error"`
}

// ================================================================= //

// ResSecurityServices Structure
type ResSecurityServices struct {
	Result  []SecurityService `json:"result"`
	Message string            `json:"error"`
}

// ResSecurityService Structure
type ResSecurityService struct {
	Result  SecurityService `json:"result"`
	Message string          `json:"error"`
}

// ================================================================= //

// ResNetworkMaps Structure
type ResNetworkMaps struct {
	Result  []NetworkMap `json:"result"`
	Message string       `json:"error"`
}

// ResServices Structure
type ResServices struct {
	Result  []K8sService `json:"result"`
	Message string       `json:"error"`
}

// ResEndpoints Structure
type ResEndpoints struct {
	Result  []K8sEndpoint `json:"result"`
	Message string        `json:"error"`
}

// ResSvcToEndpoints Structure
type ResSvcToEndpoints struct {
	Result  []K8sSvcToEndpoint `json:"result"`
	Message string             `json:"error"`
}

// ================================================================= //

// ResAppArmorProfiles Structure
type ResAppArmorProfiles struct {
	Result  []AppArmorProfile `json:"result"`
	Message string            `json:"error"`
}

// ================================================================= //

// ResSuricataRules Structure
type ResSuricataRules struct {
	Result  []SuricataRule `json:"result"`
	Message string         `json:"error"`
}

// ResSuricataRule Structure
type ResSuricataRule struct {
	Result  SuricataRule `json:"result"`
	Message string       `json:"error"`
}

// ================================================================= //
