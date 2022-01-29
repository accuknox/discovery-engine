package types

type SysObservabilityData struct {
	PolicyName    string   `json:"policyName,omitempty"`
	ClusterName   string   `json:"clustername,omitempty"`
	ContainerName string   `json:"containername,omitempty"`
	Namespace     string   `json:"namespace,omitempty"`
	Labels        string   `json:"labels,omitempty"`
	FromSource    string   `json:"fromsource,omitempty"`
	SetType       string   `json:"settype,omitempty"`
	Paths         []string `json:"paths,omitempty"`
}
