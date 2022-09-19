package types

type InsightRequest struct {
	Request       string
	Source        string
	ClusterName   string
	Namespace     string
	ContainerName string
	Labels        string
	FromSource    string
	Duration      string
	Type          string
	Rule          string
}

type SystemData struct {
	FromSource   string   `json:"source,omitempty"`
	ProcessPaths []string `json:"processes,omitempty"`
	FilePaths    []string `json:"files,omitempty"`
	NetworkPaths []string `json:"network,omitempty"`
}

type SysInsightData struct {
	ClusterName        string       `json:"clustername,omitempty"`
	Namespace          string       `json:"namespace,omitempty"`
	Labels             string       `json:"labels,omitempty"`
	ContainerName      string       `json:"containername,omitempty"`
	SysProcessFileData []SystemData `json:"system-resources,omitempty"`
}

type SysInsightResponseData struct {
	SysData []SysInsightData
}
