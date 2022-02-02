package types

type SysObsProcessFileData struct {
	FromSource   string   `json:"source,omitempty"`
	ProcessPaths []string `json:"processes,omitempty"`
	FilePaths    []string `json:"files,omitempty"`
}

type SysObservabilityData struct {
	ClusterName        string                  `json:"clustername,omitempty"`
	Namespace          string                  `json:"namespace,omitempty"`
	Labels             string                  `json:"labels,omitempty"`
	ContainerName      string                  `json:"containername,omitempty"`
	SysProcessFileData []SysObsProcessFileData `json:"process-files,omitempty"`
}

type SysObsResponseData struct {
	Data []SysObservabilityData
}
