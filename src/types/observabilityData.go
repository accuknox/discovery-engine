package types

type SysObsProcessFileData struct {
	FromSource   string   `json:"source,omitempty"`
	ProcessPaths []string `json:"processes,omitempty"`
	FilePaths    []string `json:"files,omitempty"`
}

type SysObservabilityData struct {
	ClusterName        string                  `json:"clustername,omitempty"`
	ContainerName      string                  `json:"containername,omitempty"`
	Namespace          string                  `json:"namespace,omitempty"`
	Labels             string                  `json:"labels,omitempty"`
	SysProcessFileData []SysObsProcessFileData `json:"process-files,omitempty"`
}
