package types

type ReportOptions struct {
	Clusters     []string
	Namespaces   []string
	ResourceType []string
	ResourceName []string
	Operation    string
	MetaData     *MetaData
	PodName      string
	Source       []string
	Destination  []string
}

type MetaData struct {
	Label         string
	ContainerName string
}
