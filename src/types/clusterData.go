package types

// Cluster Structure
type Cluster struct {
	ClusterName string `json:"ClusterName" bson:"ClusterName"`
	ClusterID   int    `json:"cluster_id" bson:"ClusterID"`
	WorkspaceID int    `json:"workspace_id" bson:"WorkspaceID"`
	Location    string `json:"Location" bson:"Location"`
}

// ServiceCluster Structure
type ServiceCluster struct {
	Namespace   string              `json:"namespace,omitempty" bson:"namespace,omitempty"`
	ServiceName string              `json:"service_name,omitempty" bson:"service_name,omitempty"`
	Labels      []map[string]string `json:"labels,omitempty" bson:"labels,omitempty"`
	Types       string              `json:"Types,omitempty" bson:"Types,omitempty"`
	Mappings    []map[string]string `json:"mappings" bson:"mappings"`
	Selector    []map[string]string `json:"selector" bson:"selector"`
	Status      string              `json:"Status,omitempty" bson:"Status,omitempty"`
}

// EndpointCluster Structure
type EndpointCluster struct {
	Namespace    string                   `json:"namespace,omitempty" bson:"namespace,omitempty"`
	EndpointName string                   `json:"endpoint_name,omitempty" bson:"endpoint_name,omitempty"`
	IP           string                   `json:"ip,omitempty" bson:"ip,omitempty"`
	Labels       []map[string]string      `json:"labels,omitempty" bson:"labels,omitempty"`
	Mappings     []map[string]interface{} `json:"mappings" bson:"mappings"`
}

// PodCluster Structure
type PodCluster struct {
	Namespace string                   `json:"namespace,omitempty" bson:"namespace,omitempty"`
	PodName   string                   `json:"podname,omitempty" bson:"podname,omitempty"`
	Labels    []map[string]interface{} `json:"Labels,omitempty" bson:"Labels,omitempty"`
}
