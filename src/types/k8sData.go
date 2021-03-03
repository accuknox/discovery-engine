package types

// Mapping Structure
type Mapping struct {
	Protocol string `json:"protocol" bson:"protocol"`
	IP       string `json:"ip" bson:"ip"`
	Port     int    `json:"port" bson:"port"`
}

// Endpoint Structure
type Endpoint struct {
	Namespace    string `json:"namespace,omitempty" bson:"namespace,omitempty"`
	EndpointName string `json:"endpoint_name,omitempty" bson:"endpoint_name,omitempty"`

	Labels []string `json:"labels,omitempty" bson:"labels,omitempty"`

	Endpoints []Mapping `json:"mappings" bson:"mappings"`
}

// Service Structure
type Service struct {
	Namespace   string `json:"namespace,omitempty" bson:"namespace,omitempty"`
	ServiceName string `json:"service_name,omitempty" bson:"service_name,omitempty"`

	Labels []string `json:"labels,omitempty" bson:"labels,omitempty"`

	Type      string `json:"type,omitempty" bson:"type,omitempty"`
	Protocol  string `json:"protocol,omitempty" bson:"protocol,omitempty"`
	ClusterIP string `json:"cluster_ip,omitempty" bson:"cluster_ip,omitempty"`

	ServicePort int `json:"service_port" bson:"service_port"`
	NodePort    int `json:"node_port" bson:"node_port"`
	TargetPort  int `json:"target_port" bson:"target_port"`

	Selector map[string]string `json:"selector" bson:"selector"`
}

// Pod Structure
type Pod struct {
	Namespace string `json:"namespace" bson:"namespace"`

	PodUID  string `json:"pod_uid" bson:"pod_uid"`
	PodName string `json:"pod_name" bson:"pod_name"`

	HostID   string `json:"host_id" bson:"host_id"`
	HostName string `json:"host_name" bson:"host_name"`
	HostIP   string `json:"host_ip" bson:"host_ip"`

	Labels []string `json:"labels" bson:"labels"`
}

// Namespace Structure
type Namespace struct {
	NamespaceUID  string `json:"namespace_uid" bson:"namespace_uid"`
	NamespaceName string `json:"namespace_name" bson:"namespace_name"`

	Status string `json:"status" bson:"status"`

	Labels []string `json:"labels" bson:"labels"`

	Pods       []string `json:"pods" bson:"pods"`
	Containers []string `json:"containers" bson:"containers"`
}
