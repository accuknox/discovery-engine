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

	ServicePort int      `json:"service_port" bson:"service_port"`
	NodePort    int      `json:"node_port" bson:"node_port"`
	TargetPort  int      `json:"target_port" bson:"target_port"`
	ExternalIPs []string `json:"external_ip" bson:"external_ip"`

	Selector map[string]string `json:"selector" bson:"selector"`
}

// Pod Structure
type Pod struct {
	Namespace string   `json:"namespace" bson:"namespace"`
	PodName   string   `json:"pod_name" bson:"pod_name"`
	Labels    []string `json:"labels" bson:"labels"`
	PodIP     string   `json:"pod_ip" bson:"pod_ip"`
}

// Deployment Structure
type Deployment struct {
	Name      string `json:"name" bson:"name"`
	Namespace string `json:"namespace" bson:"namespace"`
	Labels    string `json:"labels" bson:"labels"`
}
