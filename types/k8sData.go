package types

// K8sData Structure
type K8sData struct {
	MicroserviceUID   string
	ContainerGroupUID string
	Labels            map[string]string
	CreatedTime       string
}

// K8sService Structure
type K8sService struct {
	MicroserviceName string `json:"microservice_name,omitempty" bson:"microservice_name,omitempty"`

	ServiceUID  string `json:"service_uid,omitempty" bson:"service_uid,omitempty"`
	ServiceName string `json:"service_name,omitempty" bson:"service_name,omitempty"`

	Labels     []string `json:"labels,omitempty" bson:"labels,omitempty"`
	Identities []string `json:"identities,omitempty" bson:"identities,omitempty"`

	Type string `json:"type,omitempty" bson:"type,omitempty"`

	Protocol    string `json:"protocol,omitempty" bson:"protocol,omitempty"`
	ClusterIP   string `json:"cluster_ip,omitempty" bson:"cluster_ip,omitempty"`
	ServicePort int    `json:"service_port" bson:"service_port"`

	NodePort      int `json:"node_port" bson:"node_port"`
	ContainerPort int `json:"container_port" bson:"container_port"`

	CreatedTime string `json:"created_time,omitempty" bson:"created_time,omitempty"`
	RemovedTime string `json:"removed_time,omitempty" bson:"removed_time,omitempty"`
}

// Endpoint Structure
type Endpoint struct {
	ContainerGroupName string `json:"container_group_name" bson:"container_group_name"`
	Protocol           string `json:"protocol" bson:"protocol"`
	IP                 string `json:"ip" bson:"ip"`
	Port               int    `json:"port" bson:"port"`
}

// K8sEndpoint Structure
type K8sEndpoint struct {
	MicroserviceName string `json:"microservice_name,omitempty" bson:"microservice_name,omitempty"`

	EndpointUID  string `json:"endpoint_uid,omitempty" bson:"endpoint_uid,omitempty"`
	EndpointName string `json:"endpoint_name,omitempty" bson:"endpoint_name,omitempty"`

	Labels     []string `json:"labels,omitempty" bson:"labels,omitempty"`
	Identities []string `json:"identities,omitempty" bson:"identities,omitempty"`

	Endpoints []Endpoint `json:"mappings" bson:"mappings"`

	CreatedTime string `json:"created_time,omitempty" bson:"created_time,omitempty"`
	RemovedTime string `json:"removed_time,omitempty" bson:"removed_time,omitempty"`
}

// K8sSvcToEndpoint Structure
type K8sSvcToEndpoint struct {
	MicroserviceName string `json:"microservice_name,omitempty" bson:"microservice_name,omitempty"`

	Type string `json:"type,omitempty" bson:"type,omitempty"`

	Protocol    string `json:"protocol,omitempty" bson:"protocol,omitempty"`
	ServiceIP   string `json:"service_ip,omitempty" bson:"service_ip,omitempty"`
	ServicePort int    `json:"service_port,omitempty" bson:"service_port,omitempty"`

	NumContainers int        `json:"num_containers,omitempty" bson:"num_containers,omitempty"`
	Endpoints     []Endpoint `json:"mappings,omitempty" bson:"mappings,omitempty"`

	CreatedTime string `json:"created_time,omitempty" bson:"created_time,omitempty"`
	RemovedTime string `json:"removed_time,omitempty" bson:"removed_time,omitempty"`
}
