package types

// PortBinding Structure
type PortBinding struct {
	Protocol string `json:"protocol" bson:"protocol"`
	Port     int    `json:"port" bson:"port"`
	HostIP   string `json:"host_ip" bson:"host_ip"`
	HostPort int    `json:"host_port" bson:"host_port"`
}

// ContainerGroup Structure
type ContainerGroup struct {
	MicroserviceName string `json:"microservice_name" bson:"microservice_name"`

	ContainerGroupUID  string `json:"container_group_uid" bson:"container_group_uid"`
	ContainerGroupName string `json:"container_group_name" bson:"container_group_name"`

	Status string `json:"status" bson:"status"`

	HostID   string `json:"host_id" bson:"host_id"`
	HostName string `json:"host_name" bson:"host_name"`
	HostIP   string `json:"host_ip" bson:"host_ip"`

	Labels []string `json:"labels" bson:"labels"`

	PortBindings []PortBinding `json:"port_bindings" bson:"port_bindings"`
}

// Microservice Structure
type Microservice struct {
	MicroserviceUID  string `json:"microservice_uid" bson:"microservice_uid"`
	MicroserviceName string `json:"microservice_name" bson:"microservice_name"`

	Status string `json:"status" bson:"status"`

	Labels []string `json:"labels" bson:"labels"`

	ContainerGroups []string `json:"container_groups" bson:"container_groups"`
	Containers      []string `json:"containers" bson:"containers"`
}
