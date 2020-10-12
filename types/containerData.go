package types

// Host Structure
type Host struct {
	HostID   string `json:"host_id" bson:"host_id"`
	HostName string `json:"host_name" bson:"host_name"`

	Status string `json:"status" bson:"status"`

	Labels []string `json:"labels" bson:"labels"`

	Architecture    string `json:"architecture" bson:"architecture"`
	OSType          string `json:"os_type" bson:"os_type"`
	OperatingSystem string `json:"operating_system" bson:"operating_system"`
	KernelVersion   string `json:"kernel_version" bson:"kernel_version"`

	NumContainers        int `json:"num_containers" bson:"num_containers"`
	NumPausedContainers  int `json:"num_paused_containers" bson:"num_paused_containers"`
	NumRunningContainers int `json:"num_running_containers" bson:"num_running_containers"`
	NumStoppedContainers int `json:"num_stopped_containers" bson:"num_stopped_containers"`

	NumImages int `json:"num_images" bson:"num_images"`

	NumCpus int   `json:"num_cpus" bson:"num_cpus"`
	MemSize int64 `json:"memory_size" bson:"memory_size"`

	HostIP string `json:"host_ip" bson:"host_ip"`

	AttachedTime string `json:"attached_time" bson:"attached_time"`
	DetachedTime string `json:"detached_time" bson:"detached_time"`

	UpdatedTime string `json:"updated_time" bson:"updated_time"` // db
}

// Bridge Structure
type Bridge struct {
	BridgeName string `json:"bridge_name" bson:"bridge_name"`
	IP         string `json:"ip" bson:"ip"`
	Mac        string `json:"mac" bson:"mac"`
	CIDRbits   int    `json:"cidr_bits" bson:"cidr_bits"`
	Index      int    `json:"idx" bson:"idx"`
}

// PortBinding Structure
type PortBinding struct {
	Protocol string `json:"protocol" bson:"protocol"`
	Port     int    `json:"port" bson:"port"`
	HostIP   string `json:"host_ip" bson:"host_ip"`
	HostPort int    `json:"host_port" bson:"host_port"`
}

// Network Structure
type Network struct {
	NetworkName string `json:"network_name" bson:"network_name"`

	IP       string `json:"ip" bson:"ip"`
	Mac      string `json:"mac" bson:"mac"`
	Gateway  string `json:"gateway" bson:"gateway"`
	CIDRbits int    `json:"cidr_bits" bson:"cidr_bits"`

	VEthName string `json:"veth_name" bson:"veth_name"`
	VEthIdx  int    `json:"veth_idx" bson:"veth_idx"`

	Bridge Bridge `json:"bridge" bson:"bridge"`
}

// Container Structure
type Container struct {
	ContainerID   string `json:"container_id" bson:"container_id"`
	ContainerName string `json:"container_name" bson:"container_name"`
	ContainerPID  int    `json:"container_pid" bson:"container_pid"`

	Status string `json:"status" bson:"status"`

	HostID   string `json:"host_id" bson:"host_id"`
	HostName string `json:"host_name" bson:"host_name"`
	HostIP   string `json:"host_ip" bson:"host_ip"`

	MicroserviceName   string `json:"microservice_name" bson:"microservice_name"`
	ContainerGroupName string `json:"container_group_name" bson:"container_group_name"`

	ImageID   string `json:"image_id" bson:"image_id"`
	ImageName string `json:"image_name" bson:"image_name"`

	Labels []string `json:"labels" bson:"labels"`

	HostNameL  string   `json:"hostname" bson:"hostname"`
	Owner      string   `json:"user" bson:"user"`
	Cmd        []string `json:"cmd" bson:"cmd"`
	Entrypoint []string `json:"entrypoint" bson:"entrypoint"`
	Env        []string `json:"env" bson:"env"`

	Privileged  bool   `json:"privileged" bson:"privileged"`
	PidMode     string `json:"pid_mode" bson:"pid_mode"`
	IpcMode     string `json:"ipc_mode" bson:"ipc_mode"`
	UTSMode     string `json:"uts_mode" bson:"uts_mode"`
	NetworkMode string `json:"network_mode" bson:"network_mode"`
	UsernsMode  string `json:"userns_mode" bson:"userns_mode"`

	CapAdd  []string `json:"cap_add" bson:"cap_add"`
	CapDrop []string `json:"cap_drop" bson:"cap_drop"`

	ReadonlyRootfs  bool   `json:"readonly_rootfs" bson:"readonly_rootfs"`
	AppArmorProfile string `json:"apparmor_profile" bson:"apparmor_profile"`

	PortBindings []PortBinding `json:"port_bindings" bson:"port_bindings"`
	Networks     []Network     `json:"networks" bson:"networks"`

	CreatedTime  string `json:"created_time" bson:"created_time"`
	StartedTime  string `json:"started_time" bson:"started_time"`
	FinishedTime string `json:"finished_time" bson:"finished_time"`
	RemovedTime  string `json:"removed_time" bson:"removed_time"`

	UpdatedTime string `json:"updated_time" bson:"updated_time"`
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

	Labels     []string `json:"labels" bson:"labels"`
	Identities []string `json:"identities" bson:"identities"`

	Containers []string `json:"containers" bson:"containers"`

	PortBindings []PortBinding `json:"port_bindings" bson:"port_bindings"`
	Networks     []Network     `json:"networks" bson:"networks"`

	NetworkPolicies          []NetworkPolicy `json:"network_policies" bson:"network_policies"`
	DependentNetworkPolicies []NetworkPolicy `json:"dependent_network_policies" bson:"dependent_network_policies"`
	SystemPolicies           []SystemPolicy  `json:"system_policies" bson:"system_policies"`
	RuntimePolicies          []RuntimePolicy `json:"runtime_policies" bson:"runtime_policies"`

	DefaultNetworkActions map[string]string `json:"default_network_actions" bson:"default_network_actions"`

	AppArmorProfiles map[string]string `json:"apparmor_profiles" bson:"apparmor_profiles"`

	CreatedTime string `json:"created_time" bson:"created_time"`
	RemovedTime string `json:"removed_time" bson:"removed_time"`

	UpdatedTime string `json:"updated_time" bson:"updated_time"`
}

// Microservice Structure
type Microservice struct {
	MicroserviceUID  string `json:"microservice_uid" bson:"microservice_uid"`
	MicroserviceName string `json:"microservice_name" bson:"microservice_name"`

	Status string `json:"status" bson:"status"`

	Labels []string `json:"labels" bson:"labels"`

	ContainerGroups []string `json:"container_groups" bson:"container_groups"`
	Containers      []string `json:"containers" bson:"containers"`

	CreatedTime string `json:"created_time" bson:"created_time"`
	RemovedTime string `json:"removed_time" bson:"removed_time"`

	UpdatedTime string `json:"updated_time" bson:"updated_time"`
}

// Image Structure
type Image struct {
	HostID   string `json:"host_id" bson:"host_id"`
	HostName string `json:"host_name" bson:"host_name"`

	ImageID   string `json:"image_id" bson:"image_id"`
	ImageName string `json:"image_name" bson:"image_name"`
	ImageSize int64  `json:"image_size" bson:"image_size"`

	Status string `json:"status" bson:"status"`

	ScanResult string `json:"scan_result" bson:"scan_result"`

	CreatedTime string `json:"created_time" bson:"created_time"`
	RemovedTime string `json:"removed_time" bson:"removed_time"`

	UpdatedTime string `json:"updated_time" bson:"updated_time"`
}
