package types

// NetworkLog Structure
type NetworkLog struct {
	HostName string `json:"host_name" bson:"host_name"`

	SrcMicroserviceName   string `json:"src_microservice_name" bson:"src_microservice_name"`
	SrcContainerGroupName string `json:"src_container_group_name" bson:"src_container_group_name"`
	DstMicroserviceName   string `json:"dst_microservice_name" bson:"dst_microservice_name"`
	DstContainerGroupName string `json:"dst_container_group_name" bson:"dst_container_group_name"`

	EtherType int    `json:"ether_type" bson:"ether_type"` // default ipv4
	SrcMac    string `json:"src_mac" bson:"src_mac"`
	DstMac    string `json:"dst_mac" bson:"dst_mac"`

	Protocol int    `json:"protocol" bson:"protocol"`
	SrcIP    string `json:"src_ip" bson:"src_ip"`
	DstIP    string `json:"dst_ip" bson:"dst_ip"`
	SrcPort  int    `json:"src_port" bson:"src_port"`
	DstPort  int    `json:"dst_port" bson:"dst_port"`

	Action    string `json:"action" bson:"action"`
	Direction string `json:"direction" bson:"direction"` // ingress or egress

	Reason string `json:"reason" bson:"reason"`
}

// SystemLog Structure
type SystemLog struct {
	// detected time
	DetectedTime string `json:"detected_time" bson:"detected_time"`

	// host and container
	HostName      string `json:"host_name" bson:"host_name"`
	ContainerName string `json:"container_name" bson:"container_name"`

	// common
	HostPID int    `json:"host_pid" bson:"host_pid"`
	PPID    int    `json:"ppid" bson:"ppid"`
	PID     int    `json:"pid" bson:"pid"`
	TID     int    `json:"tid" bson:"tid"`
	UID     int    `json:"uid" bson:"uid"`
	Comm    string `json:"comm" bson:"comm"`

	// syscall
	Syscall string `json:"syscall" bson:"syscall"`
	Argnum  int    `json:"argnum" bson:"argnum"`
	Retval  int    `json:"retval" bson:"retval"`

	Fd int `json:"fd" bson:"fd"`

	// process
	ProcExecPath string   `json:"proc_exec,omitempty" bson:"proc_exec,omitempty"`
	ProcArgs     []string `json:"proc_args,omitempty" bson:"proc_args,omitempty"`
	ProcExecFlag string   `json:"proc_flags,omitempty" bson:"proc_flags,omitempty"`

	// file
	FileName      string `json:"file_name,omitempty" bson:"file_name,omitempty"`
	FileOpenFlags string `json:"file_open_flags,omitempty" bson:"file_open_flags,omitempty"`

	// network
	SockDomain   string            `json:"sock_domain,omitempty" bson:"sock_domain,omitempty"`
	SockType     string            `json:"sock_type,omitempty" bson:"sock_type,omitempty"`
	SockProtocol int               `json:"sock_proto,omitempty" bson:"sock_proto,omitempty"`
	SockAddr     map[string]string `json:"sock_addr,omitempty" bson:"sock_addr,omitempty"`

	Data string `json:"data" bson:"data"`
}

// RuntimeLog Structure
type RuntimeLog struct {
	// host and container
	HostName      string `json:"host_name" bson:"host_name"`
	ContainerName string `json:"container_name" bson:"container_name"`

	Type    string `json:"type" bson:"type"`
	Message string `json:"message" bson:"message"`

	UpdatedTime string `json:"updated_time" bson:"updated_time"`
}

// SuricataLog Structure
type SuricataLog struct {
	Source   string `json:"source" bson:"source"`
	SourceIP string `json:"source_ip" bson:"source_ip"`

	Type    string `json:"type" bson:"type"`
	RawData string `json:"raw_data" bson:"raw_data"`
}
