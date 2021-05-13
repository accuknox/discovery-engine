package types

// SystemLogEvent - Model for SystemLog Table
type SystemLogEvent struct {
	Timestamp int `json:"timestamp,omitempty"`

	ClusterName string `json:"cluster_name,omitempty"`
	HostName    string `json:"host_name,omitempty"`

	NamespaceName string `json:"namespace_name,omitempty"`
	PodName       string `json:"pod_name,omitempty"`

	ContainerID   string `json:"container_id,omitempty"`
	ContainerName string `json:"container_name,omitempty"`

	HostPID int `json:"host_pid,omitempty"`
	PPID    int `json:"ppid,omitempty"`
	PID     int `json:"pid,omitempty"`
	UID     int `json:"uid,omitempty"`

	Type      string `json:"type,omitempty"`
	Source    string `json:"source,omitempty"`
	Operation string `json:"operation,omitempty"`
	Resource  string `json:"resource,omitempty"`
	Data      string `json:"data,omitempty"`
	Result    string `json:"result,omitempty"`
}
