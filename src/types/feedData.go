package types

import "encoding/json"

type NetworkLogEvent struct {
	Time                  string          `json:"time,omitempty"`
	ClusterName           string          `json:"cluster_name,omitempty"`
	Verdict               string          `json:"verdict,omitempty"`
	DropReason            int             `json:"drop_reason,omitempty"`
	Ethernet              json.RawMessage `json:"ethernet,omitempty"`
	IP                    json.RawMessage `json:"IP,omitempty"`
	L4                    json.RawMessage `json:"l4,omitempty"`
	L7                    json.RawMessage `json:"l7,omitempty"`
	Source                json.RawMessage `json:"source,omitempty"`
	Destination           json.RawMessage `json:"destination,omitempty"`
	Type                  string          `json:"Type,omitempty"`
	NodeName              string          `json:"node_name,omitempty"`
	EventType             json.RawMessage `json:"event_type,omitempty"`
	SourceService         json.RawMessage `json:"source_service,omitempty"`
	DestinationService    json.RawMessage `json:"destination_service,omitempty"`
	TrafficDirection      string          `json:"traffic_direction,omitempty"`
	PolicyMatchType       int             `json:"policy_match_type,omitempty"`
	TraceObservationPoint string          `json:"trace_observation_point,omitempty"`
	Reply                 bool            `json:"is_reply,omitempty"`
	Summary               string          `json:"Summary,omitempty"`
}

type SystemLogEvent struct {
	ID          int    `json:"id,omitempty"`
	Time        string `json:"time,omitempty"`
	Timestamp   int    `json:"timestamp,omitempty"`
	UpdatedTime string `json:"updatedTime,omitempty"`

	Clustername string `json:"cluster_name,omitempty"` // for knox feeder consumer

	ClusterName   string `json:"clusterName,omitempty"`
	HostName      string `json:"hostName,omitempty"`
	NamespaceName string `json:"namespaceName,omitempty"`
	PodName       string `json:"podName,omitempty"`
	ContainerID   string `json:"containerID,omitempty"`
	ContainerName string `json:"containerName,omitempty"`

	HostPID int `json:"hostPid,omitempty"`
	PPID    int `json:"ppid,omitempty"`
	PID     int `json:"pid,omitempty"`
	UID     int `json:"uid,omitempty"`

	Type      string `json:"type,omitempty"`
	Source    string `json:"source,omitempty"`
	Operation string `json:"operation,omitempty"` // Process, File, Network
	Resource  string `json:"resource,omitempty"`
	Data      string `json:"data,omitempty"`
	Result    string `json:"result,omitempty"`
}

type SystemAlertEvent struct {
	ID          int    `json:"id,omitempty"`
	Timestamp   int    `json:"timestamp,omitempty"`
	UpdatedTime string `json:"updatedTime,omitempty"`

	Clustername string `json:"cluster_name,omitempty"` // for knox feeder consumer

	ClusterName   string `json:"clusterName,omitempty"`
	HostName      string `json:"hostName,omitempty"`
	NamespaceName string `json:"namespaceName,omitempty"`
	PodName       string `json:"podName,omitempty"`
	ContainerID   string `json:"containerID,omitempty"`
	ContainerName string `json:"containerName,omitempty"`

	HostPID int `json:"hostPid,omitempty"`
	PPID    int `json:"ppid,omitempty"`
	PID     int `json:"pid,omitempty"`
	UID     int `json:"uid,omitempty"`

	PolicyName string `json:"policyName,omitempty"` // added
	Severity   string `json:"severity,omitempty"`   // added
	Tags       string `json:"tags,omitempty"`       // added
	Message    string `json:"message,omitempty"`    // added

	Type      string `json:"type,omitempty"`
	Source    string `json:"source,omitempty"`
	Operation string `json:"operation,omitempty"`
	Resource  string `json:"resource,omitempty"`
	Data      string `json:"data,omitempty"`

	Action string `json:"action,omitempty"` // added

	Result string `json:"result,omitempty"`
}

// WorkloadProcessFileSet = clusterName + podname, namespace, {sorted set of labels}, fromSource.
type WorkloadProcessFileSet struct {
	ClusterName   string
	ContainerName string
	Namespace     string
	Labels        string // comma separated list of pod labels
	FromSource    string
	SetType       string // SetType: "file" or "process"
}

type PolicyNameMap map[WorkloadProcessFileSet]string
type ResourceSetMap map[WorkloadProcessFileSet][]string
