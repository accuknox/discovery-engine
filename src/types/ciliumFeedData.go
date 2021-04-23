package types

import "encoding/json"

// NetworkFlowEvent - Model for NetworkFlow Table
type NetworkFlowEvent struct {
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
