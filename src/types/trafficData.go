package types

import pb "github.com/accuknox/knoxServiceFlowMgmt/src/proto"

// EventType Structure
type EventType struct {
	Type    int64 `json:"type,omitempty"`
	SubType int64 `json:"sub_type,omitempty"`
}

// KnoxTrafficFlow Structure
type KnoxTrafficFlow struct {
	TrafficFlow *pb.TrafficFlow `json:"traffic_flow,omitempty"`

	// additional info from cilium hubble
	PolicyMatchType int64      `json:"policy_match_type,omitempty"`
	DropReason      int64      `json:"drop_reason,omitempty"`
	EventType       *EventType `json:"event_type,omitempty"`
}
