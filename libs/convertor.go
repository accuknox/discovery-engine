package libs

import (
	"github.com/accuknox/knoxAutoPolicy/types"
	pb "github.com/accuknox/knoxServiceFlowMgmt/src/proto"
)

func isSynFlagOnly(tcp *pb.TCP) bool {
	if tcp.Flags.SYN && !tcp.Flags.ACK {
		return true
	}
	return false
}

func getL4Ports(l4 *pb.Layer4) (int, int) {
	if l4.TCP != nil {
		return int(l4.TCP.SourcePort), int(l4.TCP.DestinationPort)
	} else if l4.UDP != nil {
		return int(l4.UDP.SourcePort), int(l4.UDP.DestinationPort)
	} else if l4.ICMPv4 != nil {
		return int(l4.ICMPv4.Type), int(l4.ICMPv4.Code)
	} else {
		return -1, -1
	}
}

func getProtocol(l4 *pb.Layer4) int {
	if l4.TCP != nil {
		return 6
	} else if l4.UDP != nil {
		return 17
	} else if l4.ICMPv4 != nil {
		return 1
	} else {
		return 0 // unknown?
	}
}

func TrafficToLog(flow *pb.TrafficFlow) types.NetworkLog {
	log := types.NetworkLog{}

	if flow.Source.Namespace == "" {
		log.SrcMicroserviceName = "external"
	} else {
		log.SrcMicroserviceName = flow.Source.Namespace
	}

	if flow.Source.Pod == "" {
		log.SrcContainerGroupName = flow.Ip.Source
	} else {
		log.SrcContainerGroupName = flow.Source.Pod
	}

	if flow.Destination.Namespace == "" {
		log.DstMicroserviceName = "external"
	} else {
		log.DstMicroserviceName = flow.Destination.Namespace
	}

	if flow.Destination.Pod == "" {
		log.DstContainerGroupName = flow.Ip.Destination
	} else {
		log.DstContainerGroupName = flow.Destination.Pod
	}

	log.SrcMac = flow.Ethernet.Source
	log.DstMac = flow.Ethernet.Destination

	log.Protocol = getProtocol(flow.L4)
	if log.Protocol == 6 { //
		log.SynFlag = isSynFlagOnly(flow.L4.TCP)
	}

	log.SrcIP = flow.Ip.Source
	log.DstIP = flow.Ip.Destination

	log.SrcPort, log.DstPort = getL4Ports(flow.L4)

	if flow.Verdict == "FORWARDED" {
		log.Action = "allow"
	} else if flow.Verdict == "DROPPED" {
		log.Action = "deny"
	} else { // default
		log.Action = "allow"
	}

	log.Direction = flow.TrafficDirection

	return log
}
