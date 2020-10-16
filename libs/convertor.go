package libs

import (
	"github.com/seungsoo-lee/knoxAutoPolicy/types"
)

func getTrafficDirection(val int) string {
	if val == 1 {
		return "ingress"
	} else if val == 2 {
		return "egress"
	} else {
		return "unknown"
	}
}

func getL4Ports(l4 types.KnoxL4) (int, int) {
	if l4.TCP.SourcePort != 0 {
		return int(l4.TCP.SourcePort), int(l4.TCP.DestinationPort)
	} else if l4.UDP.SourcePort != 0 {
		return int(l4.UDP.SourcePort), int(l4.UDP.DestinationPort)
	} else {
		return -1, -1 // unkown
	}
}

func getProtocol(l4 types.KnoxL4) int {
	if l4.TCP.SourcePort != 0 {
		return 6
	} else if l4.UDP.SourcePort != 0 {
		return 17
	} else {
		return 1 // assume icmp for test
	}
}

func TrafficToLog(traffic types.NetworkTraffic) types.NetworkLog {
	log := types.NetworkLog{}

	log.HostName = traffic.NodeName

	log.SrcMicroserviceName = traffic.Source.Namespace
	log.SrcContainerGroupName = traffic.SrcPodName

	log.DstMicroserviceName = traffic.Destination.Namespace
	log.DstContainerGroupName = traffic.DstPodName

	log.SrcMac = traffic.Ethernet.Source
	log.DstMac = traffic.Ethernet.Destination

	log.Protocol = getProtocol(traffic.L4)

	log.SrcIP = traffic.IP.Source
	log.DstIP = traffic.IP.Destination

	log.SrcPort, log.DstPort = getL4Ports(traffic.L4)

	if traffic.Verdict == "1" {
		log.Action = "allow"
	}
	log.Direction = getTrafficDirection(traffic.TrafficDirection)

	return log
}
