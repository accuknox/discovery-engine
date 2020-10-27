package libs

import (
	"strings"

	"github.com/accuknox/knoxAutoPolicy/types"
	pb "github.com/accuknox/knoxServiceFlowMgmt/src/proto"
)

// ============================ //
// == Traffic Flow Convertor == //
// ============================ //

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

func getReservedLabel(labels []string) string {
	for _, label := range labels {
		if strings.HasPrefix(label, "reserved:") {
			return label
		}
	}

	return "unknown"
}

func ConvertKoxTrafficToLog(microName string, knoxTrafficFlow *types.KnoxTrafficFlow) (types.NetworkLog, bool) {
	log := types.NetworkLog{}

	flow := knoxTrafficFlow.TrafficFlow

	if flow.Source.Namespace == "" {
		log.SrcMicroserviceName = getReservedLabel(flow.Source.Lables)
	} else {
		log.SrcMicroserviceName = flow.Source.Namespace
	}

	if flow.Source.Pod == "" {
		log.SrcContainerGroupName = flow.Ip.Source
	} else {
		log.SrcContainerGroupName = flow.Source.Pod
	}

	if flow.Destination.Namespace == "" {
		log.DstMicroserviceName = getReservedLabel(flow.Destination.Lables)
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
		log.Action = "unknown"
	}

	log.Direction = flow.TrafficDirection

	// filter 1: microservice name (namespace)
	if log.SrcMicroserviceName != microName && log.DstMicroserviceName != microName {
		return log, false
	}

	// filter 2: packet is dropped and drop reason == 181 (Policy denied by denylist)
	if flow.Verdict == "DROPPED" && knoxTrafficFlow.DropReason == 181 {
		return log, false
	}

	return log, true
}

func ConvertTrafficFlowToLogs(microName string, flows []*types.KnoxTrafficFlow) []types.NetworkLog {
	networkLogs := []types.NetworkLog{}
	for _, flow := range flows {
		log, valid := ConvertKoxTrafficToLog(microName, flow)
		if !valid {
			continue
		}

		networkLogs = append(networkLogs, log)
	}

	return networkLogs
}

// ===================================== //
// == Cilium Network Policy Convertor == //
// ===================================== //

func ToCiliumEgressNetworkPolicy(inPolicy types.KnoxNetworkPolicy) types.CiliumNetworkPolicy {
	ciliumPolicy := types.CiliumNetworkPolicy{}

	ciliumPolicy.APIVersion = "cilium.io/v2"
	ciliumPolicy.Kind = "CiliumNetworkPolicy"
	ciliumPolicy.Metadata = map[string]string{}
	for k, v := range inPolicy.Metadata {
		ciliumPolicy.Metadata[k] = v
	}

	// update selector matchLabels
	ciliumPolicy.Spec.Selector.MatchLabels = map[string]string{}
	for k, v := range inPolicy.Spec.Selector.MatchLabels {
		ciliumPolicy.Spec.Selector.MatchLabels[k] = v
	}

	// update egress matchLabels
	egress := types.CiliumEgress{}
	if inPolicy.Spec.Egress.MatchLabels != nil {
		matchLabels := map[string]string{}
		for k, v := range inPolicy.Spec.Egress.MatchLabels {
			matchLabels[k] = v
		}

		toEndpoints := []types.CiliumEndpoints{types.CiliumEndpoints{matchLabels}}
		egress.ToEndpoints = toEndpoints
	}

	// update toPorts
	for _, toPort := range inPolicy.Spec.Egress.ToPorts {
		if egress.ToPorts == nil {
			egress.ToPorts = []types.CiliumPortList{}
			ciliumPort := types.CiliumPortList{}
			ciliumPort.Ports = []types.CiliumPort{}
			egress.ToPorts = append(egress.ToPorts, ciliumPort)
		}

		port := types.CiliumPort{Port: toPort.Ports, Protocol: strings.ToUpper(toPort.Protocol)}
		egress.ToPorts[0].Ports = append(egress.ToPorts[0].Ports, port)
	}

	// update toCIDRs
	for _, toCIDR := range inPolicy.Spec.Egress.ToCIDRs {
		egress.ToCIDRs = append(egress.ToCIDRs, toCIDR.CIDR)
	}

	// update toEntities
	for _, entity := range inPolicy.Spec.Egress.ToEndtities {
		if egress.ToEndtities == nil {
			egress.ToEndtities = []string{}
		}

		egress.ToEndtities = append(egress.ToEndtities, entity)
	}

	// update toServices
	for _, service := range inPolicy.Spec.Egress.ToServices {
		if egress.ToServices == nil {
			egress.ToServices = []types.CiliumService{}
		}
		ciliumService := types.CiliumService{
			K8sService: []types.CiliumK8sService{
				types.CiliumK8sService{
					ServiceName: service.ServiceName,
					Namespace:   service.Namespace,
				},
			},
		}
		egress.ToServices = append(egress.ToServices, ciliumService)
	}

	ciliumPolicy.Spec.Egress = []types.CiliumEgress{}
	ciliumPolicy.Spec.Egress = append(ciliumPolicy.Spec.Egress, egress)

	return ciliumPolicy
}

func ToCiliumIngressNetworkPolicy(inPolicy types.KnoxNetworkPolicy) types.CiliumNetworkPolicy {
	ciliumPolicy := types.CiliumNetworkPolicy{}

	ciliumPolicy.APIVersion = "cilium.io/v2"
	ciliumPolicy.Kind = "CiliumNetworkPolicy"
	ciliumPolicy.Metadata = map[string]string{}
	for k, v := range inPolicy.Metadata {
		ciliumPolicy.Metadata[k] = v
	}

	// update selector
	ciliumPolicy.Spec.Selector.MatchLabels = map[string]string{}
	for k, v := range inPolicy.Spec.Selector.MatchLabels {
		ciliumPolicy.Spec.Selector.MatchLabels[k] = v
	}

	// update ingress
	ingress := types.CiliumIngress{}

	if inPolicy.Spec.Ingress.MatchLabels != nil {
		matchLabels := map[string]string{}
		for k, v := range inPolicy.Spec.Ingress.MatchLabels {
			matchLabels[k] = v
		}

		fromEndpoints := []types.CiliumEndpoints{types.CiliumEndpoints{matchLabels}}
		ingress.FromEndpoints = fromEndpoints
	}

	// update fromPorts
	for _, fromPort := range inPolicy.Spec.Ingress.FromPorts {
		if ingress.FromPorts == nil {
			ingress.FromPorts = []types.CiliumPortList{}
			ciliumPort := types.CiliumPortList{}
			ciliumPort.Ports = []types.CiliumPort{}
			ingress.FromPorts = append(ingress.FromPorts, ciliumPort)
		}

		port := types.CiliumPort{Port: fromPort.Ports, Protocol: strings.ToUpper(fromPort.Protocol)}
		ingress.FromPorts[0].Ports = append(ingress.FromPorts[0].Ports, port)
	}

	// update fromCIDRs
	for _, fromCIDR := range inPolicy.Spec.Ingress.FromCIDRs {
		ingress.FromCIDRs = append(ingress.FromCIDRs, fromCIDR.CIDR)
	}

	// update fromEntities
	for _, entity := range inPolicy.Spec.Ingress.FromEntities {
		if ingress.FromEntities == nil {
			ingress.FromEntities = []string{}
		}
		ingress.FromEntities = append(ingress.FromEntities, entity)
	}

	ciliumPolicy.Spec.Ingress = []types.CiliumIngress{}
	ciliumPolicy.Spec.Ingress = append(ciliumPolicy.Spec.Ingress, ingress)

	return ciliumPolicy
}

func ToCiliumNetworkPolicy(inPolicy types.KnoxNetworkPolicy) types.CiliumNetworkPolicy {
	if inPolicy.Spec.Egress.MatchLabels != nil ||
		inPolicy.Spec.Egress.ToCIDRs != nil ||
		inPolicy.Spec.Egress.ToPorts != nil ||
		inPolicy.Spec.Egress.ToEndtities != nil ||
		inPolicy.Spec.Egress.ToServices != nil {
		return ToCiliumEgressNetworkPolicy(inPolicy)
	} else {
		return ToCiliumIngressNetworkPolicy(inPolicy)
	}
}
