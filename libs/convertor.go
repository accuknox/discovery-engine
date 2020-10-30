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
	if tcp.Flags != nil && tcp.Flags.SYN && !tcp.Flags.ACK {
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

func getReservedLabelIfExist(labels []string) string {
	for _, label := range labels {
		if strings.HasPrefix(label, "reserved:") {
			return label
		}
	}

	return ""
}

func getDnsQuery(flow *pb.TrafficFlow) string {
	if flow.L7 != nil && flow.L7.Dns != nil {
		if flow.L7.GetType() == "REQUEST" &&
			!strings.HasSuffix(flow.L7.Dns.GetQuery(), "cluster.local.") {
			q := strings.TrimSuffix(flow.L7.Dns.GetQuery(), ".")
			return q
		}
	}

	return ""
}

func ConvertKoxTrafficToLog(microName string, knoxTrafficFlow *types.KnoxTrafficFlow) types.NetworkLog {
	flow := knoxTrafficFlow.TrafficFlow

	log := types.NetworkLog{}

	// set namespace/pod
	if flow.Source.Namespace == "" {
		log.SrcMicroserviceName = getReservedLabelIfExist(flow.Source.Lables)
	} else {
		log.SrcMicroserviceName = flow.Source.Namespace
	}

	if flow.Source.Pod == "" {
		log.SrcContainerGroupName = flow.Ip.Source
	} else {
		log.SrcContainerGroupName = flow.Source.Pod
	}

	if flow.Destination.Namespace == "" {
		log.DstMicroserviceName = getReservedLabelIfExist(flow.Destination.Lables)
	} else {
		log.DstMicroserviceName = flow.Destination.Namespace
	}

	if flow.Destination.Pod == "" {
		log.DstContainerGroupName = flow.Ip.Destination
	} else {
		log.DstContainerGroupName = flow.Destination.Pod
	}

	// get action
	if flow.Verdict == "DROPPED" {
		log.Action = "deny"
	} else {
		log.Action = "allow"
	}

	// get egress / ingress
	log.Direction = flow.TrafficDirection

	// get L3
	if flow.Ip != nil {
		log.SrcIP = flow.Ip.Source
		log.DstIP = flow.Ip.Destination
	}

	// get L4
	if flow.L4 != nil {
		log.Protocol = getProtocol(flow.L4)
		if log.Protocol == 6 && flow.L4.TCP != nil { // if tcp,
			log.SynFlag = isSynFlagOnly(flow.L4.TCP)
		}

		log.SrcPort, log.DstPort = getL4Ports(flow.L4)
	}

	// get L7
	log.DNSQuery = getDnsQuery(flow)

	return log
}

func filterTrafficFlow(microName string, flow *types.KnoxTrafficFlow) bool {
	// filter 1: microservice name (namespace)
	if flow.TrafficFlow.Source.Namespace != microName {
		return false
	}

	// filter 2: packet is dropped and drop reason == 181 (Policy denied by denylist)
	if flow.TrafficFlow.Verdict == "DROPPED" && flow.DropReason == 181 {
		return false
	}

	return true
}

func ConvertTrafficFlowToLogs(microName string, flows []*types.KnoxTrafficFlow) []types.NetworkLog {
	networkLogs := []types.NetworkLog{}
	for _, flow := range flows {
		if filterTrafficFlow(microName, flow) {
			log := ConvertKoxTrafficToLog(microName, flow)
			networkLogs = append(networkLogs, log)
		}
	}

	return networkLogs
}

// ===================================== //
// == Cilium Network Policy Convertor == //
// ===================================== //

func buildBaseCiliumNetworkPolicy(inPolicy types.KnoxNetworkPolicy) types.CiliumNetworkPolicy {
	ciliumPolicy := types.CiliumNetworkPolicy{}

	ciliumPolicy.APIVersion = "cilium.io/v2"
	ciliumPolicy.Kind = "CiliumNetworkPolicy"
	ciliumPolicy.Metadata = inPolicy.Metadata

	// update selector matchLabels
	ciliumPolicy.Spec.Selector.MatchLabels = inPolicy.Spec.Selector.MatchLabels

	return ciliumPolicy
}

// TODO: search core-dns or dns pod
func getCoreDnsEndpoint() []types.CiliumEndpoint {
	matchLabel := map[string]string{
		"k8s:io.kubernetes.pod.namespace": "kube-system",
		"k8s-app":                         "kube-dns",
	}

	coreDns := []types.CiliumEndpoint{types.CiliumEndpoint{matchLabel}}
	return coreDns
}

func ToCiliumEgressNetworkPolicy(inPolicy types.KnoxNetworkPolicy) types.CiliumNetworkPolicy {
	ciliumPolicy := buildBaseCiliumNetworkPolicy(inPolicy)
	ciliumPolicy.Spec.Egress = []types.CiliumEgress{}

	// update egress matchLabels
	egress := types.CiliumEgress{}
	if inPolicy.Spec.Egress.MatchLabels != nil {
		egress.ToEndpoints = []types.CiliumEndpoint{types.CiliumEndpoint{inPolicy.Spec.Egress.MatchLabels}}
	}

	// pod -> pod: update toPorts
	for _, toPort := range inPolicy.Spec.Egress.ToPorts {
		if toPort.Ports == "" { // if port number is none, skip
			continue
		}

		if egress.ToPorts == nil {
			egress.ToPorts = []types.CiliumPortList{}
			ciliumPort := types.CiliumPortList{}
			ciliumPort.Ports = []types.CiliumPort{}
			egress.ToPorts = append(egress.ToPorts, ciliumPort)
		}

		port := types.CiliumPort{Port: toPort.Ports, Protocol: strings.ToUpper(toPort.Protocol)}
		egress.ToPorts[0].Ports = append(egress.ToPorts[0].Ports, port)
	}

	// pod -> cidr: update toCIDRs
	for _, toCIDR := range inPolicy.Spec.Egress.ToCIDRs {
		cidrs := []string{}
		for _, cidr := range toCIDR.CIDRs {
			cidrs = append(cidrs, cidr)
		}
		egress.ToCIDRs = cidrs

		// update toPorts if exist
		for _, toPort := range toCIDR.Ports {
			if toPort.Ports == "" { // if port number is none, skip
				continue
			}

			if egress.ToPorts == nil {
				egress.ToPorts = []types.CiliumPortList{}
				ciliumPort := types.CiliumPortList{}
				ciliumPort.Ports = []types.CiliumPort{}
				egress.ToPorts = append(egress.ToPorts, ciliumPort)
			}

			port := types.CiliumPort{Port: toPort.Ports, Protocol: strings.ToUpper(toPort.Protocol)}
			egress.ToPorts[0].Ports = append(egress.ToPorts[0].Ports, port)
		}
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

	// update toFQDNs
	egressFqdn := types.CiliumEgress{}
	for _, fqdn := range inPolicy.Spec.Egress.ToFQDNs {
		// TODO: static core-dns
		egress.ToEndpoints = getCoreDnsEndpoint()

		if egress.ToPorts == nil {
			egress.ToPorts = []types.CiliumPortList{}
			ciliumPort := types.CiliumPortList{}
			ciliumPort.Ports = []types.CiliumPort{}
			egress.ToPorts = append(egress.ToPorts, ciliumPort)
		}

		for _, port := range fqdn.ToPorts {
			ciliumPort := types.CiliumPort{Port: port.Ports, Protocol: strings.ToUpper(port.Protocol)}
			egress.ToPorts[0].Ports = append(egress.ToPorts[0].Ports, ciliumPort)
		}

		dnsRules := []types.DnsRule{types.DnsRule{"matchPattern": "*"}}
		egress.ToPorts[0].Rules = map[string][]types.DnsRule{"dns": dnsRules}

		if egressFqdn.ToFQDNs == nil {
			egressFqdn.ToFQDNs = []map[string]string{}
		}

		for _, matchName := range fqdn.Matchnames {
			egressFqdn.ToFQDNs = append(egressFqdn.ToFQDNs, map[string]string{"matchName": matchName})
		}
	}

	ciliumPolicy.Spec.Egress = append(ciliumPolicy.Spec.Egress, egress)

	if egressFqdn.ToFQDNs != nil && len(egressFqdn.ToFQDNs) > 0 {
		ciliumPolicy.Spec.Egress = append(ciliumPolicy.Spec.Egress, egressFqdn)
	}

	return ciliumPolicy
}

func ToCiliumIngressNetworkPolicy(inPolicy types.KnoxNetworkPolicy) types.CiliumNetworkPolicy {
	ciliumPolicy := buildBaseCiliumNetworkPolicy(inPolicy)

	// update ingress
	ingress := types.CiliumIngress{}

	if inPolicy.Spec.Ingress.MatchLabels != nil {
		matchLabels := map[string]string{}
		for k, v := range inPolicy.Spec.Ingress.MatchLabels {
			matchLabels[k] = v
		}

		fromEndpoints := []types.CiliumEndpoint{types.CiliumEndpoint{matchLabels}}
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
		for _, cidr := range fromCIDR.CIDRs {
			ingress.FromCIDRs = append(ingress.FromCIDRs, cidr)
		}

		// update toPorts if exist
		for _, fromPort := range fromCIDR.Ports {
			if fromPort.Ports == "" { // if port number is none, skip
				continue
			}

			if ingress.FromPorts == nil {
				ingress.FromPorts = []types.CiliumPortList{}
				ciliumPort := types.CiliumPortList{}
				ciliumPort.Ports = []types.CiliumPort{}
				ingress.FromPorts = append(ingress.FromPorts, ciliumPort)
			}

			port := types.CiliumPort{Port: fromPort.Ports, Protocol: strings.ToUpper(fromPort.Protocol)}
			ingress.FromPorts[0].Ports = append(ingress.FromPorts[0].Ports, port)
		}
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
		inPolicy.Spec.Egress.ToServices != nil ||
		inPolicy.Spec.Egress.ToFQDNs != nil {
		return ToCiliumEgressNetworkPolicy(inPolicy)
	} else {
		return ToCiliumIngressNetworkPolicy(inPolicy)
	}
}
