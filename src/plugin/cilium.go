package plugin

import (
	"encoding/json"
	"net/url"
	"strings"

	"github.com/accuknox/knoxAutoPolicy/src/types"

	flow "github.com/cilium/cilium/api/v1/flow"
)

// ============================ //
// == Traffic Flow Convertor == //
// ============================ //

// isSynFlagOnly function
func isSynFlagOnly(tcp *flow.TCP) bool {
	if tcp.Flags != nil && tcp.Flags.SYN && !tcp.Flags.ACK {
		return true
	}
	return false
}

// getL4Ports function
func getL4Ports(l4 *flow.Layer4) (int, int) {
	if l4.GetTCP() != nil {
		return int(l4.GetTCP().SourcePort), int(l4.GetTCP().DestinationPort)
	} else if l4.GetTCP() != nil {
		return int(l4.GetUDP().SourcePort), int(l4.GetTCP().DestinationPort)
	} else if l4.GetICMPv4() != nil {
		return int(l4.GetICMPv4().Type), int(l4.GetICMPv4().Code)
	} else {
		return -1, -1
	}
}

// getProtocol function
func getProtocol(l4 *flow.Layer4) int {
	if l4.GetTCP() != nil {
		return 6
	} else if l4.GetUDP() != nil {
		return 17
	} else if l4.GetICMPv4() != nil {
		return 1
	} else {
		return 0 // unknown?
	}
}

// getReservedLabelIfExist function
func getReservedLabelIfExist(labels []string) string {
	for _, label := range labels {
		if strings.HasPrefix(label, "reserved:") {
			return label
		}
	}

	return ""
}

// getDNS function
func getDNS(flow *flow.Flow) string {
	if flow.L7 != nil && flow.L7.GetDns() != nil {
		if flow.L7.GetType() == 1 && // REQUEST only
			!strings.HasSuffix(flow.L7.GetDns().Query, "cluster.local.") {
			q := strings.TrimSuffix(flow.L7.GetDns().Query, ".")
			return q
		}
	}

	return ""
}

// getHTTP function
func getHTTP(flow *flow.Flow) (string, string) {
	if flow.L7 != nil && flow.L7.GetHttp() != nil {
		if flow.L7.GetType() == 1 { // REQUEST only
			method := flow.L7.GetHttp().GetMethod()
			u, _ := url.Parse(flow.L7.GetHttp().GetUrl())
			path := u.Path
			return method, path
		}
	}

	return "", ""
}

// ConvertCiliumFlowToKnoxLog function
func ConvertCiliumFlowToKnoxLog(flow *flow.Flow) types.NetworkLog {
	log := types.NetworkLog{}

	// set namespace/pod
	if flow.Source.Namespace == "" {
		log.SrcMicroserviceName = getReservedLabelIfExist(flow.Source.Labels)
	} else {
		log.SrcMicroserviceName = flow.Source.Namespace
	}

	if flow.Source.PodName == "" {
		log.SrcContainerGroupName = flow.IP.Source
	} else {
		log.SrcContainerGroupName = flow.Source.GetPodName()
	}

	if flow.Destination.Namespace == "" {
		log.DstMicroserviceName = getReservedLabelIfExist(flow.Destination.Labels)
	} else {
		log.DstMicroserviceName = flow.Destination.Namespace
	}

	if flow.Destination.PodName == "" {
		log.DstContainerGroupName = flow.IP.Destination
	} else {
		log.DstContainerGroupName = flow.Destination.GetPodName()
	}

	// get action
	if flow.Verdict == 2 {
		log.Action = "deny"
	} else {
		log.Action = "allow"
	}

	// get egress / ingress
	log.Direction = flow.GetTrafficDirection().String()

	// get L3
	if flow.IP != nil {
		log.SrcIP = flow.IP.Source
		log.DstIP = flow.IP.Destination
	}

	// get L4
	if flow.L4 != nil {
		log.Protocol = getProtocol(flow.L4)
		if log.Protocol == 6 && flow.L4.GetTCP() != nil { // if tcp,
			log.SynFlag = isSynFlagOnly(flow.L4.GetTCP())
		}

		log.SrcPort, log.DstPort = getL4Ports(flow.L4)
	}

	// get L7
	log.DNSQuery = getDNS(flow)
	log.HTTPMethod, log.HTTPPath = getHTTP(flow)

	return log
}

// filterTrafficFlow function
func filterTrafficFlow(microName string, flow *flow.Flow) bool {
	// filter 1: microservice name (namespace)
	// skipList := []string{"kube-system", "kube-public", "kube-node-lease"}
	if flow.Source.Namespace != microName && flow.Destination.Namespace != microName {
		return false
	}

	// filter 2: packet is dropped (flow.Verdict == 2) and drop reason == 181 (Policy denied by denylist)
	if flow.Verdict == 2 && flow.DropReason == 181 {
		return false
	}

	return true
}

// ConvertCiliumFlowsToKnoxLogs function
func ConvertCiliumFlowsToKnoxLogs(microName string, docs []map[string]interface{}) []types.NetworkLog {
	networkLogs := []types.NetworkLog{}

	for _, doc := range docs {
		flow := &flow.Flow{}
		flowByte, _ := json.Marshal(doc)
		json.Unmarshal(flowByte, flow)

		if filterTrafficFlow(microName, flow) {
			log := ConvertCiliumFlowToKnoxLog(flow)
			networkLogs = append(networkLogs, log)
		}
	}

	return networkLogs
}

// ===================================== //
// == Cilium Network Policy Convertor == //
// ===================================== //

// buildNewCiliumNetworkPolicy function
func buildNewCiliumNetworkPolicy(inPolicy types.KnoxNetworkPolicy) types.CiliumNetworkPolicy {
	ciliumPolicy := types.CiliumNetworkPolicy{}

	ciliumPolicy.APIVersion = "cilium.io/v2"
	ciliumPolicy.Kind = "CiliumNetworkPolicy"
	ciliumPolicy.Metadata = inPolicy.Metadata

	// update selector matchLabels
	ciliumPolicy.Spec.Selector.MatchLabels = inPolicy.Spec.Selector.MatchLabels

	return ciliumPolicy
}

// TODO: search core-dns? or statically return dns pod
// getCoreDNSEndpoint function
func getCoreDNSEndpoint() []types.CiliumEndpoint {
	matchLabel := map[string]string{
		"k8s:io.kubernetes.pod.namespace": "kube-system",
		"k8s-app":                         "kube-dns",
	}

	coreDns := []types.CiliumEndpoint{types.CiliumEndpoint{matchLabel}}
	return coreDns
}

// ConvertKnoxPolicyToCiliumPolicy function
func ConvertKnoxPolicyToCiliumPolicy(inPolicy types.KnoxNetworkPolicy) types.CiliumNetworkPolicy {
	ciliumPolicy := buildNewCiliumNetworkPolicy(inPolicy)

	// ====== //
	// Egress //
	// ====== //
	if len(inPolicy.Spec.Egress) > 0 {
		ciliumPolicy.Spec.Egress = []types.CiliumEgress{}

		for _, knoxEgress := range inPolicy.Spec.Egress {
			ciliumEgress := types.CiliumEgress{}

			// ====================== //
			// build label-based rule //
			// ====================== //
			if knoxEgress.MatchLabels != nil {
				ciliumEgress.ToEndpoints = []types.CiliumEndpoint{types.CiliumEndpoint{knoxEgress.MatchLabels}}
			}

			// ================ //
			// build L4 toPorts //
			// ================ //
			for _, toPort := range knoxEgress.ToPorts {
				if toPort.Ports == "" { // if port number is none, skip
					continue
				}

				if ciliumEgress.ToPorts == nil {
					ciliumEgress.ToPorts = []types.CiliumPortList{}
					ciliumPort := types.CiliumPortList{}
					ciliumPort.Ports = []types.CiliumPort{}
					ciliumEgress.ToPorts = append(ciliumEgress.ToPorts, ciliumPort)

					// =============== //
					// build HTTP rule //
					// =============== //
					if len(knoxEgress.ToHTTPs) > 0 {
						ciliumEgress.ToPorts[0].Rules = map[string][]types.SubRule{}

						httpRules := []types.SubRule{}
						for _, http := range knoxEgress.ToHTTPs {
							// matchPattern
							httpRules = append(httpRules, map[string]string{"method": http.Method,
								"path": http.Path})
						}
						ciliumEgress.ToPorts[0].Rules = map[string][]types.SubRule{"http": httpRules}
					}
				}

				port := types.CiliumPort{Port: toPort.Ports, Protocol: strings.ToUpper(toPort.Protocol)}
				ciliumEgress.ToPorts[0].Ports = append(ciliumEgress.ToPorts[0].Ports, port)
			}

			// =============== //
			// build CIDR rule //
			// =============== //
			for _, toCIDR := range knoxEgress.ToCIDRs {
				cidrs := []string{}
				for _, cidr := range toCIDR.CIDRs {
					cidrs = append(cidrs, cidr)
				}
				ciliumEgress.ToCIDRs = cidrs

				// update toPorts if exist
				for _, toPort := range toCIDR.Ports {
					if toPort.Ports == "" { // if port number is none, skip
						continue
					}

					if ciliumEgress.ToPorts == nil {
						ciliumEgress.ToPorts = []types.CiliumPortList{}
						ciliumPort := types.CiliumPortList{}
						ciliumPort.Ports = []types.CiliumPort{}
						ciliumEgress.ToPorts = append(ciliumEgress.ToPorts, ciliumPort)
					}

					port := types.CiliumPort{Port: toPort.Ports, Protocol: strings.ToUpper(toPort.Protocol)}
					ciliumEgress.ToPorts[0].Ports = append(ciliumEgress.ToPorts[0].Ports, port)
				}
			}

			// ================= //
			// build Entity rule //
			// ================= //
			for _, entity := range knoxEgress.ToEndtities {
				if ciliumEgress.ToEndtities == nil {
					ciliumEgress.ToEndtities = []string{}
				}

				ciliumEgress.ToEndtities = append(ciliumEgress.ToEndtities, entity)
			}

			// ================== //
			// build Service rule //
			// ================== //
			for _, service := range knoxEgress.ToServices {
				if ciliumEgress.ToServices == nil {
					ciliumEgress.ToServices = []types.CiliumService{}
				}

				ciliumService := types.CiliumService{
					K8sService: []types.CiliumK8sService{
						types.CiliumK8sService{
							ServiceName: service.ServiceName,
							Namespace:   service.Namespace,
						},
					},
				}

				ciliumEgress.ToServices = append(ciliumEgress.ToServices, ciliumService)
			}

			// =============== //
			// build FQDN rule //
			// =============== //
			for _, fqdn := range knoxEgress.ToFQDNs {
				egressFqdn := types.CiliumEgress{}
				// TODO: static core-dns
				ciliumEgress.ToEndpoints = getCoreDNSEndpoint()

				if ciliumEgress.ToPorts == nil {
					ciliumEgress.ToPorts = []types.CiliumPortList{}
					ciliumPort := types.CiliumPortList{}
					ciliumPort.Ports = []types.CiliumPort{}
					ciliumEgress.ToPorts = append(ciliumEgress.ToPorts, ciliumPort)
				}

				for _, port := range fqdn.ToPorts {
					ciliumPort := types.CiliumPort{Port: port.Ports, Protocol: strings.ToUpper(port.Protocol)}
					ciliumEgress.ToPorts[0].Ports = append(ciliumEgress.ToPorts[0].Ports, ciliumPort)
				}

				// matchNames (TODO)
				// dnsRules := []types.DnsRule{}
				// for _, matchName := range fqdn.Matchnames {
				// 	dnsRules = append(dnsRules, map[string]string{"matchName": matchName})
				// }

				// matchPattern
				dnsRules := []types.SubRule{map[string]string{"matchPattern": "*"}}
				ciliumEgress.ToPorts[0].Rules = map[string][]types.SubRule{"dns": dnsRules}

				if egressFqdn.ToFQDNs == nil {
					egressFqdn.ToFQDNs = []map[string]string{}
				}

				for _, matchName := range fqdn.Matchnames {
					egressFqdn.ToFQDNs = append(egressFqdn.ToFQDNs, map[string]string{"matchName": matchName})
				}

				ciliumPolicy.Spec.Egress = append(ciliumPolicy.Spec.Egress, egressFqdn)
			}

			ciliumPolicy.Spec.Egress = append(ciliumPolicy.Spec.Egress, ciliumEgress)
		}
	}

	// ======= //
	// Ingress //
	// ===-=== //
	if len(inPolicy.Spec.Ingress) > 0 {
		ciliumPolicy.Spec.Ingress = []types.CiliumIngress{}

		for _, knoxIngress := range inPolicy.Spec.Ingress {
			ciliumIngress := types.CiliumIngress{}

			// ================= //
			// build label-based //
			// ================= //
			if knoxIngress.MatchLabels != nil {
				ciliumIngress.FromEndpoints = []types.CiliumEndpoint{types.CiliumEndpoint{knoxIngress.MatchLabels}}
			}

			// ================ //
			// build L4 toPorts //
			// ================ //
			for _, fromPort := range knoxIngress.ToPorts {
				if ciliumIngress.FromPorts == nil {
					ciliumIngress.FromPorts = []types.CiliumPortList{}
					ciliumPort := types.CiliumPortList{}
					ciliumPort.Ports = []types.CiliumPort{}
					ciliumIngress.FromPorts = append(ciliumIngress.FromPorts, ciliumPort)
				}

				port := types.CiliumPort{Port: fromPort.Ports, Protocol: strings.ToUpper(fromPort.Protocol)}
				ciliumIngress.FromPorts[0].Ports = append(ciliumIngress.FromPorts[0].Ports, port)
			}

			// =============== //
			// build CIDR rule //
			// =============== //
			for _, fromCIDR := range knoxIngress.FromCIDRs {
				for _, cidr := range fromCIDR.CIDRs {
					ciliumIngress.FromCIDRs = append(ciliumIngress.FromCIDRs, cidr)
				}

				// update toPorts if exist
				for _, fromPort := range fromCIDR.Ports {
					if fromPort.Ports == "" { // if port number is none, skip
						continue
					}

					if ciliumIngress.FromPorts == nil {
						ciliumIngress.FromPorts = []types.CiliumPortList{}
						ciliumPort := types.CiliumPortList{}
						ciliumPort.Ports = []types.CiliumPort{}
						ciliumIngress.FromPorts = append(ciliumIngress.FromPorts, ciliumPort)
					}

					port := types.CiliumPort{Port: fromPort.Ports, Protocol: strings.ToUpper(fromPort.Protocol)}
					ciliumIngress.FromPorts[0].Ports = append(ciliumIngress.FromPorts[0].Ports, port)
				}
			}

			// ================= //
			// build Entity rule //
			// ================= //
			for _, entity := range knoxIngress.FromEntities {
				if ciliumIngress.FromEntities == nil {
					ciliumIngress.FromEntities = []string{}
				}
				ciliumIngress.FromEntities = append(ciliumIngress.FromEntities, entity)
			}

			ciliumPolicy.Spec.Ingress = append(ciliumPolicy.Spec.Ingress, ciliumIngress)
		}

	}

	return ciliumPolicy
}
