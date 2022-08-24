package plugin

import (
	"context"
	"encoding/json"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/accuknox/auto-policy-discovery/src/config"
	"github.com/accuknox/auto-policy-discovery/src/libs"
	logger "github.com/accuknox/auto-policy-discovery/src/logging"
	obs "github.com/accuknox/auto-policy-discovery/src/observability"
	"github.com/accuknox/auto-policy-discovery/src/types"
	"github.com/rs/zerolog"
	"google.golang.org/grpc"

	"github.com/cilium/cilium/api/v1/flow"
	cilium "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/api/v1/observer"
	cu "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/utils"
)

var CiliumReserved string = "reserved:"

var TrafficDirection = map[string]int{
	"TRAFFIC_DIRECTION_UNKNOWN": 0,
	"INGRESS":                   1,
	"EGRESS":                    2,
}

var TraceObservationPoint = map[string]int{
	"UNKNOWN_POINT": 0,
	"TO_PROXY":      1,
	"TO_HOST":       2,
	"TO_STACK":      3,
	"TO_OVERLAY":    4,
	"TO_ENDPOINT":   101,
	"FROM_ENDPOINT": 5,
	"FROM_PROXY":    6,
	"FROM_HOST":     7,
	"FROM_STACK":    8,
	"FROM_OVERLAY":  9,
	"FROM_NETWORK":  10,
	"TO_NETWORK":    11,
}

var Verdict = map[string]int{
	"VERDICT_UNKNOWN": 0,
	"FORWARDED":       1,
	"DROPPED":         2,
	"ERROR":           3,
}

// ======================= //
// == Global Variables  == //
// ======================= //

var CiliumFlows []*cilium.Flow
var CiliumFlowsMutex *sync.Mutex
var CiliumFlowsFC []*types.KnoxNetworkLog
var CiliumFlowsFCMutex *sync.Mutex

var log *zerolog.Logger

func init() {
	log = logger.GetInstance()
	CiliumFlowsMutex = &sync.Mutex{}
	KubeArmorRelayLogsMutex = &sync.Mutex{}
	CiliumFlowsFCMutex = &sync.Mutex{}
	KubeArmorFCLogsMutex = &sync.Mutex{}
}

// ====================== //
// == Helper Functions == //
// ====================== //

func convertVerdictToInt(vType interface{}) int {
	return Verdict[vType.(string)]
}

func convertTrafficDirectionToInt(tType interface{}) int {
	return TrafficDirection[tType.(string)]
}

func isSynFlagOnly(tcp *cilium.TCP) bool {
	if tcp.Flags != nil && tcp.Flags.SYN && !tcp.Flags.ACK {
		return true
	}
	return false
}

func getL4Ports(l4 *cilium.Layer4) (int, int) {
	if l4.GetTCP() != nil {
		return int(l4.GetTCP().SourcePort), int(l4.GetTCP().DestinationPort)
	} else if l4.GetUDP() != nil {
		return int(l4.GetUDP().SourcePort), int(l4.GetUDP().DestinationPort)
	} else if l4.GetICMPv4() != nil {
		return int(l4.GetICMPv4().Type), int(l4.GetICMPv4().Code)
	} else {
		return -1, -1
	}
}

func getICMPType(l4 *cilium.Layer4) int {
	if l4.GetICMPv4() != nil {
		return int(l4.GetICMPv4().GetType())
	} else if l4.GetICMPv6() != nil {
		return int(l4.GetICMPv6().GetType())
	} else {
		return -1
	}
}

func getProtocol(l4 *cilium.Layer4) int {
	if l4.GetTCP() != nil {
		return libs.IPProtocolTCP
	} else if l4.GetUDP() != nil {
		return libs.IPProtocolUDP
	} else if l4.GetICMPv4() != nil {
		return libs.IPProtocolICMP
	} else if l4.GetICMPv6() != nil {
		return libs.IPProtocolICMPv6
	} else {
		return libs.IPProtoUnknown
	}
}

func getReservedLabelsIfExist(labels []string) []string {
	var reservedLabels []string
	for _, label := range labels {
		if strings.HasPrefix(label, "reserved:") {
			reservedLabels = append(reservedLabels, label)
		}
	}

	return reservedLabels
}

func getHTTP(flow *cilium.Flow) (string, string) {
	if flow.L7 != nil && flow.L7.GetHttp() != nil {
		if flow.L7.GetType() == 1 { // REQUEST only
			method := flow.L7.GetHttp().GetMethod()
			u, _ := url.Parse(flow.L7.GetHttp().GetUrl())
			path := u.Path

			if strings.HasPrefix(path, "//") {
				path = strings.Replace(path, "//", "/", 1)
			}

			return method, path
		}
	}

	return "", ""
}

// ============================ //
// == Network Flow Convertor == //
// ============================ //

func ConvertCiliumFlowToKnoxNetworkLog(ciliumFlow *cilium.Flow) (types.KnoxNetworkLog, bool) {
	log := types.KnoxNetworkLog{}

	// TODO: packet is dropped (flow.Verdict == 2) and drop reason == 181 (Flows denied by deny policy)?
	// http://github.com/cilium/cilium/blob/f3887bd83f6f7495f5d487fe1002896488b9495f/bpf/lib/common.h#L432s
	if ciliumFlow.Verdict == cilium.Verdict_DROPPED && ciliumFlow.GetDropReasonDesc() == 181 {
		return log, false
	}

	// set action
	if ciliumFlow.Verdict == 2 {
		log.Action = "deny"
	} else {
		log.Action = "allow"
	}

	// set EGRESS / INGRESS
	log.Direction = ciliumFlow.GetTrafficDirection().String()

	// set namespace
	log.SrcNamespace = ciliumFlow.Source.Namespace
	log.DstNamespace = ciliumFlow.Destination.Namespace

	// set pod
	log.SrcPodName = ciliumFlow.Source.GetPodName()
	log.DstPodName = ciliumFlow.Destination.GetPodName()

	// copy reservedLabels
	log.DstReservedLabels = getReservedLabelsIfExist(ciliumFlow.Destination.Labels)
	log.SrcReservedLabels = getReservedLabelsIfExist(ciliumFlow.Source.Labels)

	log.IsReply = ciliumFlow.GetIsReply().GetValue()

	// get L3
	if ciliumFlow.IP != nil {
		log.SrcIP = ciliumFlow.IP.Source
		log.DstIP = ciliumFlow.IP.Destination
	} else {
		return log, false
	}

	// get L4
	if ciliumFlow.L4 != nil {
		log.Protocol = getProtocol(ciliumFlow.L4)

		if libs.IsICMP(log.Protocol) {
			log.ICMPType = getICMPType(ciliumFlow.L4)
			// Sometimes, ICMP flow for certain `type` (like EchoReply)
			// does not have the `IsReply` flag set in the Cilium Flow.
			// So we cannot fully rely on `IsReply` flag in case of ICMP flows.
			if libs.IsReplyICMP(log.ICMPType) {
				log.IsReply = true
			}
		} else { // tcp & udp
			log.SrcPort, log.DstPort = getL4Ports(ciliumFlow.L4)
		}

		if log.Protocol == libs.IPProtocolTCP {
			log.SynFlag = isSynFlagOnly(ciliumFlow.L4.GetTCP())
		}
	} else {
		return log, false
	}

	// get L7 HTTP
	if ciliumFlow.GetL7() != nil && ciliumFlow.L7.GetHttp() != nil {
		log.HTTPMethod, log.HTTPPath = getHTTP(ciliumFlow)
		if log.HTTPMethod == "" && log.HTTPPath == "" {
			return log, false
		}
		log.L7Protocol = libs.L7ProtocolHTTP
	}

	// get L7 DNS
	if ciliumFlow.GetL7() != nil && ciliumFlow.L7.GetDns() != nil {
		// if DSN response includes IPs
		if ciliumFlow.L7.GetType() == 2 && len(ciliumFlow.L7.GetDns().Ips) > 0 {
			// if internal services, skip
			if strings.HasSuffix(ciliumFlow.L7.GetDns().GetQuery(), "svc.cluster.local.") {
				return log, false
			}

			query := strings.TrimSuffix(ciliumFlow.L7.GetDns().GetQuery(), ".")
			ips := ciliumFlow.L7.GetDns().GetIps()

			log.DNSRes = query
			log.DNSResIPs = ips
			log.L7Protocol = libs.L7ProtocolDNS
		}
	}

	return log, true
}

func ConvertSQLiteCiliumLogsToKnoxNetworkLogs(docs []map[string]interface{}) []types.KnoxNetworkLog {
	logs := []types.KnoxNetworkLog{}

	for _, doc := range docs {
		ciliumFlow := &cilium.Flow{}
		var err error

		primitiveDoc := map[string]interface{}{
			"traffic_direction": convertTrafficDirectionToInt(doc["traffic_direction"]),
			"verdict":           convertVerdictToInt(doc["verdict"]),
			"policy_match_type": doc["policy_match_type"],
			"drop_reason":       doc["drop_reason"],
		}

		flowByte, err := json.Marshal(primitiveDoc)
		if err != nil {
			log.Error().Msg("Error while unmarshing primitives :" + err.Error())
			continue
		}

		err = json.Unmarshal(flowByte, ciliumFlow)
		if err != nil {
			log.Error().Msg("Error while unmarshing primitives :" + err.Error())
			continue
		}

		if doc["event_type"] != nil {
			err = json.Unmarshal(doc["event_type"].([]byte), &ciliumFlow.EventType)
			if err != nil {
				log.Error().Msg("Error while unmarshing event type :" + err.Error())
				continue
			}
		}

		if doc["source"] != nil {
			err = json.Unmarshal(doc["source"].([]byte), &ciliumFlow.Source)
			if err != nil {
				log.Error().Msg("Error while unmarshing source :" + err.Error())
				continue
			}
		}

		if doc["destination"] != nil {
			err = json.Unmarshal(doc["destination"].([]byte), &ciliumFlow.Destination)
			if err != nil {
				log.Error().Msg("Error while unmarshing destination :" + err.Error())
				continue
			}
		}

		if doc["ip"] != nil {
			err = json.Unmarshal(doc["ip"].([]byte), &ciliumFlow.IP)
			if err != nil {
				log.Error().Msg("Error while unmarshing ip :" + err.Error())
				continue
			}
		}

		if doc["l4"] != nil {
			err = json.Unmarshal(doc["l4"].([]byte), &ciliumFlow.L4)
			if err != nil {
				log.Error().Msg("Error while unmarshing l4 :" + err.Error())
				continue
			}
		}

		if doc["l7"] != nil {
			l7Byte := doc["l7"].([]byte)
			if len(l7Byte) != 0 {
				err = json.Unmarshal(l7Byte, &ciliumFlow.L7)
				if err != nil {
					log.Error().Msg("Error while unmarshing l7 :" + err.Error())
					continue
				}
			}
		}

		if log, valid := ConvertCiliumFlowToKnoxNetworkLog(ciliumFlow); valid {
			// get flow id
			log.FlowID = int(doc["id"].(uint32))

			// get cluster name
			log.ClusterName = doc["cluster_name"].(string)

			logs = append(logs, log)
		}
	}

	return logs
}

func ConvertMySQLCiliumLogsToKnoxNetworkLogs(docs []map[string]interface{}) []types.KnoxNetworkLog {
	logs := []types.KnoxNetworkLog{}

	for _, doc := range docs {
		ciliumFlow := &cilium.Flow{}
		var err error

		primitiveDoc := map[string]interface{}{
			"traffic_direction": convertTrafficDirectionToInt(doc["traffic_direction"]),
			"verdict":           convertVerdictToInt(doc["verdict"]),
			"policy_match_type": doc["policy_match_type"],
			"drop_reason":       doc["drop_reason"],
		}

		flowByte, err := json.Marshal(primitiveDoc)
		if err != nil {
			log.Error().Msg("Error while unmarshing primitives :" + err.Error())
			continue
		}

		err = json.Unmarshal(flowByte, ciliumFlow)
		if err != nil {
			log.Error().Msg("Error while unmarshing primitives :" + err.Error())
			continue
		}

		if doc["event_type"] != nil {
			err = json.Unmarshal(doc["event_type"].([]byte), &ciliumFlow.EventType)
			if err != nil {
				log.Error().Msg("Error while unmarshing event type :" + err.Error())
				continue
			}
		}

		if doc["source"] != nil {
			err = json.Unmarshal(doc["source"].([]byte), &ciliumFlow.Source)
			if err != nil {
				log.Error().Msg("Error while unmarshing source :" + err.Error())
				continue
			}
		}

		if doc["destination"] != nil {
			err = json.Unmarshal(doc["destination"].([]byte), &ciliumFlow.Destination)
			if err != nil {
				log.Error().Msg("Error while unmarshing destination :" + err.Error())
				continue
			}
		}

		if doc["ip"] != nil {
			err = json.Unmarshal(doc["ip"].([]byte), &ciliumFlow.IP)
			if err != nil {
				log.Error().Msg("Error while unmarshing ip :" + err.Error())
				continue
			}
		}

		if doc["l4"] != nil {
			err = json.Unmarshal(doc["l4"].([]byte), &ciliumFlow.L4)
			if err != nil {
				log.Error().Msg("Error while unmarshing l4 :" + err.Error())
				continue
			}
		}

		if doc["l7"] != nil {
			l7Byte := doc["l7"].([]byte)
			if len(l7Byte) != 0 {
				err = json.Unmarshal(l7Byte, &ciliumFlow.L7)
				if err != nil {
					log.Error().Msg("Error while unmarshing l7 :" + err.Error())
					continue
				}
			}
		}

		if log, valid := ConvertCiliumFlowToKnoxNetworkLog(ciliumFlow); valid {
			// get flow id
			log.FlowID = int(doc["id"].(uint32))

			// get cluster name
			log.ClusterName = doc["cluster_name"].(string)

			logs = append(logs, log)
		}
	}

	return logs
}

func ConvertMongodCiliumLogsToKnoxNetworkLogs(docs []map[string]interface{}) []types.KnoxNetworkLog {
	logs := []types.KnoxNetworkLog{}

	for _, doc := range docs {
		flow := &cilium.Flow{}
		flowByte, _ := json.Marshal(doc)
		if err := json.Unmarshal(flowByte, flow); err != nil {
			log.Error().Msg(err.Error())
			continue
		}

		if log, valid := ConvertCiliumFlowToKnoxNetworkLog(flow); valid {
			logs = append(logs, log)
		}
	}

	return logs
}

func ConvertCiliumNetworkLogsToKnoxNetworkLogs(dbDriver string, docs []map[string]interface{}) []types.KnoxNetworkLog {
	if dbDriver == "mysql" {
		return ConvertMySQLCiliumLogsToKnoxNetworkLogs(docs)
	} else if dbDriver == "sqlite3" {
		return ConvertSQLiteCiliumLogsToKnoxNetworkLogs(docs)
	} else if dbDriver == "mongo" {
		return ConvertMongodCiliumLogsToKnoxNetworkLogs(docs)
	} else {
		return []types.KnoxNetworkLog{}
	}
}

func GetFlowData(netLogEventType []byte, flowEventType interface{}) error {
	if netLogEventType == nil {
		return nil
	}
	err := json.Unmarshal(netLogEventType, flowEventType)
	if err != nil {
		log.Error().Msg("error while unmarshing event type :" + err.Error())
	}
	return err
}

// ============================== //
// == Network Policy Convertor == //
// ============================== //

// TODO: search core-dns? or statically return dns pod
func getCoreDNSEndpoint(services []types.Service) ([]types.CiliumEndpoint, []types.CiliumPortList) {
	matchLabel := map[string]string{
		"k8s:io.kubernetes.pod.namespace": "kube-system",
		"k8s-app":                         "kube-dns",
	}

	coreDNS := []types.CiliumEndpoint{{matchLabel}}

	ciliumPort := types.CiliumPortList{}
	ciliumPort.Ports = []types.CiliumPort{}

	if len(services) == 0 { // add statically
		ciliumPort.Ports = append(ciliumPort.Ports, types.CiliumPort{
			Port: strconv.Itoa(53), Protocol: strings.ToUpper("UDP")},
		)
	} else { // search DNS
		for _, svc := range services {
			if svc.Namespace == "kube-system" && svc.ServiceName == "kube-dns" {
				ciliumPort.Ports = append(ciliumPort.Ports, types.CiliumPort{
					Port: strconv.Itoa(svc.ServicePort), Protocol: strings.ToUpper(svc.Protocol)},
				)
			}
		}
	}

	toPorts := []types.CiliumPortList{ciliumPort}

	// matchPattern
	dnsRules := []types.SubRule{map[string]string{"matchPattern": "*"}}
	toPorts[0].Rules = map[string][]types.SubRule{"dns": dnsRules}

	return coreDNS, toPorts
}

func buildNewCiliumNetworkPolicy(inPolicy types.KnoxNetworkPolicy) types.CiliumNetworkPolicy {
	ciliumPolicy := types.CiliumNetworkPolicy{}

	ciliumPolicy.APIVersion = "cilium.io/v2"
	ciliumPolicy.Metadata = map[string]string{}
	for k, v := range inPolicy.Metadata {
		if k == "name" || k == "namespace" {
			ciliumPolicy.Metadata[k] = v
		}
	}

	if inPolicy.Kind == types.KindKnoxHostNetworkPolicy {
		ciliumPolicy.Kind = cu.ResourceTypeCiliumClusterwideNetworkPolicy
		ciliumPolicy.Spec.NodeSelector.MatchLabels = inPolicy.Spec.Selector.MatchLabels
	} else {
		ciliumPolicy.Kind = cu.ResourceTypeCiliumNetworkPolicy
		ciliumPolicy.Spec.EndpointSelector.MatchLabels = inPolicy.Spec.Selector.MatchLabels
	}

	return ciliumPolicy
}

func ConvertKnoxNetworkPolicyToCiliumPolicy(inPolicy types.KnoxNetworkPolicy) types.CiliumNetworkPolicy {
	ciliumPolicy := buildNewCiliumNetworkPolicy(inPolicy)

	// ====== //
	// Egress //
	// ====== //
	if len(inPolicy.Spec.Egress) > 0 {
		ciliumPolicy.Spec.Egress = []types.CiliumEgress{}

		for _, knoxEgress := range inPolicy.Spec.Egress {
			ciliumEgress := types.CiliumEgress{}

			if knoxEgress.MatchLabels != nil {
				// ====================== //
				// build label-based rule //
				// ====================== //
				ciliumEgress.ToEndpoints = []types.CiliumEndpoint{{knoxEgress.MatchLabels}}
			} else if len(knoxEgress.ToCIDRs) > 0 {
				// =============== //
				// build CIDR rule //
				// =============== //
				for _, toCIDR := range knoxEgress.ToCIDRs {
					cidrs := []string{}
					cidrs = append(cidrs, toCIDR.CIDRs...)
					ciliumEgress.ToCIDRs = cidrs
				}
			} else if len(knoxEgress.ToEntities) > 0 {
				// ================= //
				// build Entity rule //
				// ================= //
				for _, entity := range knoxEgress.ToEntities {
					if ciliumEgress.ToEntities == nil {
						ciliumEgress.ToEntities = []string{}
					}
					ciliumEgress.ToEntities = append(ciliumEgress.ToEntities, entity)
				}
			} else if len(knoxEgress.ToFQDNs) > 0 {
				// =============== //
				// build FQDN rule //
				// =============== //
				for _, fqdn := range knoxEgress.ToFQDNs {
					if ciliumEgress.ToFQDNs == nil {
						ciliumEgress.ToFQDNs = []types.CiliumFQDN{}
					}

					// FQDN (+ToPorts)
					for _, matchName := range fqdn.MatchNames {
						ciliumEgress.ToFQDNs = append(ciliumEgress.ToFQDNs, map[string]string{"matchName": matchName})
					}
				}
			} else if len(knoxEgress.ToServices) > 0 {
				// ================== //
				// build Service rule //
				// ================== //
				for _, service := range knoxEgress.ToServices {
					if ciliumEgress.ToServices == nil {
						ciliumEgress.ToServices = []types.CiliumService{}
					}

					ciliumService := types.CiliumService{
						K8sService: types.CiliumK8sService{
							ServiceName: service.ServiceName,
							Namespace:   service.Namespace,
						},
					}

					ciliumEgress.ToServices = append(ciliumEgress.ToServices, ciliumService)
				}
			}

			// ================ //
			// build L4 toPorts //
			// ================ //
			for _, toPort := range knoxEgress.ToPorts {
				if toPort.Port == "" { // if port number is none, skip
					continue
				}

				if ciliumEgress.ToPorts == nil {
					ciliumEgress.ToPorts = []types.CiliumPortList{{Ports: []types.CiliumPort{}}}
				}

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

				port := types.CiliumPort{Port: toPort.Port, Protocol: strings.ToUpper(toPort.Protocol)}
				ciliumEgress.ToPorts[0].Ports = append(ciliumEgress.ToPorts[0].Ports, port)
			}

			// ================ //
			// build ICMP rule  //
			// ================ //
			for _, icmp := range knoxEgress.ICMPs {
				if ciliumEgress.ICMPs == nil {
					ciliumEgress.ICMPs = []types.CiliumICMP{{Fields: []types.CiliumICMPField{}}}
				}
				newField := types.CiliumICMPField{
					Family: icmp.Family,
					Type:   icmp.Type,
				}
				ciliumEgress.ICMPs[0].Fields = append(ciliumEgress.ICMPs[0].Fields, newField)
			}

			ciliumPolicy.Spec.Egress = append(ciliumPolicy.Spec.Egress, ciliumEgress)
		}
	}

	// ======= //
	// Ingress //
	// ======= //
	if len(inPolicy.Spec.Ingress) > 0 {
		ciliumPolicy.Spec.Ingress = []types.CiliumIngress{}

		for _, knoxIngress := range inPolicy.Spec.Ingress {
			ciliumIngress := types.CiliumIngress{}

			// ================= //
			// build label-based //
			// ================= //
			if knoxIngress.MatchLabels != nil {
				ciliumIngress.FromEndpoints = []types.CiliumEndpoint{{knoxIngress.MatchLabels}}
			}

			// =============== //
			// build CIDR rule //
			// =============== //
			for _, fromCIDR := range knoxIngress.FromCIDRs {
				ciliumIngress.FromCIDRs = append(ciliumIngress.FromCIDRs, fromCIDR.CIDRs...)
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

			// ================ //
			// build L4 toPorts //
			// ================ //
			for _, toPort := range knoxIngress.ToPorts {
				if ciliumIngress.ToPorts == nil {
					ciliumIngress.ToPorts = []types.CiliumPortList{{Ports: []types.CiliumPort{}}}
				}

				// =============== //
				// build HTTP rule //
				// =============== //
				if len(knoxIngress.ToHTTPs) > 0 {
					ciliumIngress.ToPorts[0].Rules = map[string][]types.SubRule{}

					httpRules := []types.SubRule{}
					for _, http := range knoxIngress.ToHTTPs {
						// matchPattern
						httpRules = append(httpRules, map[string]string{"method": http.Method,
							"path": http.Path})
					}
					ciliumIngress.ToPorts[0].Rules = map[string][]types.SubRule{"http": httpRules}
				}

				port := types.CiliumPort{Port: toPort.Port, Protocol: strings.ToUpper(toPort.Protocol)}
				ciliumIngress.ToPorts[0].Ports = append(ciliumIngress.ToPorts[0].Ports, port)
			}

			// ================ //
			// build ICMP rule  //
			// ================ //
			for _, icmp := range knoxIngress.ICMPs {
				if ciliumIngress.ICMPs == nil {
					ciliumIngress.ICMPs = []types.CiliumICMP{{Fields: []types.CiliumICMPField{}}}
				}
				newField := types.CiliumICMPField{
					Family: icmp.Family,
					Type:   icmp.Type,
				}
				ciliumIngress.ICMPs[0].Fields = append(ciliumIngress.ICMPs[0].Fields, newField)
			}

			ciliumPolicy.Spec.Ingress = append(ciliumPolicy.Spec.Ingress, ciliumIngress)
		}

	}

	return ciliumPolicy
}

func ConvertKnoxPoliciesToCiliumPolicies(policies []types.KnoxNetworkPolicy) []types.CiliumNetworkPolicy {
	ciliumPolicies := []types.CiliumNetworkPolicy{}

	for _, policy := range policies {
		ciliumPolicy := ConvertKnoxNetworkPolicyToCiliumPolicy(policy)
		ciliumPolicies = append(ciliumPolicies, ciliumPolicy)
	}

	return ciliumPolicies
}

// ========================= //
// == Cilium Hubble Relay == //
// ========================= //

func ConnectHubbleRelay(cfg types.ConfigCiliumHubble) *grpc.ClientConn {
	addr := net.JoinHostPort(cfg.HubbleURL, cfg.HubblePort)

	conn, err := grpc.Dial(addr, grpc.WithInsecure())
	if err != nil {
		log.Error().Err(err)
		return nil
	}

	log.Info().Msg("dialed for hubble relay:" + addr)
	return conn
}

func GetCiliumFlowsFromHubble(trigger int) []*cilium.Flow {
	results := []*cilium.Flow{}

	CiliumFlowsMutex.Lock()
	if len(CiliumFlows) == 0 {
		log.Info().Msgf("Cilium hubble traffic flow not exist")
		CiliumFlowsMutex.Unlock()
		return results
	}

	if len(CiliumFlows) < trigger {
		log.Info().Msgf("The number of cilium hubble traffic flow [%d] is less than trigger [%d]", len(CiliumFlows), trigger)
		CiliumFlowsMutex.Unlock()
		return results
	}

	results = CiliumFlows          // copy
	CiliumFlows = []*cilium.Flow{} // reset
	CiliumFlowsMutex.Unlock()

	fisrtDoc := results[0]
	lastDoc := results[len(results)-1]

	// id/time filter update
	startTime := fisrtDoc.Time.Seconds
	endTime := lastDoc.Time.Seconds

	log.Info().Msgf("The total number of cilium hubble traffic flow: [%d] from %s ~ to %s", len(results),
		time.Unix(startTime, 0).Format(libs.TimeFormSimple),
		time.Unix(endTime, 0).Format(libs.TimeFormSimple))

	return results
}

var HubbleRelayStarted = false

func StartHubbleRelay(StopChan chan struct{}, cfg types.ConfigCiliumHubble) {
	if HubbleRelayStarted {
		return
	}
	conn := ConnectHubbleRelay(cfg)
	if conn == nil {
		log.Error().Msg("ConnectHubbleRelay() failed")
		return
	}
	HubbleRelayStarted = true

	defer func() {
		log.Info().Msg("hubble relay stream rcvr returning")
		HubbleRelayStarted = false
		_ = conn.Close()
	}()

	client := observer.NewObserverClient(conn)

	req := &observer.GetFlowsRequest{
		Follow: true,
		Whitelist: []*cilium.FlowFilter{
			{
				TcpFlags: []*flow.TCPFlags{
					{SYN: true},
					{FIN: true},
					{RST: true},
					{NS: true},
					{ECE: true},
				},
			},
			{
				Protocol: []string{"udp", "icmp", "http", "dns"},
			},
		},
	}

	nsFilter := config.CurrentCfg.ConfigNetPolicy.NsFilter
	nsNotFilter := config.CurrentCfg.ConfigSysPolicy.NsNotFilter

	stream, err := client.GetFlows(context.Background(), req)
	if err != nil {
		log.Error().Msg("Unable to stream network flow: " + err.Error())
		return
	}
	for {
		select {
		case <-StopChan:
			return

		default:
			res, err := stream.Recv()
			if err != nil {
				log.Error().Msg("Cilium network flow stream stopped: " + err.Error())
				return
			}

			switch r := res.ResponseTypes.(type) {
			case *observer.GetFlowsResponse_Flow:
				flow := r.Flow

				if IgnoreLogFromRelayWithNamespace(nsFilter, nsNotFilter, flow.Source.Namespace) {
					continue
				}

				CiliumFlowsMutex.Lock()
				CiliumFlows = append(CiliumFlows, flow)
				CiliumFlowsMutex.Unlock()

				if config.GetCfgObservabilityEnable() {
					obs.ProcessCiliumFlow(flow)
				}
			}
		}
	}
}

func GetCiliumFlowsFromFeedConsumer(trigger int) []*types.KnoxNetworkLog {
	results := []*types.KnoxNetworkLog{}

	CiliumFlowsFCMutex.Lock()
	defer CiliumFlowsFCMutex.Unlock()
	if len(CiliumFlowsFC) == 0 {
		log.Info().Msgf("Cilium feed-consumer traffic flow not exist")
		return results
	}

	if len(CiliumFlowsFC) < trigger {
		log.Info().Msgf("The number of cilium feed-consumer traffic flow [%d] is less than trigger [%d]", len(CiliumFlowsFC), trigger)
		return results
	}

	results = CiliumFlowsFC                   // copy
	CiliumFlowsFC = []*types.KnoxNetworkLog{} // reset

	log.Info().Msgf("The total number of cilium feed-consumer traffic flow: [%d]", len(results))

	return results
}
