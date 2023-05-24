package networkpolicy

import (
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/accuknox/auto-policy-discovery/src/cluster"
	"github.com/accuknox/auto-policy-discovery/src/config"
	cfg "github.com/accuknox/auto-policy-discovery/src/config"
	fc "github.com/accuknox/auto-policy-discovery/src/feedconsumer"
	"github.com/accuknox/auto-policy-discovery/src/libs"
	logger "github.com/accuknox/auto-policy-discovery/src/logging"
	"github.com/accuknox/auto-policy-discovery/src/plugin"
	"github.com/accuknox/auto-policy-discovery/src/types"
	cu "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/utils"
	"github.com/clarketm/json"
	"github.com/google/go-cmp/cmp"
	"sigs.k8s.io/yaml"

	"github.com/robfig/cron"
	"github.com/rs/zerolog"
)

var log *zerolog.Logger

func init() {
	log = logger.GetInstance()
}

// const values
const (
	// operation mode
	OP_MODE_NOOP    = 0
	OP_MODE_CRONJOB = 1
	OP_MODE_ONETIME = 2

	// status
	STATUS_RUNNING = "running"
	STATUS_IDLE    = "idle"
)

// ================================== //
// == Discovery Policy/Rule Types  == //
// ================================== //

// const values
const (
	// discovery policy type
	EGRESS         = 1
	INGRESS        = 2
	EGRESS_INGRESS = 3

	// discovery rule type
	MATCH_LABELS  = 1 << 0 // 1
	TO_ICMPS      = 1 << 1 // 2
	TO_PORTS      = 1 << 2 // 4
	TO_HTTPS      = 1 << 3 // 8
	TO_CIDRS      = 1 << 4 // 16
	TO_ENTITIES   = 1 << 5 // 32
	TO_SERVICES   = 1 << 6 // 64
	TO_FQDNS      = 1 << 7 // 126
	FROM_CIDRS    = 1 << 8 // 256
	FROM_ENTITIES = 1 << 9 // 512
)

const (
	PolicyTypeIngress = "ingress"
	PolicyTypeEgress  = "egress"
)

const (
	ReservedHost  = "reserved:host"
	ReservedWorld = "reserved:world"
)

// ====================== //
// == Global Variables == //
// ====================== //

// NetworkWorkerStatus global worker
var NetworkWorkerStatus string

// for cron job
var NetworkCronJob *cron.Cron

// var NetworkWaitG sync.WaitGroup
var NetworkStopChan chan struct{} // for hubble
var OperationTrigger int
var CfgDB types.ConfigDB

var NetworkLogFrom string
var NetworkLogFile string
var NetworkPolicyTo string

var CIDRBits int
var HTTPThreshold int

var L3DiscoveryLevel int
var L4DiscoveryLevel int
var L7DiscoveryLevel int

var NetworkLogFilters []types.NetworkLogFilter
var NamespaceFilters []string

// init Function
func init() {
	NetworkWorkerStatus = STATUS_IDLE
	NetworkStopChan = make(chan struct{})
	// NetworkWaitG = sync.WaitGroup{}
}

func InitNetPolicyDiscoveryConfiguration() {
	CfgDB = cfg.GetCfgDB()

	OperationTrigger = cfg.GetCfgNetOperationTrigger()

	NetworkLogFrom = cfg.GetCfgNetworkLogFrom()
	NetworkLogFile = cfg.GetCfgNetworkLogFile()
	NetworkPolicyTo = cfg.GetCfgNetworkPolicyTo()

	L3DiscoveryLevel = cfg.GetCfgNetworkL3Level()
	L4DiscoveryLevel = cfg.GetCfgNetworkL4Level()
	L7DiscoveryLevel = cfg.GetCfgNetworkL7Level()

	CIDRBits = cfg.GetCfgCIDRBits()
	HTTPThreshold = cfg.GetCfgNetworkHTTPThreshold()

	NetworkLogFilters = cfg.GetCfgNetworkLogFilters()
	NamespaceFilters = cfg.GetCfgNetworkSkipNamespaces()
}

// ============================= //
// == Multi Cluster Variables == //
// ============================= //

// k8s service ports
var K8sServiceTCPPorts []int
var K8sServiceUDPPorts []int
var K8sServiceSCTPPorts []int

// K8sDNSServices kube-dns services
var K8sDNSServices []types.Service

// labeledSrcsPerDstMap [key: simple Dst, value: simple Src]
type labeledSrcsPerDstMap map[Dst][]SrcSimple

// LabeledSrcsPerDst [key: namespace, value: LabeledSrcsPerDstMap]
var LabeledSrcsPerDst map[string]labeledSrcsPerDstMap

// DomainToIPs [key: domain name, value: ip addresses]
var DomainToIPs map[string][]string

// FlowIDTrackerFirst flow ids (stored in DB) tracking
// To show a discovered policy comes from which network logs
var FlowIDTrackerFirst map[FlowIDTrackingFirst][]int
var FlowIDTrackerSecond map[FlowIDTrackingSecond][]int

type ClusterVariable struct {
	K8sServiceTCPPorts  []int
	K8sServiceUDPPorts  []int
	K8sServiceSCTPPorts []int
	K8sDNSServices      []types.Service

	LabeledSrcsPerDst map[string]labeledSrcsPerDstMap
	DomainToIPs       map[string][]string

	FlowIDTrackerFirst  map[FlowIDTrackingFirst][]int
	FlowIDTrackerSecond map[FlowIDTrackingSecond][]int
}

// ClusterVariableMap [key: cluster name, val: cluster variable]
var ClusterVariableMap = map[string]ClusterVariable{}

// ========================== //
// == Inner Structure Type == //
// ========================== //

type SrcSimple struct {
	Namespace   string
	PodName     string
	MatchLabels string
}

type DstSimple struct {
	Namespace  string
	PodName    string
	Additional string
}

type Dst struct {
	Namespace   string
	PodName     string
	Additional  string
	MatchLabels string
	ICMPType    int
	Protocol    int
	DstPort     int
	HTTP        string
}

type MergedPortDst struct {
	FlowIDs []int

	Namespace   string
	PodName     string
	Additionals []string
	MatchLabels string
	ToPorts     []types.SpecPort
	ICMPs       []types.SpecICMP
	ToHTTPs     []types.SpecHTTP
}

type LabelCount struct {
	Label string
	Count float64
}

type FlowIDTrackingFirst struct {
	Src SrcSimple
	Dst Dst
}

type FlowIDTrackingSecond struct {
	AggreagtedSrc string
	Dst           Dst
}

type IcmpPortPair struct {
	ICMPs []types.SpecICMP
	Ports []types.SpecPort
}

type Selector struct {
	Kind   string
	Labels string
}

// =========================================== //
// == Step 1: Grouping Network Logs Per Dst == //
// =========================================== //

func getDst(log types.KnoxNetworkLog, services []types.Service, cidrBits int) (Dst, bool) {
	var httpInfo string

	// check HTTP
	if log.HTTPMethod != "" && log.HTTPPath != "" {
		httpInfo = log.HTTPMethod + "|" + log.HTTPPath
	}

	// check DNS
	if log.DNSQuery != "" {
		dst := Dst{
			Namespace:  "reserved:dns",
			Additional: log.DNSQuery,
			Protocol:   log.Protocol,
			DstPort:    log.DstPort,
			HTTP:       httpInfo,
		}

		return dst, true
	}

	if log.DstPodName == "" {
		/*
			// check CIDR (out of cluster)
			if libs.ContainsElement(log.DstReservedLabels, ReservedWorld) && log.DstIP != "" {
				cidr := ""
				if svc, valid := checkK8sService(log, services); valid {
					// 1. check if the dst IP belongs to a service
					log.DstNamespace = svc.Namespace
					for k, v := range svc.Selector {
						labels = append(labels, k+"="+v)
					}
				} else {
					// 3. else, handle it as cidr policy
					log.DstNamespace = "reserved:cidr"
					ipNetwork := log.DstIP + "/" + strconv.Itoa(cidrBits)
					_, network, _ := net.ParseCIDR(ipNetwork)
					cidr = network.String()
				}

				dst := Dst{
					Namespace:   log.DstNamespace,
					Additional:  cidr,
					Protocol:    log.Protocol,
					DstPort:     log.DstPort,
					ICMPType:    log.ICMPType,
					MatchLabels: strings.Join(labels, ","),
					HTTP:        httpInfo,
				}

				return dst, true
			}
		*/

		// reserved entities -> host, remote-node, kube-apiserver
		if len(log.DstReservedLabels) > 0 {
			entities := []string{}

			for _, label := range log.DstReservedLabels {
				entities = append(entities, strings.TrimPrefix(label, "reserved:"))
			}

			dst := Dst{
				Namespace:  "reserved:entities",
				Additional: strings.Join(entities, ","),
				Protocol:   log.Protocol,
				DstPort:    log.DstPort,
				ICMPType:   log.ICMPType,
				HTTP:       httpInfo,
			}
			return dst, true
		}
	}

	if !libs.IsICMP(log.Protocol) {
		// if dst port is unexposed and namespace is not reserved, it's invalid
		if !isExposedPort(log.Protocol, log.DstPort) && !strings.HasPrefix(log.DstNamespace, "reserved:") {
			return Dst{}, false
		}
	}

	dst := Dst{
		Namespace: log.DstNamespace,
		PodName:   log.DstPodName,
		Protocol:  log.Protocol,
		DstPort:   log.DstPort,
		ICMPType:  log.ICMPType,
		HTTP:      httpInfo,
	}

	return dst, true
}

func groupNetworkLogPerDst(networkLogs []types.KnoxNetworkLog, services []types.Service, cidrBits int) map[Dst][]types.KnoxNetworkLog {
	perDst := map[Dst][]types.KnoxNetworkLog{}

	for _, log := range networkLogs {
		dst, valid := getDst(log, services, cidrBits)
		if !valid {
			continue
		}

		if _, ok := perDst[dst]; !ok {
			perDst[dst] = []types.KnoxNetworkLog{log}
		} else {
			perDst[dst] = append(perDst[dst], log)
		}
	}

	// remove tcp dst which is included in http dst
	for dst := range perDst {
		if dst.Protocol == libs.IPProtocolTCP && CheckHTTPMethod(dst.HTTP) {
			dstCopy := dst

			dstCopy.HTTP = ""
			for tcp := range perDst {
				if dstCopy == tcp {
					delete(perDst, tcp)
				}
			}
		}
	}

	return perDst
}

// ====================================== //
// == Step 2: Replacing Src to Labeled == //
// ====================================== //

func extractSrcByLabel(labeledSrcsPerDst map[Dst][]SrcSimple, perDst map[Dst][]types.KnoxNetworkLog, pods []types.Pod) map[Dst][]SrcSimple {
	for dst, logs := range perDst {
		srcs := []SrcSimple{}

		for _, log := range logs {
			src := SrcSimple{}

			// if src is reserved
			if len(log.SrcReservedLabels) > 0 {
				src = SrcSimple{
					MatchLabels: strings.Join(log.SrcReservedLabels, ","),
				}
			} else {
				// else get merged and sorted matchlables: "a=b,c=d,e=f"
				mergedSortedLabels := getMergedSortedLabels(log.SrcNamespace, log.SrcPodName, pods)
				if mergedSortedLabels == "" {
					continue
				}

				src = SrcSimple{
					Namespace:   log.SrcNamespace,
					PodName:     log.SrcPodName,
					MatchLabels: mergedSortedLabels}
			}

			// storing flow IDs per DST before replacing by labels
			trackFlowIDFirst(src, dst, log.FlowID)

			// remove redundant
			if !libs.ContainsElement(srcs, src) {
				srcs = append(srcs, src)
			}
		}

		if val, ok := labeledSrcsPerDst[dst]; ok {
			for _, src := range srcs {
				if !libs.ContainsElement(val, src) {
					val = append(val, src)
				}
			}

			// update srcs
			labeledSrcsPerDst[dst] = val
		} else {
			// or, set new srcs
			labeledSrcsPerDst[dst] = srcs
		}
	}

	return labeledSrcsPerDst
}

// ============================================= //
// == Step 3: Aggregating Src Based on Labels == //
// ============================================= //

func checkIncludeAllSrcPods(superSetLabels string, srcs []SrcSimple, pods []types.Pod) bool {
	srcNamespace := ""
	labels := strings.Split(superSetLabels, ",")

	// temporary pod struct
	type innerPod struct {
		namespace string
		podName   string
	}

	// 1. get pods from srcs
	podNamesFromSrcs := []innerPod{}
	for _, src := range srcs {
		srcNamespace = src.Namespace

		include := true
		for _, label := range labels {
			if !strings.Contains(src.MatchLabels, label) {
				include = false
				break
			}
		}

		if include {
			podNamesFromSrcs = append(podNamesFromSrcs, innerPod{
				namespace: src.Namespace,
				podName:   src.PodName,
			})
		}
	}

	// 2. get pods from k8s
	podNamesFromK8s := []innerPod{}
	for _, pod := range pods {
		if pod.Namespace != srcNamespace {
			continue
		}

		include := true
		for _, label := range labels {
			if !libs.ContainsElement(pod.Labels, label) {
				include = false
				break
			}
		}

		if include {
			podNamesFromK8s = append(podNamesFromK8s, innerPod{
				namespace: pod.Namespace,
				podName:   pod.PodName,
			})
		}
	}

	// 3. compare two slices
	srcIncludeAllK8sPods := true
	for _, pod := range podNamesFromSrcs {
		if libs.ContainsElement(podNamesFromK8s, pod) {
			srcIncludeAllK8sPods = false
			break
		}
	}

	return srcIncludeAllK8sPods
}

func aggregateSrcByLabel(labeledSrcsPerDst map[Dst][]SrcSimple, pods []types.Pod) map[Dst][]string {
	aggregatedSrcsPerDst := map[Dst][]string{}

	for dst, srcs := range labeledSrcsPerDst {
		aggregatedSrcsPerDst[dst] = []string{}

		// srcs namespace is target namespace except for the reserved:
		// if l3 aggregation level 2 or 3, aggregate labels
		if L3DiscoveryLevel >= 2 {
			// first, count each src label (a=b:1 a=b,c=d:2 e=f:1, ... )
			labelCountMap := map[string]int{}
			for _, src := range srcs {
				countLabelByCombinations(labelCountMap, src.MatchLabels)
			}

			// sorting label by descending order (e=f:10, f=e:9, d=s:5, ...)
			countPerLabels := descendingLabelCountMap(labelCountMap)

			// enumerating src label by descending order
			for _, countPerLabel := range countPerLabels {
				// aggregate if at least match count >= 2
				if countPerLabel.Count >= 2 {
					// the label could be single (a=b) or combined (a=b,c=d)
					aggregatedLabel := countPerLabel.Label

					// if the level 2, the super set of labels should be included in all the pods to be aggregated
					if L3DiscoveryLevel == 2 && !checkIncludeAllSrcPods(aggregatedLabel, srcs, pods) {
						continue
					}

					// if 'src' contains the label, remove 'src' from srcs
					for _, src := range srcs {
						if containLabel(aggregatedLabel, src.MatchLabels) {
							trackFlowIDSecond(aggregatedLabel, src, dst)
							srcs = removeSrcFromSlice(srcs, src)

							// append the label (the removed src included) to the dst
							if !libs.ContainsElement(aggregatedSrcsPerDst[dst], aggregatedLabel) {
								aggregatedSrcsPerDst[dst] = append(aggregatedSrcsPerDst[dst], aggregatedLabel)
							}
						}
					}
				}
			}
		}

		// if there is remained src or l3 aggregate level 1, append it
		for _, src := range srcs {
			trackFlowIDSecond(src.MatchLabels, src, dst)
			aggregatedSrcsPerDst[dst] = append(aggregatedSrcsPerDst[dst], src.MatchLabels)
		}
	}

	return aggregatedSrcsPerDst
}

// =========================================== //
// == Step 4: Merging Dst's Protocol + Port == //
// =========================================== //

func mergeCIDR(mergedSrcPerMergedDst map[string][]MergedPortDst) {
	// merge cidr dst per each merged Src
	for aggregatedSrc, dsts := range mergedSrcPerMergedDst {
		newDsts := []MergedPortDst{}

		// cidrMap, key: cidr addr, val: icmps & toPorts rules
		cidrMap := map[string]IcmpPortPair{}

		// cidrFlowIDMap key: cidr addr, val: flow ids
		cidrFlowIDMap := map[string][]int{}

		// step 1: get cidr
		for _, dst := range dsts {
			if dst.Namespace == "reserved:cidr" {
				// get tracked flowIDs
				flowIDs := dst.FlowIDs

				for _, cidrAddr := range dst.Additionals {
					if icmpPortPair, ok := cidrMap[cidrAddr]; !ok {
						// if not exist, create cidr, and move icmps & toPorts
						cidrMap[cidrAddr] = IcmpPortPair{dst.ICMPs, dst.ToPorts}
					} else {
						// if exist, check duplicated toPorts
						for _, port := range dst.ToPorts {
							if !libs.ContainsElement(icmpPortPair.Ports, port) {
								icmpPortPair.Ports = append(icmpPortPair.Ports, port)
							}
						}
						// append icmps
						for _, icmp := range dst.ICMPs {
							if !libs.ContainsElement(icmpPortPair.ICMPs, icmp) {
								icmpPortPair.ICMPs = append(icmpPortPair.ICMPs, icmp)
							}
						}
						// update toPorts
						cidrMap[cidrAddr] = icmpPortPair
					}

					// update flow ids
					if existFlowIDs, ok := cidrFlowIDMap[cidrAddr]; !ok {
						cidrFlowIDMap[cidrAddr] = flowIDs
					} else {
						for _, id := range existFlowIDs {
							if !libs.ContainsElement(existFlowIDs, id) {
								existFlowIDs = append(existFlowIDs, id)
								cidrFlowIDMap[cidrAddr] = existFlowIDs
							}
						}
					}
				}

			} else {
				// if no reserved:cidr
				newDsts = append(newDsts, dst)
			}
		}

		// step 2: update mergedSrcPerMergedDst
		for cidrAddr, icmpPortPair := range cidrMap {
			newDst := MergedPortDst{
				FlowIDs:     cidrFlowIDMap[cidrAddr],
				Namespace:   "reserved:cidr",
				Additionals: []string{cidrAddr},
				ToPorts:     icmpPortPair.Ports,
				ICMPs:       icmpPortPair.ICMPs,
			}
			newDsts = append(newDsts, newDst)
		}

		mergedSrcPerMergedDst[aggregatedSrc] = newDsts
	}
}

func mergeFQDN(mergedSrcPerMergedDst map[string][]MergedPortDst) {
	// merge same dns per each aggregated Src
	for aggregatedSrc, dsts := range mergedSrcPerMergedDst {
		newDsts := []MergedPortDst{}

		// dnsMap key: domain name, val: icmp & toPorts rules
		dnsMap := map[string]IcmpPortPair{}

		// dnsFlowIDMap key: domain name, val: flow ids
		dnsFlowIDMap := map[string][]int{}

		// step 1: get dns
		for _, dst := range dsts {
			if dst.Namespace == "reserved:dns" {
				// get tracked flowIDs
				flowIDs := dst.FlowIDs

				for _, domainName := range dst.Additionals {
					if icmpPortPair, ok := dnsMap[domainName]; !ok {
						// if not exist, create dns, and move toPorts
						dnsMap[domainName] = IcmpPortPair{dst.ICMPs, dst.ToPorts}

					} else {
						// if exist, check duplicated toPorts
						for _, port := range dst.ToPorts {
							if !libs.ContainsElement(icmpPortPair.Ports, port) {
								icmpPortPair.Ports = append(icmpPortPair.Ports, port)
							}
						}
						// append icmps
						for _, icmp := range dst.ICMPs {
							if !libs.ContainsElement(icmpPortPair.ICMPs, icmp) {
								icmpPortPair.ICMPs = append(icmpPortPair.ICMPs, icmp)
							}
						}
						// update toPorts
						dnsMap[domainName] = icmpPortPair
					}

					// update flow ids
					if existFlowIDs, ok := dnsFlowIDMap[domainName]; !ok {
						dnsFlowIDMap[domainName] = flowIDs
					} else {
						for _, id := range existFlowIDs {
							if !libs.ContainsElement(existFlowIDs, id) {
								existFlowIDs = append(existFlowIDs, id)
								dnsFlowIDMap[domainName] = existFlowIDs
							}
						}
					}
				}
			} else {
				// if no reserved:dns
				newDsts = append(newDsts, dst)
			}
		}

		// step 2: update mergedSrcPerMergedDst
		for domainName, icmpPortPair := range dnsMap {
			newDNS := MergedPortDst{
				FlowIDs:     dnsFlowIDMap[domainName],
				Namespace:   "reserved:dns",
				Additionals: []string{domainName},
				ToPorts:     icmpPortPair.Ports,
				ICMPs:       icmpPortPair.ICMPs,
			}
			newDsts = append(newDsts, newDNS)
		}

		mergedSrcPerMergedDst[aggregatedSrc] = newDsts
	}
}

func mergeEntities(mergedSrcPerMergedDst map[string][]MergedPortDst) {
	// merge entities dst per each merged Src
	for aggregatedSrc, dsts := range mergedSrcPerMergedDst {
		newDsts := []MergedPortDst{}

		// entityMap, key: entities addr, val: icmps & toPorts rules
		entityMap := map[string]IcmpPortPair{}

		// entityFlowIDMap key: entities addr, val: flow ids
		entityFlowIDMap := map[string][]int{}

		// step 1: get entities
		for _, dst := range dsts {
			if dst.Namespace == "reserved:entities" {
				// get tracked flowIDs
				flowIDs := dst.FlowIDs

				entities := strings.Split(dst.Additionals[0], ",")

				for _, entity := range entities {
					if icmpPortPair, ok := entityMap[entity]; !ok {
						// if not exist, create entities, and move icmps & toPorts
						entityMap[entity] = IcmpPortPair{dst.ICMPs, dst.ToPorts}
					} else {
						// if exist, check duplicated toPorts
						for _, port := range dst.ToPorts {
							if !libs.ContainsElement(icmpPortPair.Ports, port) {
								icmpPortPair.Ports = append(icmpPortPair.Ports, port)
							}
						}
						// append icmps
						for _, icmp := range dst.ICMPs {
							if !libs.ContainsElement(icmpPortPair.ICMPs, icmp) {
								icmpPortPair.ICMPs = append(icmpPortPair.ICMPs, icmp)
							}
						}
						// update toPorts
						entityMap[entity] = icmpPortPair
					}

					// update flow ids
					if existFlowIDs, ok := entityFlowIDMap[entity]; !ok {
						entityFlowIDMap[entity] = flowIDs
					} else {
						for _, id := range existFlowIDs {
							if !libs.ContainsElement(existFlowIDs, id) {
								existFlowIDs = append(existFlowIDs, id)
								entityFlowIDMap[entity] = existFlowIDs
							}
						}
					}
				}

			} else {
				// if no reserved:entities
				newDsts = append(newDsts, dst)
			}
		}

		// step 2: update mergedSrcPerMergedDst
		for entity, icmpPortPair := range entityMap {
			newDst := MergedPortDst{
				FlowIDs:     entityFlowIDMap[entity],
				Namespace:   "reserved:entities",
				Additionals: []string{entity},
				ToPorts:     icmpPortPair.Ports,
				ICMPs:       icmpPortPair.ICMPs,
			}
			newDsts = append(newDsts, newDst)
		}

		mergedSrcPerMergedDst[aggregatedSrc] = newDsts
	}
}

func mergeProtocolPorts(src string, dsts []Dst) []MergedPortDst {
	if len(dsts) == 0 {
		return nil
	}

	l7MergedDsts := map[int]MergedPortDst{}

	l4DstExists := false
	l7DstExists := false

	l4MergedDst := MergedPortDst{
		Namespace:   dsts[0].Namespace,
		PodName:     dsts[0].PodName,
		MatchLabels: dsts[0].MatchLabels,
		Additionals: []string{dsts[0].Additional},
	}

	for _, dst := range dsts {
		if !CheckHTTPMethod(dst.HTTP) {
			// L4 dst
			// Merged all the L4 dsts into one dst

			l4DstExists = true

			if libs.IsICMP(dst.Protocol) {
				family := "IPv4"
				if dst.Protocol == libs.IPProtocolICMPv6 {
					family = "IPv6"
				}
				l4MergedDst.ICMPs = []types.SpecICMP{{
					Family: family,
					Type:   uint8(dst.ICMPType),
				}}
			} else {
				l4MergedDst.ToPorts = []types.SpecPort{{
					Protocol: libs.GetProtocol(dst.Protocol),
					Port:     strconv.Itoa(dst.DstPort),
				}}
			}

			flowIDs := getFlowIDFromTrackMap2(src, dst)
			for _, id := range flowIDs {
				if !libs.ContainsElement(l4MergedDst.FlowIDs, id) {
					l4MergedDst.FlowIDs = append(l4MergedDst.FlowIDs, id)
				}
			}
		} else if dst.Protocol == libs.IPProtocolTCP {
			// L7 dst
			// Group the L7 (http) dsts based on TCP port
			// Create one MergedDst per group (combine http path/method together)

			l7DstExists = true

			mergedDst, ok := l7MergedDsts[dst.DstPort]
			if !ok {
				toPort := []types.SpecPort{{
					Protocol: libs.GetProtocol(dst.Protocol),
					Port:     strconv.Itoa(dst.DstPort),
				}}

				mergedDst = MergedPortDst{
					Namespace:   dst.Namespace,
					PodName:     dst.PodName,
					MatchLabels: dst.MatchLabels,
					Additionals: []string{dst.Additional},
					ToPorts:     toPort,
				}
			}

			method, path := strings.Split(dst.HTTP, "|")[0], strings.Split(dst.HTTP, "|")[1]
			toHTTP := types.SpecHTTP{
				Method: method,
				Path:   path,
			}
			mergedDst.ToHTTPs = append(mergedDst.ToHTTPs, toHTTP)
			l7MergedDsts[dst.DstPort] = mergedDst
		}
	}

	l47Dsts := []MergedPortDst{}
	if l4DstExists {
		l47Dsts = append(l47Dsts, l4MergedDst)
	}
	if l7DstExists {
		for _, l7Dst := range l7MergedDsts {
			l47Dsts = append(l47Dsts, l7Dst)
		}
	}
	return l47Dsts
}

func mergeDstByProtoPort(aggregatedSrcsPerDst map[Dst][]string) map[string][]MergedPortDst {
	aggregatedSrcPerMergedDst := map[string][]MergedPortDst{}

	// convert {dst: [srcs]} -> {src: [dsts]}
	dstsPerAggregatedSrc := map[string][]Dst{}
	for dst, aggregatedSrcs := range aggregatedSrcsPerDst {
		for _, aggregatedSrc := range aggregatedSrcs {
			if dstsPerAggregatedSrc[aggregatedSrc] == nil {
				dstsPerAggregatedSrc[aggregatedSrc] = make([]Dst, 0)
			}

			if !libs.ContainsElement(dstsPerAggregatedSrc[aggregatedSrc], dst) {
				dstsPerAggregatedSrc[aggregatedSrc] = append(dstsPerAggregatedSrc[aggregatedSrc], dst)
			}
		}
	}

	// if l4 compression on, do this
	if L4DiscoveryLevel == 1 {
		for aggregatedSrc, dsts := range dstsPerAggregatedSrc {
			if aggregatedSrcPerMergedDst[aggregatedSrc] == nil {
				aggregatedSrcPerMergedDst[aggregatedSrc] = []MergedPortDst{}
			}

			// convert dst -> dst per dstSimple
			dstSimpleMap := map[DstSimple][]Dst{}

			for _, dst := range dsts {
				// 1) Group dsts based on Namespace, Podname and Additionals
				// 2) For L4 dsts within a group, merge the L4 protocol/port
				//    and create a single MergedDst
				// 3) For L7 dsts within a group, merge the HTTP path/method
				//    if the TCP port of two dsts are the same.
				dstSimple := DstSimple{
					Namespace:  dst.Namespace,
					PodName:    dst.PodName,
					Additional: dst.Additional,
				}
				dstSimpleMap[dstSimple] = append(dstSimpleMap[dstSimple], dst)
			}

			for _, dests := range dstSimpleMap {
				mergedDst := mergeProtocolPorts(aggregatedSrc, dests)
				if len(mergedDst) > 0 {
					aggregatedSrcPerMergedDst[aggregatedSrc] = append(aggregatedSrcPerMergedDst[aggregatedSrc], mergedDst...)
				}
			}
		}
	}

	return aggregatedSrcPerMergedDst
}

// ============================================ //
// == Step 5: Aggregating Dst based on Label == //
// ============================================ //

func groupDstByNamespace(dsts []MergedPortDst) map[string][]MergedPortDst {
	dstsPerNamespaceMap := map[string][]MergedPortDst{}

	for _, dst := range dsts {
		if val, ok := dstsPerNamespaceMap[dst.Namespace]; !ok {
			dstsPerNamespaceMap[dst.Namespace] = []MergedPortDst{dst}
		} else {
			val = append(val, dst)
			dstsPerNamespaceMap[dst.Namespace] = val
		}
	}

	return dstsPerNamespaceMap
}

func checkIncludeAllDstPods(superSetLabels string, dsts []MergedPortDst, pods []types.Pod) bool {
	dstNamespace := ""
	labels := strings.Split(superSetLabels, ",")

	// temporary pod struct
	type innerPod struct {
		namespace string
		podName   string
	}

	// 1. get pods from srcs
	podNamesFromDsts := []innerPod{}
	for _, dst := range dsts {
		dstNamespace = dst.Namespace

		include := true
		for _, label := range labels {
			if !strings.Contains(dst.MatchLabels, label) {
				include = false
				break
			}
		}

		if include {
			podNamesFromDsts = append(podNamesFromDsts, innerPod{
				namespace: dst.Namespace,
				podName:   dst.PodName,
			})
		}
	}

	// 2. get pods from k8s
	podNamesFromK8s := []innerPod{}
	for _, pod := range pods {
		if pod.Namespace != dstNamespace {
			continue
		}

		include := true
		for _, label := range labels {
			if !libs.ContainsElement(pod.Labels, label) {
				include = false
				break
			}
		}

		if include {
			podNamesFromK8s = append(podNamesFromK8s, innerPod{
				namespace: pod.Namespace,
				podName:   pod.PodName,
			})
		}
	}

	// 3. compare two slices
	dstIncludeAllK8sPods := true
	for _, pod := range podNamesFromDsts {
		if libs.ContainsElement(podNamesFromK8s, pod) {
			dstIncludeAllK8sPods = false
			break
		}
	}

	return dstIncludeAllK8sPods
}

func groupingDstMergeds(label string, dsts []MergedPortDst) MergedPortDst {
	newMerged := MergedPortDst{
		FlowIDs:     []int{},
		MatchLabels: label,
		ToPorts:     []types.SpecPort{}}

	for _, dst := range dsts {
		newMerged.Namespace = dst.Namespace

		// if there is additionals, append it
		if len(dst.Additionals) > 0 {
			if newMerged.Additionals != nil {
				for _, additional := range dst.Additionals {
					if additional != "" && !libs.ContainsElement(newMerged.Additionals, additional) {
						newMerged.Additionals = append(newMerged.Additionals, additional)
					}
				}
			} else {
				newMerged.Additionals = dst.Additionals
			}
		}

		// merge toPort
		for _, toPort := range dst.ToPorts {
			if !libs.ContainsElement(newMerged.ToPorts, toPort) {
				newMerged.ToPorts = append(newMerged.ToPorts, toPort)
			}
		}

		// merge flow ids
		for _, id := range dst.FlowIDs {
			if !libs.ContainsElement(newMerged.FlowIDs, id) {
				newMerged.FlowIDs = append(newMerged.FlowIDs, id)
			}
		}
	}

	return newMerged
}

func aggregateDstByLabel(aggregatedSrcPerMergedDst map[string][]MergedPortDst, pods []types.Pod) map[string][]MergedPortDst {
	aggregatedSrcPerAggregatedDst := map[string][]MergedPortDst{}

	for aggregatedSrc := range aggregatedSrcPerMergedDst {
		if aggregatedSrcPerAggregatedDst[aggregatedSrc] == nil {
			aggregatedSrcPerAggregatedDst[aggregatedSrc] = []MergedPortDst{}
		}

		// dstsPerNamespaceMap key: namespace, val: []MergedPortDst
		dstsPerNamespaceMap := groupDstByNamespace(aggregatedSrcPerMergedDst[aggregatedSrc])
		for namespace, mergedDsts := range dstsPerNamespaceMap {
			if namespace != "reserved:dns" && namespace != "reserved:cidr" && namespace != "reserved:entities" {
				// label update
				mergedDsts = updateDstLabels(mergedDsts, pods)
			}

			// if level 2 or 3, aggregate labels
			if L3DiscoveryLevel >= 2 {
				// count each dst label
				labelCountMap := map[string]int{}
				for _, dst := range mergedDsts {
					if dst.MatchLabels == "" {
						continue
					}

					countLabelByCombinations(labelCountMap, dst.MatchLabels)
				}

				// sort label count by descending orders
				labelCounts := descendingLabelCountMap(labelCountMap)

				// fetch matched label dsts
				for _, labelCount := range labelCounts {
					if labelCount.Count >= 2 {
						// at least match count >= 2
						label := labelCount.Label

						// if level 2, the super set of labels should be included in all the pods to be aggregated
						if L3DiscoveryLevel == 2 && !checkIncludeAllDstPods(label, mergedDsts, pods) {
							continue
						}

						selectedDsts := make([]MergedPortDst, 0)
						for _, dst := range mergedDsts {
							if containLabel(label, dst.MatchLabels) {
								selectedDsts = append(selectedDsts, dst)
								mergedDsts = removeDstFromMergedDstSlice(mergedDsts, dst)
							}
						}

						if len(selectedDsts) != 0 {
							// groupingDsts -> one merged grouping dst
							groupedDst := groupingDstMergeds(label, selectedDsts)
							aggregatedSrcPerAggregatedDst[aggregatedSrc] = append(aggregatedSrcPerAggregatedDst[aggregatedSrc], groupedDst)
						}
					}
				}
			}

			// not grouped dst remains, append it
			aggregatedSrcPerAggregatedDst[aggregatedSrc] = append(aggregatedSrcPerAggregatedDst[aggregatedSrc], mergedDsts...)
		}
	}

	return aggregatedSrcPerAggregatedDst
}

// ======================================= //
// == Step 7: Building Network Policies == //
// ======================================= //

func buildNewKnoxPolicy() types.KnoxNetworkPolicy {
	return types.KnoxNetworkPolicy{
		APIVersion: "v1",
		Kind:       types.KindKnoxNetworkPolicy,
		Metadata: map[string]string{
			"status": "latest",
		},
		Outdated: "",
		Spec: types.Spec{
			Selector: types.Selector{
				MatchLabels: map[string]string{}},
			Action: "allow",
		},
	}
}

func buildNewKnoxEgressPolicy() types.KnoxNetworkPolicy {
	policy := buildNewKnoxPolicy()
	policy.Metadata["type"] = PolicyTypeEgress
	policy.Spec.Egress = []types.Egress{}

	return policy
}

func buildNewKnoxIngressPolicy() types.KnoxNetworkPolicy {
	policy := buildNewKnoxPolicy()
	policy.Metadata["type"] = PolicyTypeIngress
	policy.Spec.Ingress = []types.Ingress{}

	return policy
}

func buildNewIngressPolicyFromEgressPolicy(egressRule types.Egress, selector types.Selector) types.KnoxNetworkPolicy {
	ingress := buildNewKnoxIngressPolicy()
	ingress.Metadata["rule"] = "matchLabels"

	// update selector labels from egress match labels
	for k, v := range egressRule.MatchLabels {
		if k != "k8s:io.kubernetes.pod.namespace" {
			ingress.Spec.Selector.MatchLabels[k] = v
		} else if k == "k8s:io.kubernetes.pod.namespace" {
			ingress.Metadata["namespace"] = v
		}
	}

	// update ingress labels from selector match labels
	ingress.Spec.Ingress = append(ingress.Spec.Ingress, types.Ingress{MatchLabels: map[string]string{}})
	for k, v := range selector.MatchLabels {
		ingress.Spec.Ingress[0].MatchLabels[k] = v
	}

	// if there is toPorts, move it
	if len(egressRule.ToPorts) > 0 {
		ingress.Metadata["rule"] = ingress.Metadata["rule"] + "+toPorts"

		cpy := make([]types.SpecPort, len(egressRule.ToPorts))
		copy(cpy, egressRule.ToPorts)
		ingress.Spec.Ingress[0].ToPorts = cpy

		if len(egressRule.ToHTTPs) > 0 {
			ingress.Metadata["rule"] = ingress.Metadata["rule"] + "+toHTTPs"

			cpyHTTP := make([]types.SpecHTTP, len(egressRule.ToHTTPs))
			copy(cpyHTTP, egressRule.ToHTTPs)
			ingress.Spec.Ingress[0].ToHTTPs = cpyHTTP
		}
	}

	if len(egressRule.ICMPs) > 0 {
		ingress.Metadata["rule"] = ingress.Metadata["rule"] + "+icmps"
		ingress.Spec.Ingress[0].ICMPs = make([]types.SpecICMP, len(egressRule.ICMPs))
		copy(ingress.Spec.Ingress[0].ICMPs, egressRule.ICMPs)
	}

	return ingress
}

func buildNewIngressPolicyFromSameSelector(namespace string, selector types.Selector) types.KnoxNetworkPolicy {
	ingress := buildNewKnoxIngressPolicy()
	ingress.Metadata["namespace"] = namespace
	for k, v := range selector.MatchLabels {
		ingress.Spec.Selector.MatchLabels[k] = v
	}

	return ingress
}

func buildIngressFromEntitiesPolicy(namespace string, mergedSrcPerMergedDst map[string][]MergedPortDst, networkPolicies []types.KnoxNetworkPolicy) []types.KnoxNetworkPolicy {
	for aggregatedSrc, aggregatedMergedDsts := range mergedSrcPerMergedDst {
		// if src includes "reserved" prefix, it means Ingress Policy
		if strings.Contains(aggregatedSrc, "reserved:") {
			reservedLables := strings.Split(aggregatedSrc, ",")

			entities := []string{}
			for _, label := range reservedLables {
				entity := strings.TrimPrefix(label, "reserved:")
				entities = append(entities, entity)
			}

			for _, dst := range aggregatedMergedDsts {
				if dst.MatchLabels == "" {
					continue
				}

				ingressPolicy := buildNewKnoxIngressPolicy()
				ingressPolicy.Metadata["namespace"] = namespace
				ingressPolicy.FlowIDs = dst.FlowIDs
				ingressPolicy.Metadata["rule"] = "fromEntities"

				dsts := strings.Split(dst.MatchLabels, ",")
				for _, dest := range dsts {
					kv := strings.Split(dest, "=")
					if len(kv) != 2 {
						continue
					}

					dstkey := kv[0]
					dstval := kv[1]

					ingressPolicy.Spec.Selector.MatchLabels[dstkey] = dstval
				}

				ingressRule := types.Ingress{}
				ingressRule.FromEntities = entities

				for _, toPort := range dst.ToPorts {
					port := types.SpecPort{Port: toPort.Port, Protocol: toPort.Protocol}
					ingressRule.ToPorts = append(ingressRule.ToPorts, port)
				}

				for _, icmp := range dst.ICMPs {
					i := types.SpecICMP{Family: icmp.Family, Type: icmp.Type}
					ingressRule.ICMPs = append(ingressRule.ICMPs, i)
				}

				ingressPolicy.Spec.Ingress = append(ingressPolicy.Spec.Ingress, ingressRule)

				included := false
				for _, policy := range networkPolicies {
					if policy.Metadata["rule"] == "fromEntities" &&
						cmp.Equal(&ingressPolicy.Spec.Selector, &policy.Spec.Selector) &&
						cmp.Equal(policy.Spec.Ingress[0].ToPorts, ingressRule.ToPorts) &&
						cmp.Equal(policy.Spec.Ingress[0].ICMPs, ingressRule.ICMPs) {

						// copy the new entities in the old policy's entity list
						oldEntities := policy.Spec.Ingress[0].FromEntities
						for _, entity := range entities {
							if !libs.ContainsElement(oldEntities, entity) {
								oldEntities = append(oldEntities, entity)
							}
						}
						policy.Spec.Ingress[0].FromEntities = oldEntities

						included = true
						break
					}
				}

				if !included {
					networkPolicies = append(networkPolicies, ingressPolicy)
				}
			}
		}
	}

	return networkPolicies
}

func buildNetworkPolicy(namespace string, services []types.Service, aggregatedSrcPerAggregatedDst map[string][]MergedPortDst) []types.KnoxNetworkPolicy {
	networkPolicies := []types.KnoxNetworkPolicy{}

	discoverPolicyTypes := cfg.GetCfgNetworkPolicyTypes()
	discoverRuleTypes := cfg.GetCfgNetworkRuleTypes()

	for aggregatedSrc, aggregatedMergedDsts := range aggregatedSrcPerAggregatedDst {
		// if src includes "reserved" prefix, process later
		if strings.Contains(aggregatedSrc, "reserved") {
			continue
		}

		for _, dst := range aggregatedMergedDsts {
			egressPolicy := buildNewKnoxEgressPolicy()
			egressPolicy.Metadata["namespace"] = namespace
			egressPolicy.FlowIDs = dst.FlowIDs

			// ======== //
			// Selector //
			// ======== //
			srcs := strings.Split(aggregatedSrc, ",")
			for _, src := range srcs {
				labelKV := strings.Split(src, "=")
				if len(labelKV) != 2 { // double check if it is k=v
					continue
				}

				egressPolicy.Spec.Selector.MatchLabels[labelKV[0]] = labelKV[1]
			}

			// sorting toPorts
			if len(dst.ToPorts) > 0 {
				sort.Slice(dst.ToPorts, func(i, j int) bool {
					return dst.ToPorts[i].Port < dst.ToPorts[j].Port
				})
			}

			egressRule := types.Egress{}

			// check toPorts rule
			if len(dst.ToPorts) > 0 && discoverRuleTypes&TO_PORTS > 0 {
				egressPolicy.Metadata["rule"] = egressPolicy.Metadata["rule"] + "+toPorts"
				egressRule.ToPorts = dst.ToPorts

				// check toHTTPs rule
				if len(dst.ToHTTPs) > 0 && discoverRuleTypes&TO_HTTPS > 0 {
					egressPolicy.Metadata["rule"] = egressPolicy.Metadata["rule"] + "+toHTTPs"
					egressRule.ToHTTPs = dst.ToHTTPs
				}
			}

			if len(dst.ICMPs) > 0 && (discoverRuleTypes&TO_ICMPS) > 0 {
				egressPolicy.Metadata["rule"] = egressPolicy.Metadata["rule"] + "+icmps"
				egressRule.ICMPs = dst.ICMPs
			}

			if dst.MatchLabels != "" {
				// ========================== //
				// build label-based policies //
				// ========================== //

				if discoverRuleTypes&MATCH_LABELS == 0 {
					continue
				}

				egressPolicy.Metadata["rule"] = egressPolicy.Metadata["rule"] + "+matchLabels"

				egressRule.MatchLabels = map[string]string{}

				dsts := strings.Split(dst.MatchLabels, ",")
				for _, dest := range dsts {
					labelKV := strings.Split(dest, "=")
					if len(labelKV) != 2 {
						continue
					}

					egressRule.MatchLabels[labelKV[0]] = labelKV[1]
				}

				// although src and dst have same namespace, speficy namespace for clarity
				egressRule.MatchLabels["k8s:io.kubernetes.pod.namespace"] = dst.Namespace

				// check egress
				egressPolicy.Spec.Egress = append(egressPolicy.Spec.Egress, egressRule)
				if discoverPolicyTypes&EGRESS > 0 {
					networkPolicies = append(networkPolicies, egressPolicy)
				}

				// check ingress
				if discoverPolicyTypes&INGRESS > 0 {
					ingressPolicy := buildNewIngressPolicyFromEgressPolicy(egressRule, egressPolicy.Spec.Selector)
					ingressPolicy.Spec.Ingress[0].MatchLabels["k8s:io.kubernetes.pod.namespace"] = namespace
					ingressPolicy.FlowIDs = egressPolicy.FlowIDs
					networkPolicies = append(networkPolicies, ingressPolicy)
				}
			} else if dst.Namespace == "reserved:cidr" && len(dst.Additionals) > 0 {
				// =============== //
				// build CIDR rule //
				// =============== //
				cidrSlice := strings.Split(dst.Additionals[0], ",")
				sort.Strings(cidrSlice)
				cidr := types.SpecCIDR{
					CIDRs: cidrSlice,
				}

				// check toCIDRs rule
				if discoverRuleTypes&TO_CIDRS > 0 {
					egressPolicy.Metadata["rule"] = egressPolicy.Metadata["rule"] + "+toCIDRs"
					egressRule.ToCIDRs = []types.SpecCIDR{cidr}
				}

				// check egress
				egressPolicy.Spec.Egress = append(egressPolicy.Spec.Egress, egressRule)
				if discoverPolicyTypes&EGRESS > 0 {
					networkPolicies = append(networkPolicies, egressPolicy)
				}

			} else if dst.Namespace == "reserved:dns" && len(dst.Additionals) > 0 {
				// =============== //
				// build FQDN rule //
				// =============== //

				// check egress & toFQDNs rule
				if discoverPolicyTypes&EGRESS > 0 && discoverRuleTypes&TO_FQDNS > 0 {
					egressPolicy.Metadata["rule"] = egressPolicy.Metadata["rule"] + "+toFQDNs"

					sort.Strings(dst.Additionals)
					fqdn := types.SpecFQDN{
						MatchNames: dst.Additionals,
					}

					egressRule.ToFQDNs = []types.SpecFQDN{fqdn}
					egressPolicy.Spec.Egress = append(egressPolicy.Spec.Egress, egressRule)
					networkPolicies = append(networkPolicies, egressPolicy)
				}
			} else if dst.Namespace == "reserved:entities" && len(dst.Additionals) > 0 {
				// ================= //
				// build Entity rule //
				// ================= //
				sort.Strings(dst.Additionals)

				// handle for entity policy in Cilium
				for _, additionals := range dst.Additionals {
					if strings.Contains(additionals, ",") {
						egressRule.ToEntities = append(egressRule.ToEntities, strings.Split(additionals, ",")...)
					} else {
						egressRule.ToEntities = append(egressRule.ToEntities, additionals)
					}
				}

				egressPolicy.Spec.Egress = append(egressPolicy.Spec.Egress, egressRule)

				// check egress & toEntities rule
				if discoverPolicyTypes&EGRESS > 0 && discoverRuleTypes&TO_ENTITIES > 0 {
					egressPolicy.Metadata["rule"] = egressPolicy.Metadata["rule"] + "+toEntities"
					networkPolicies = append(networkPolicies, egressPolicy)
				}
			}
			// toServices rule will be handled by policies with matchLabel rule
			// Keeping the below code just as a reference
			/*********************************************
			else if len(dst.Additionals) > 0 {

				egressPolicy.Metadata["rule"] = "toServices"

				// ================== //
				// build Service rule //
				// ================== //
				if discoverPolicyTypes&EGRESS > 0 && discoverRuleTypes&TO_SERVICES > 0 {
					// to external services (NOT internal k8s service)
					// to affect this policy, we need a service, an endpoint respectively
					service := types.SpecService{
						ServiceName: dst.Additionals[0],
						Namespace:   dst.Namespace,
					}

					egressRule.ToServices = []types.SpecService{service}
					egressPolicy.Spec.Egress = append(egressPolicy.Spec.Egress, egressRule)
					networkPolicies = append(networkPolicies, egressPolicy)
				}
			}
			**********************************************/
		}
	}

	// build ingress fromEntities policy
	if discoverPolicyTypes&INGRESS > 0 {
		networkPolicies = buildIngressFromEntitiesPolicy(namespace, aggregatedSrcPerAggregatedDst, networkPolicies)
	}

	// update generated time
	for i := range networkPolicies {
		networkPolicies[i].GeneratedTime = time.Now().Unix()
	}

	return networkPolicies
}

// ============================================ //
// == Step 8: Updating labeledSrcsPerDst Map == //
// ============================================ //

func updateLabeledSrcPerDst(labeledSrcsPerDst map[Dst][]SrcSimple) map[Dst][]SrcSimple {
	// only maintains pod-to-pod in cluster
	for dst := range labeledSrcsPerDst {
		if strings.HasPrefix(dst.Namespace, "reserved") || dst.HTTP != "" {
			delete(labeledSrcsPerDst, dst)
		}
	}

	return labeledSrcsPerDst
}

// ============================== //
// == Discover Network Policy  == //
// ============================== //

func DiscoverNetworkPolicy(namespace string,
	networkLogs []types.KnoxNetworkLog,
	services []types.Service,
	pods []types.Pod) []types.KnoxNetworkPolicy {

	networkPolicies := []types.KnoxNetworkPolicy{}

	ingressPolicies := map[Selector][]types.KnoxNetworkPolicy{}
	egressPolicies := map[Selector][]types.KnoxNetworkPolicy{}

	for i := range networkLogs {
		ingress, egress := convertKnoxNetworkLogToKnoxNetworkPolicy(&networkLogs[i], pods)

		if ingress != nil {
			endpointSelector := getLabelArrayFromMap(ingress.Spec.Selector.MatchLabels)
			selector := Selector{ingress.Kind, strings.Join(endpointSelector, ",")}
			ingressPolicies[selector] = append(ingressPolicies[selector], *ingress)
		}
		if egress != nil {
			endpointSelector := getLabelArrayFromMap(egress.Spec.Selector.MatchLabels)
			selector := Selector{egress.Kind, strings.Join(endpointSelector, ",")}
			egressPolicies[selector] = append(egressPolicies[selector], *egress)
		}
	}

	for selector, policies := range ingressPolicies {
		if len(policies) > 1 {
			mergedPolicy, _ := mergeNetworkPolicies(policies[0], policies[1:])
			ingressPolicies[selector] = []types.KnoxNetworkPolicy{mergedPolicy}
		}
	}

	for selector, policies := range egressPolicies {
		if len(policies) > 1 {
			mergedPolicy, _ := mergeNetworkPolicies(policies[0], policies[1:])
			egressPolicies[selector] = []types.KnoxNetworkPolicy{mergedPolicy}
		}
	}

	for _, p := range ingressPolicies {
		networkPolicies = append(networkPolicies, p...)
	}
	for _, p := range egressPolicies {
		networkPolicies = append(networkPolicies, p...)
	}
	return networkPolicies
}

func mergeNetworkPolicies(existPolicy types.KnoxNetworkPolicy, policies []types.KnoxNetworkPolicy) (types.KnoxNetworkPolicy, bool) {
	if existPolicy.Metadata["type"] == PolicyTypeIngress {
		return mergeIngressPolicies(existPolicy, policies)
	}
	return mergeEgressPolicies(existPolicy, policies)
}

func checkIfIngressEgressPortExist(polType string, newToPort types.SpecPort, mergedPolicy types.KnoxNetworkPolicy) bool {
	isExist := false

	if polType == "EGRESS" {
		for _, existEgress := range mergedPolicy.Spec.Egress {
			if len(existEgress.ToPorts) == 0 {
				continue
			}
			existToPort := existEgress.ToPorts[0]

			if existToPort == newToPort {
				isExist = true
				break
			}
		}
	} else if polType == "INGRESS" {
		for _, existIngress := range mergedPolicy.Spec.Ingress {
			if len(existIngress.ToPorts) == 0 {
				continue
			}
			existToPort := existIngress.ToPorts[0]

			if existToPort == newToPort {
				isExist = true
				break
			}
		}
	}

	return isExist
}

func mergeIngressPolicies(existPolicy types.KnoxNetworkPolicy, policies []types.KnoxNetworkPolicy) (types.KnoxNetworkPolicy, bool) {
	mergedPolicy := existPolicy
	updated := false

	var ingressMatched bool

	for _, policy := range policies {
		for _, newIngress := range policy.Spec.Ingress {
			ingressMatched = false

			if len(newIngress.MatchLabels) > 0 {
				lblArr := getLabelArrayFromMap(newIngress.MatchLabels)
				newSelector := strings.Join(lblArr, ",")

				for i, existIngress := range mergedPolicy.Spec.Ingress {
					if len(existIngress.MatchLabels) == 0 {
						continue
					}
					lblArr = getLabelArrayFromMap(existIngress.MatchLabels)
					existSelector := strings.Join(lblArr, ",")

					if newSelector == existSelector {
						ingressMatched, updated, mergedPolicy.Spec.Ingress[i].ToHTTPs = mergeHttpRules(existIngress, newIngress)
						if ingressMatched {
							break
						}
					}
				}
			} else if len(newIngress.FromEntities) > 0 {
				newEntity := newIngress.FromEntities[0]

				for i, existIngress := range mergedPolicy.Spec.Ingress {
					if len(existIngress.FromEntities) == 0 {
						continue
					}
					existEntity := existIngress.FromEntities[0]

					if newEntity == existEntity {
						ingressMatched, updated, mergedPolicy.Spec.Ingress[i].ToHTTPs = mergeHttpRules(existIngress, newIngress)
						if ingressMatched {
							break
						}
					}
				}
			} else if len(newIngress.FromCIDRs) > 0 && len(newIngress.ToPorts) > 0 {
				newToPort := newIngress.ToPorts[0]
				ingressMatched = checkIfIngressEgressPortExist("INGRESS", newToPort, mergedPolicy)
			}

			if !ingressMatched {
				mergedPolicy.Spec.Ingress = append(mergedPolicy.Spec.Ingress, newIngress)
				updated = true
			}
		}
	}

	return mergedPolicy, updated
}

func mergeEgressPolicies(existPolicy types.KnoxNetworkPolicy, policies []types.KnoxNetworkPolicy) (types.KnoxNetworkPolicy, bool) {
	mergedPolicy := existPolicy
	updated := false

	var egressMatched bool

	for _, policy := range policies {
		for _, newEgress := range policy.Spec.Egress {
			egressMatched = false

			if len(newEgress.MatchLabels) > 0 {
				lblArr := getLabelArrayFromMap(newEgress.MatchLabels)
				newSelector := strings.Join(lblArr, ",")

				for i, existEgress := range mergedPolicy.Spec.Egress {
					if len(existEgress.MatchLabels) == 0 {
						continue
					}
					lblArr = getLabelArrayFromMap(existEgress.MatchLabels)
					existSelector := strings.Join(lblArr, ",")

					if newSelector == existSelector {
						egressMatched, updated, mergedPolicy.Spec.Egress[i].ToHTTPs = mergeHttpRules(existEgress, newEgress)
						if egressMatched {
							break
						}
					}
				}
			} else if len(newEgress.ToEntities) > 0 {
				newEntity := newEgress.ToEntities[0]

				for i, existEgress := range mergedPolicy.Spec.Egress {
					if len(existEgress.ToEntities) == 0 {
						continue
					}
					existEntity := existEgress.ToEntities[0]

					if newEntity == existEntity {
						egressMatched, updated, mergedPolicy.Spec.Egress[i].ToHTTPs = mergeHttpRules(existEgress, newEgress)
						if egressMatched {
							break
						}
					}
				}
			} else if len(newEgress.ToFQDNs) > 0 {
				newFQDN := newEgress.ToFQDNs[0].MatchNames[0]

				for i, existEgress := range mergedPolicy.Spec.Egress {
					if len(existEgress.ToFQDNs) == 0 {
						continue
					}
					existFQDN := existEgress.ToFQDNs[0].MatchNames[0]

					if newFQDN == existFQDN {
						egressMatched, updated, mergedPolicy.Spec.Egress[i].ToHTTPs = mergeHttpRules(existEgress, newEgress)
						if egressMatched {
							break
						}
					}
				}
			} else if len(newEgress.ToCIDRs) > 0 && len(newEgress.ToPorts) > 0 {
				newToPort := newEgress.ToPorts[0]
				egressMatched = checkIfIngressEgressPortExist("EGRESS", newToPort, mergedPolicy)
			}

			if !egressMatched {
				mergedPolicy.Spec.Egress = append(mergedPolicy.Spec.Egress, newEgress)
				updated = true
			}
		}
	}

	return mergedPolicy, updated
}

func mergeHttpRules(existRule types.L47Rule, newRule types.L47Rule) (bool, bool, []types.SpecHTTP) {
	existIcmpRule := existRule.GetICMPRules()
	newIcmpRule := newRule.GetICMPRules()

	existPortRule := existRule.GetPortRules()
	newPortRule := newRule.GetPortRules()

	existHttpRule := existRule.GetHTTPRules()
	newHttpRule := newRule.GetHTTPRules()

	existIsICMP := false
	if len(existIcmpRule) > 0 {
		existIsICMP = true
	}

	newIsICMP := false
	if len(newIcmpRule) > 0 {
		newIsICMP = true
	}

	// Handle Ingress/Egress with ICMP rules
	if existIsICMP && !newIsICMP {
		return false, false, nil
	} else if !existIsICMP && newIsICMP {
		return false, false, nil
	} else if existIsICMP && newIsICMP {
		if existIcmpRule[0].Equal(newIcmpRule[0]) {
			return true, false, nil
		}
		return false, false, nil
	}

	// Handling Ingress/Egress with L4 and HTTP rules
	mergedHttpRule := existHttpRule
	updated := false
	if existPortRule[0].Equal(newPortRule[0]) {
		for _, h := range newHttpRule {
			if !libs.ContainsElement(existHttpRule, h) {
				mergedHttpRule = append(mergedHttpRule, h)
				updated = true
			}
		}
		return true, updated, mergedHttpRule
	}
	return false, false, nil
}

func populateIngressEgressPolicyFromKnoxNetLog(log *types.KnoxNetworkLog, pods []types.Pod) types.KnoxNetworkPolicy {
	iePolicy := types.KnoxNetworkPolicy{}
	var cidrs []string
	cidrs = append(cidrs, "0.0.0.0/32")

	specVal := types.SpecCIDR{
		CIDRs: cidrs,
	}

	portVal := types.SpecPort{
		Port:     strconv.Itoa(log.DstPort),
		Protocol: libs.GetProtocol(log.Protocol),
	}

	if log.Direction == "EGRESS" {
		iePolicy = buildNewKnoxEgressPolicy()
		egress := types.Egress{}

		egress.ToPorts = append(egress.ToPorts, portVal)
		egress.ToCIDRs = append(egress.ToCIDRs, specVal)

		iePolicy.Spec.Egress = append(iePolicy.Spec.Egress, egress)

	} else if log.Direction == "INGRESS" {
		iePolicy = buildNewKnoxIngressPolicy()
		ingress := types.Ingress{}

		ingress.ToPorts = append(ingress.ToPorts, portVal)
		ingress.FromCIDRs = append(ingress.FromCIDRs, specVal)

		iePolicy.Spec.Ingress = append(iePolicy.Spec.Ingress, ingress)
	}

	iePolicy.Spec.Selector.MatchLabels = getEndpointMatchLabels(log.SrcPodName, pods)

	return iePolicy
}

func convertKnoxNetworkLogToKnoxNetworkPolicy(log *types.KnoxNetworkLog, pods []types.Pod) (_, _ *types.KnoxNetworkPolicy) {
	var ingressPolicy, egressPolicy *types.KnoxNetworkPolicy = nil, nil

	if log.SrcPodName != "" && log.DstPodName != "" {
		// 1. Generate egress policy for the src
		//        and ingress policy for the dst

		// Ingress/Egress Policy
		ePolicy, iPolicy := buildNewKnoxEgressPolicy(), buildNewKnoxIngressPolicy()

		// 1.1 Set the endpoint selector
		ePolicy.Spec.Selector.MatchLabels = getEndpointMatchLabels(log.DstPodName, pods)
		iPolicy.Spec.Selector.MatchLabels = getEndpointMatchLabels(log.SrcPodName, pods)

		// 1.2 Set the to/from Endpoint selector
		egress := types.Egress{}
		ingress := types.Ingress{}
		egress.MatchLabels = getEndpointMatchLabels(log.SrcPodName, pods)
		ingress.MatchLabels = getEndpointMatchLabels(log.DstPodName, pods)

		if log.SrcNamespace != log.DstNamespace {
			// cross namespace policy
			egress.MatchLabels["io.kubernetes.pod.namespace"] = log.SrcNamespace
			ingress.MatchLabels["io.kubernetes.pod.namespace"] = log.DstNamespace
		}

		// 1.3 Set the dst port/protocol
		if !libs.IsICMP(log.Protocol) {
			egress.ToPorts = []types.SpecPort{{Port: strconv.Itoa(log.DstPort), Protocol: libs.GetProtocol(log.Protocol)}}
			ingress.ToPorts = append(ingress.ToPorts, egress.ToPorts...)
		} else {
			// 1.4 Set the icmp code/type
			family := "IPv4"
			if log.Protocol == libs.IPProtocolICMPv6 {
				family = "IPv6"
			}
			egress.ICMPs = []types.SpecICMP{{Family: family, Type: uint8(log.ICMPType)}}
			ingress.ICMPs = append(ingress.ICMPs, egress.ICMPs...)
		}

		if log.L7Protocol == libs.L7ProtocolHTTP {
			httpRule := types.SpecHTTP{Method: log.HTTPMethod, Path: log.HTTPPath}
			egress.ToHTTPs = []types.SpecHTTP{httpRule}
			ingress.ToHTTPs = []types.SpecHTTP{httpRule}
		}

		ePolicy.Spec.Egress = append(ePolicy.Spec.Egress, egress)
		iPolicy.Spec.Ingress = append(iPolicy.Spec.Ingress, ingress)

		ePolicy.Metadata["namespace"] = log.DstNamespace
		iPolicy.Metadata["namespace"] = log.SrcNamespace

		egressPolicy = &ePolicy
		ingressPolicy = &iPolicy
	} else if log.SrcPodName == "" && len(log.SrcReservedLabels) > 0 {
		// 2. Generate ingress policy only for the dst

		// Ingress Policy
		iPolicy := buildNewKnoxIngressPolicy()

		// 2.1 Set the endpoint selector
		iPolicy.Spec.Selector.MatchLabels = getEndpointMatchLabels(log.DstPodName, pods)

		// 2.2 Set the fromEntities selector
		ingress := types.Ingress{}
		srcEntity := getEntityFromReservedLabels(log.SrcReservedLabels)
		if srcEntity != "" {
			ingress.FromEntities = append(ingress.FromEntities, srcEntity)

			// 2.3 Set the dst port/protocol
			if !libs.IsICMP(log.Protocol) {
				ingress.ToPorts = []types.SpecPort{{Port: strconv.Itoa(log.DstPort), Protocol: libs.GetProtocol(log.Protocol)}}
			} else {
				// 2.4 Set the icmp code/type
				family := "IPv4"
				if log.Protocol == libs.IPProtocolICMPv6 {
					family = "IPv6"
				}
				ingress.ICMPs = []types.SpecICMP{{Family: family, Type: uint8(log.ICMPType)}}
			}

			if log.L7Protocol == libs.L7ProtocolHTTP {
				httpRule := types.SpecHTTP{Method: log.HTTPMethod, Path: log.HTTPPath}
				ingress.ToHTTPs = []types.SpecHTTP{httpRule}
			}

			iPolicy.Spec.Ingress = append(iPolicy.Spec.Ingress, ingress)
			iPolicy.Metadata["namespace"] = log.DstNamespace
			iPolicy.Metadata["container_name"] = log.ContainerName

			ingressPolicy = &iPolicy
		}
	} else if log.DstPodName == "" && len(log.DstReservedLabels) > 0 {
		// 3. Generate egress policy only for the src

		// Egress Policy
		ePolicy := buildNewKnoxEgressPolicy()

		// 3.1 Set the endpoint selector
		ePolicy.Spec.Selector.MatchLabels = getEndpointMatchLabels(log.SrcPodName, pods)

		// 3.2 Set the toEntities/ToFQDNs
		egress := types.Egress{}
		dstEntity := getEntityFromReservedLabels(log.DstReservedLabels)
		if dstEntity != "" {
			if dstEntity == "world" && log.DNSQuery != "" {
				fqdn := types.SpecFQDN{MatchNames: []string{log.DNSQuery}}
				egress.ToFQDNs = append(egress.ToFQDNs, fqdn)
			} else {
				egress.ToEntities = append(egress.ToEntities, dstEntity)
			}

			// 3.3 Set the dst port/protocol
			if !libs.IsICMP(log.Protocol) {
				egress.ToPorts = []types.SpecPort{{Port: strconv.Itoa(log.DstPort), Protocol: libs.GetProtocol(log.Protocol)}}
			} else {
				// 3.4 Set the icmp code/type
				family := "IPv4"
				if log.Protocol == libs.IPProtocolICMPv6 {
					family = "IPv6"
				}
				egress.ICMPs = []types.SpecICMP{{Family: family, Type: uint8(log.ICMPType)}}
			}

			if log.L7Protocol == libs.L7ProtocolHTTP {
				httpRule := types.SpecHTTP{Method: log.HTTPMethod, Path: log.HTTPPath}
				egress.ToHTTPs = []types.SpecHTTP{httpRule}
			}

			ePolicy.Spec.Egress = append(ePolicy.Spec.Egress, egress)
			ePolicy.Metadata["namespace"] = log.SrcNamespace
			ePolicy.Metadata["container_name"] = log.ContainerName
			egressPolicy = &ePolicy
		}
	} else if log.DstPodName == "" && len(log.DstReservedLabels) == 0 {
		iePolicy := populateIngressEgressPolicyFromKnoxNetLog(log, pods)
		if log.Direction == "EGRESS" {
			egressPolicy = &iePolicy
		} else if log.Direction == "INGRESS" {
			ingressPolicy = &iePolicy
		}
		// Update namespace
		if iePolicy.Metadata["status"] == "latest" {
			iePolicy.Metadata["namespace"] = log.SrcNamespace
			iePolicy.Metadata["container_name"] = log.ContainerName
		}
	}

	if !isValidPolicy(ingressPolicy) {
		ingressPolicy = nil
	}

	if !isValidPolicy(egressPolicy) {
		egressPolicy = nil
	}

	// If src/dst is VM, set kind field as host-policy
	if egressPolicy != nil && log.SrcPodName != "" && isVM(log.SrcPodName, pods) {
		egressPolicy.Kind = types.KindKnoxHostNetworkPolicy
	}
	if ingressPolicy != nil && log.DstPodName != "" && isVM(log.DstPodName, pods) {
		ingressPolicy.Kind = types.KindKnoxHostNetworkPolicy
	}

	return ingressPolicy, egressPolicy
}

func isValidPolicy(policy *types.KnoxNetworkPolicy) bool {
	if policy == nil {
		return false
	}

	if len(policy.Spec.Selector.MatchLabels) == 0 {
		return false
	}

	if policy.Metadata["type"] == PolicyTypeIngress {
		if len(policy.Spec.Ingress) == 0 {
			return false
		}

		for _, ingress := range policy.Spec.Ingress {
			if len(ingress.MatchLabels) == 0 &&
				len(ingress.FromEntities) == 0 &&
				len(ingress.FromCIDRs) == 0 {
				return false
			}

			if len(ingress.ToPorts) == 0 &&
				len(ingress.ICMPs) == 0 {
				return false
			}

			if len(ingress.ToHTTPs) > 0 {
				if len(ingress.ToPorts) == 0 {
					return false
				}
				for _, p := range ingress.ToPorts {
					if p.Protocol != "TCP" {
						return false
					}
				}
			}
		}
	}

	if policy.Metadata["type"] == PolicyTypeEgress {
		if len(policy.Spec.Egress) == 0 {
			return false
		}

		for _, egress := range policy.Spec.Egress {
			if len(egress.MatchLabels) == 0 &&
				len(egress.ToEntities) == 0 &&
				len(egress.ToFQDNs) == 0 &&
				len(egress.ToCIDRs) == 0 {
				return false
			}

			if len(egress.ToPorts) == 0 &&
				len(egress.ICMPs) == 0 {
				return false
			}

			if len(egress.ToHTTPs) > 0 {
				if len(egress.ToPorts) == 0 {
					return false
				}
				for _, p := range egress.ToPorts {
					if p.Protocol != "TCP" {
						return false
					}
				}
			}
		}
	}

	return true
}

func getEntityFromReservedLabels(reservedLabels []string) string {
	entities := []string{}

	for _, label := range reservedLabels {
		entity := strings.TrimPrefix(label, "reserved:")
		entities = append(entities, entity)
	}

	// reservedLabels might contain more than one entity name.
	// Choose the label which is more unique/specific to
	// the src/dst entity and return the entity name
	if libs.ContainsElement(entities, "kube-apiserver") {
		return "kube-apiserver"
	} else if libs.ContainsElement(entities, "world") {
		return "world"
	} else if libs.ContainsElement(entities, "remote-node") {
		return "remote-node"
	} else if libs.ContainsElement(entities, "host") {
		return "host"
	} else {
		return ""
	}
}

func getEndpointMatchLabels(podName string, pods []types.Pod) map[string]string {
	podLabels := getLabelsFromPod(podName, pods)
	matchLabels := getLabelMapFromArray(podLabels)
	return matchLabels
}

func getLabelMapFromArray(labels []string) map[string]string {
	labelMap := map[string]string{}

	for _, label := range labels {
		kvPair := strings.Split(label, "=")
		if len(kvPair) != 2 {
			continue
		}
		labelMap[kvPair[0]] = kvPair[1]
	}

	return labelMap
}

func getLabelArrayFromMap(labelMap map[string]string) []string {
	labels := []string{}

	for k, v := range labelMap {
		labels = append(labels, (k + "=" + v))
	}

	sort.Strings(labels)

	return labels
}

func isVM(podName string, pods []types.Pod) bool {
	return libs.ContainsElement(getLabelsFromPod(podName, pods), ReservedHost)
}

func applyPolicyFilter(discoveredPolicies map[string][]types.KnoxNetworkPolicy) map[string][]types.KnoxNetworkPolicy {

	nsFilter := config.CurrentCfg.ConfigNetPolicy.NsFilter
	nsNotFilter := config.CurrentCfg.ConfigNetPolicy.NsNotFilter

	if len(nsFilter) > 0 {
		for ns := range discoveredPolicies {
			if !libs.ContainsElement(nsFilter, ns) {
				delete(discoveredPolicies, ns)
			}
		}
	} else if len(nsNotFilter) > 0 {
		for ns := range discoveredPolicies {
			if libs.ContainsElement(nsNotFilter, ns) {
				delete(discoveredPolicies, ns)
			}
		}
	}

	return discoveredPolicies
}

func PopulateNetworkPoliciesFromNetworkLogs(networkLogs []types.KnoxNetworkLog) map[string][]types.KnoxNetworkPolicy {

	discoveredNetworkPolicies := map[string][]types.KnoxNetworkPolicy{}

	// get cluster names, iterate each cluster
	clusteredLogs := clusteringNetworkLogs(networkLogs)

	for clusterName, networkLogs := range clusteredLogs {
		log.Info().Msgf("Network policy discovery started for cluster [%s]", clusterName)

		// set cluster global variables
		initMultiClusterVariables(clusterName)

		// get k8s resources
		log.Info().Msgf("GetAllClusterResources for cluster [%s]", clusterName)
		namespaces, services, endpoints, pods, err := cluster.GetAllClusterResources(clusterName)
		if err != nil {
			log.Error().Msg(err.Error())
			continue
		}

		log.Info().Msgf("updateDNSFlows for cluster [%s]", clusterName)
		// update DNS req. flows, DNSToIPs map
		updateDNSFlows(networkLogs)

		log.Info().Msgf("updateServiceEndpoint for cluster [%s]", clusterName)
		// update service ports (k8s service, endpoint, kube-dns)
		updateServiceEndpoint(services, endpoints, pods)

		log.Info().Msgf("FilterNetworkLogsByConfig for cluster [%s]", clusterName)
		// filter ignoring network logs from configuration
		filteredLogs := FilterNetworkLogsByConfig(networkLogs, pods)

		// iterate each namespace
		for _, namespace := range namespaces {
			// get network logs by target namespace
			log.Info().Msgf("FilterNetworkLogsByNamespace for cluster [%s] namespace [%s]", clusterName, namespace)
			logsPerNamespace := FilterNetworkLogsByNamespace(namespace, filteredLogs)
			if len(logsPerNamespace) == 0 {
				continue
			}

			// reset flow id track at each target namespace
			clearTrackFlowIDMaps()

			log.Info().Msgf("DiscoverNetworkPolicy for cluster [%s] namespace [%s]", clusterName, namespace)
			// discover network policies based on the network logs
			discoveredNetPolicies := DiscoverNetworkPolicy(namespace, logsPerNamespace, services, pods)

			// Segregate policies based on policy namespace
			// Context:
			// --------
			// When source and destination of a hubble flow are in different namespaces (A and B),
			// we will generate the egress policy in a namespace (A) and the associated ingress
			// policy in a different namespace (B). So it is important to do the segregation
			// before starting the deduplication process.
			for _, policy := range discoveredNetPolicies {
				ns := policy.Metadata["namespace"]
				discoveredNetworkPolicies[ns] = append(discoveredNetworkPolicies[ns], policy)
			}
		}

		// filter discovered policies
		discoveredNetworkPolicies = applyPolicyFilter(discoveredNetworkPolicies)

		// iterate each namespace
		for _, namespace := range namespaces {
			discoveredPolicies := discoveredNetworkPolicies[namespace]
			if len(discoveredPolicies) == 0 {
				continue
			}

			log.Info().Msgf("libs.GetNetworkPolicies for cluster [%s] namespace [%s]", clusterName, namespace)
			// get existing network policies in db
			existingNetPolicies := libs.GetNetworkPolicies(CfgDB, clusterName, namespace, "latest", "", "")

			log.Info().Msgf("UpdateDuplicatedPolicy for cluster [%s] namespace [%s]", clusterName, namespace)
			// update duplicated policy
			newPolicies, updatedPolicies := UpdateDuplicatedPolicy(existingNetPolicies, discoveredPolicies, DomainToIPs, clusterName)

			if len(updatedPolicies) > 0 {
				libs.UpdateNetworkPolicies(CfgDB, updatedPolicies)
				writeNetworkPoliciesYamlToDB(updatedPolicies)
			}
			if len(newPolicies) > 0 {
				libs.InsertNetworkPolicies(CfgDB, newPolicies)
				writeNetworkPoliciesYamlToDB(newPolicies)
			}
			log.Info().Msgf("-> Network policy discovery done for namespace: [%s], [%d] policies updated, [%d] policies newly discovered", namespace, len(updatedPolicies), len(newPolicies))
		}

		// update cluster global variables
		updateMultiClusterVariables(clusterName)
	}

	return discoveredNetworkPolicies
}

func writeNetworkPoliciesYamlToDB(policies []types.KnoxNetworkPolicy) {
	res := []types.PolicyYaml{}

	if cfg.CurrentCfg.ConfigNetPolicy.NetworkLogFrom == "kubearmor" {
		k8sNetPolicies := plugin.ConvertKnoxNetPolicyToK8sNetworkPolicy("", "", policies)

		for _, np := range k8sNetPolicies {
			jsonBytes, err := json.Marshal(np)
			if err != nil {
				log.Error().Msg(err.Error())
				continue
			}
			yamlBytes, err := yaml.JSONToYAML(jsonBytes)
			if err != nil {
				log.Error().Msg(err.Error())
				continue
			}

			policyYaml := types.PolicyYaml{
				Type:        types.PolicyTypeNetwork,
				Kind:        np.Kind,
				Name:        np.Name,
				Namespace:   np.Namespace,
				WorkspaceId: cfg.GetCfgWorkspaceId(),
				ClusterId:   cfg.GetCfgClusterId(),
				Cluster:     cfg.GetCfgClusterName(),
				Labels:      np.Spec.PodSelector.MatchLabels,
				Yaml:        yamlBytes,
			}
			res = append(res, policyYaml)

			PolicyStore.Publish(&policyYaml)
		}

	} else {

		// convert knoxPolicy to CiliumPolicy
		ciliumPolicies := plugin.ConvertKnoxPoliciesToCiliumPolicies(policies)

		for _, ciliumPolicy := range ciliumPolicies {
			jsonBytes, err := json.Marshal(ciliumPolicy)
			if err != nil {
				log.Error().Msg(err.Error())
				continue
			}
			yamlBytes, err := yaml.JSONToYAML(jsonBytes)
			if err != nil {
				log.Error().Msg(err.Error())
				continue
			}

			var labels types.LabelMap
			if ciliumPolicy.Kind == cu.ResourceTypeCiliumNetworkPolicy {
				labels = ciliumPolicy.Spec.EndpointSelector.MatchLabels
			} else {
				labels = ciliumPolicy.Spec.NodeSelector.MatchLabels
			}

			policyYaml := types.PolicyYaml{
				Type:        types.PolicyTypeNetwork,
				Kind:        ciliumPolicy.Kind,
				Name:        ciliumPolicy.Metadata["name"],
				Namespace:   ciliumPolicy.Metadata["namespace"],
				Cluster:     cfg.GetCfgClusterName(),
				WorkspaceId: cfg.GetCfgWorkspaceId(),
				ClusterId:   cfg.GetCfgClusterId(),
				Labels:      labels,
				Yaml:        yamlBytes,
			}
			res = append(res, policyYaml)

			PolicyStore.Publish(&policyYaml)
		}
	}

	if err := libs.UpdateOrInsertPolicyYamls(CfgDB, res); err != nil {
		log.Error().Msgf(err.Error())
	}
}

func DiscoverNetworkPolicyMain() {
	if NetworkWorkerStatus == STATUS_RUNNING {
		return
	} else {
		NetworkWorkerStatus = STATUS_RUNNING
	}

	defer func() {
		NetworkWorkerStatus = STATUS_IDLE
	}()

	// init the configuration related to the network policy
	InitNetPolicyDiscoveryConfiguration()

	// get network logs
	allNetworkLogs := getNetworkLogs()
	if allNetworkLogs == nil || len(allNetworkLogs) < OperationTrigger {
		return
	}

	PopulateNetworkPoliciesFromNetworkLogs(allNetworkLogs)

}

// ===================================== //
// == Network Policy Discovery Worker == //
// ===================================== //

func StartNetworkLogRcvr() {
	for {
		if cfg.GetCfgNetworkLogFrom() == "hubble" {
			plugin.StartHubbleRelay(NetworkStopChan /* &NetworkWaitG, */, cfg.GetCfgCiliumHubble())
		} else if cfg.GetCfgNetworkLogFrom() == "feed-consumer" {
			fc.ConsumerMutex.Lock()
			fc.StartConsumer()
			fc.ConsumerMutex.Unlock()
		}
		time.Sleep(time.Second * 2)
	}
}

func StartNetworkCronJob() {
	go StartNetworkLogRcvr()

	// init cron job
	NetworkCronJob = cron.New()
	err := NetworkCronJob.AddFunc(cfg.GetCfgNetCronJobTime(), DiscoverNetworkPolicyMain) // time interval
	if err != nil {
		log.Error().Msg(err.Error())
		return
	}
	NetworkCronJob.Start()

	log.Info().Msg("Auto network policy discovery cron job started")
}

func StopNetworkCronJob() {
	if NetworkCronJob != nil {
		log.Info().Msg("Got a signal to terminate the auto network policy discovery")

		close(NetworkStopChan)
		// NetworkWaitG.Wait()

		NetworkCronJob.Stop() // Stop the scheduler (does not stop any jobs already running).

		NetworkCronJob = nil
	}
}

func StartNetworkWorker() {
	if NetworkWorkerStatus != STATUS_IDLE {
		log.Info().Msg("There is no idle network policy discovery worker")
		return
	}

	if cfg.GetCfgNetOperationMode() == OP_MODE_NOOP { // Do not run the operation
		log.Info().Msg("network operation mode is NOOP ... NO NETWORK POLICY DISCOVERY")
	} else if cfg.GetCfgNetOperationMode() == OP_MODE_CRONJOB { // every time intervals
		StartNetworkCronJob()
	} else { // one-time generation
		DiscoverNetworkPolicyMain()
		log.Info().Msgf("Auto network policy onetime job done")
	}
}

func StopNetworkWorker() {
	if cfg.GetCfgNetOperationMode() == OP_MODE_CRONJOB { // every time intervals
		StopNetworkCronJob()
	} else {
		if NetworkWorkerStatus != STATUS_RUNNING {
			log.Info().Msg("There is no running network policy discovery worker")
			return
		}
	}
}
