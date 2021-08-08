package networkpolicy

import (
	"encoding/json"
	"io/ioutil"
	"math/bits"
	"os"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"github.com/accuknox/knoxAutoPolicy/src/cluster"
	"github.com/accuknox/knoxAutoPolicy/src/libs"
	"github.com/accuknox/knoxAutoPolicy/src/plugin"
	types "github.com/accuknox/knoxAutoPolicy/src/types"
	"github.com/cilium/cilium/api/v1/flow"
)

// ============================= //
// == Multi Cluster Variables == //
// ============================= //

func initMultiClusterVariables(clusterName string) {
	val := ClusterVariable{
		K8sServiceTCPPorts:  []int{},
		K8sServiceUDPPorts:  []int{},
		K8sServiceSCTPPorts: []int{},

		LabeledSrcsPerDst: map[string]labeledSrcsPerDstMap{},
		DomainToIPs:       map[string][]string{},
		K8sDNSServices:    []types.Service{},

		FlowIDTrackerFirst:  map[FlowIDTrackingFirst][]int{},
		FlowIDTrackerSecond: map[FlowIDTrackingSecond][]int{},
	}

	if exist, ok := ClusterVariableMap[clusterName]; ok {
		val = exist
	}

	K8sServiceTCPPorts = val.K8sServiceTCPPorts
	K8sServiceUDPPorts = val.K8sServiceUDPPorts
	K8sServiceSCTPPorts = val.K8sServiceSCTPPorts

	LabeledSrcsPerDst = val.LabeledSrcsPerDst
	DomainToIPs = val.DomainToIPs

	K8sDNSServices = val.K8sDNSServices

	FlowIDTrackerFirst = val.FlowIDTrackerFirst
	FlowIDTrackerSecond = val.FlowIDTrackerSecond
}

func updateMultiClusterVariables(clusterName string) {
	if exist, ok := ClusterVariableMap[clusterName]; ok {
		exist.K8sServiceTCPPorts = K8sServiceTCPPorts
		exist.K8sServiceUDPPorts = K8sServiceUDPPorts
		exist.K8sServiceSCTPPorts = K8sServiceSCTPPorts

		exist.LabeledSrcsPerDst = LabeledSrcsPerDst
		exist.DomainToIPs = DomainToIPs

		exist.K8sDNSServices = K8sDNSServices

		exist.FlowIDTrackerFirst = FlowIDTrackerFirst
		exist.FlowIDTrackerSecond = FlowIDTrackerSecond

		ClusterVariableMap[clusterName] = exist
	}
}

// =========================== //
// == Network Policy Filter == //
// =========================== //

func SkipNamespaceForNetworkPolicy(namespace string) bool {
	// skip uninterested namespaces
	if libs.ContainsElement(NamespaceFilters, namespace) {
		return true
	} else if strings.HasPrefix(namespace, "accuknox-") {
		return true
	}

	return false
}

func getHaveToCheckItems(igFlows types.NetworkLogFilter) int {
	check := 0

	if igFlows.SourceNamespace != "" {
		check = check | 1<<0 // 1
	}

	if len(igFlows.SourceLabels) > 0 {
		check = check | 1<<1 // 2
	}

	if igFlows.DestinationNamespace != "" {
		check = check | 1<<2 // 4
	}

	if len(igFlows.DestinationLabels) > 0 {
		check = check | 1<<3 // 8
	}

	if igFlows.Protocol != "" {
		check = check | 1<<4 // 16
	}

	if igFlows.PortNumber != "" {
		check = check | 1<<5 // 32
	}

	return check
}

func FilterNetworkLogsByConfig(logs []types.KnoxNetworkLog, pods []types.Pod) []types.KnoxNetworkLog {
	filteredLogs := []types.KnoxNetworkLog{}

	for _, log := range logs {
		filtered := false

		for _, filter := range NetworkLogFilters {
			checkItems := getHaveToCheckItems(filter)

			checkedItems := 0

			// 1. check src namespace
			if (checkItems&1 > 0) && filter.SourceNamespace == log.SrcNamespace {
				checkedItems = checkedItems | 1<<0
			}

			// 2. check src pod labels
			if (checkItems&2 > 0) && containLabelByConfiguration("cilium", filter.SourceLabels, getLabelsFromPod(log.SrcPodName, pods)) {
				checkedItems = checkedItems | 1<<1
			}

			// 3. check dest namespace
			if (checkItems&4 > 0) && filter.DestinationNamespace == log.DstNamespace {
				checkedItems = checkedItems | 1<<2
			}

			// 4. check dest pod labels
			if (checkItems&8 > 0) && containLabelByConfiguration("cilium", filter.DestinationLabels, getLabelsFromPod(log.DstPodName, pods)) {
				checkedItems = checkedItems | 1<<3
			}

			// 5. check protocol
			if (checkItems&16 > 0) && libs.GetProtocol(log.Protocol) == strings.ToLower(filter.Protocol) {
				checkedItems = checkedItems | 1<<4
			}

			// 6. check port number (src or dst)
			if checkItems&32 > 0 {
				if strconv.Itoa(log.SrcPort) == filter.PortNumber || strconv.Itoa(log.DstPort) == filter.PortNumber {
					checkedItems = checkedItems | 1<<5
				}
			}

			if checkItems == checkedItems {
				filtered = true
				break
			}
		}

		if !filtered {
			filteredLogs = append(filteredLogs, log)
		}
	}

	return filteredLogs
}

func FilterNetworkLogsByNamespace(targetNamespace string, logs []types.KnoxNetworkLog) []types.KnoxNetworkLog {
	filteredLogs := []types.KnoxNetworkLog{}

	// case 1: src namespace == target namespace
	// case 2: dst namespace == target namespace && src namespace == reserved: or kube-system or cilium
	for _, log := range logs {
		if log.SrcNamespace == targetNamespace {
			filteredLogs = append(filteredLogs, log)

		} else if log.DstNamespace == targetNamespace {
			if strings.Contains(log.SrcNamespace, "reserved:") {
				filteredLogs = append(filteredLogs, log)
			}
		}
	}

	return filteredLogs
}

// ================= //
// == Network Log == //
// ================= //

func getNetworkLogs() []types.KnoxNetworkLog {
	networkLogs := []types.KnoxNetworkLog{}

	// =============== //
	// == Database  == //
	// =============== //
	if NetworkLogFrom == "db" {
		log.Info().Msg("Get network log from the database")

		// get network logs from db
		netLogs := libs.GetNetworkLogsFromDB(CfgDB, OneTimeJobTime)
		if len(netLogs) == 0 {
			return nil
		}

		// convert cilium network logs -> knox network logs
		networkLogs = plugin.ConvertCiliumNetworkLogsToKnoxNetworkLogs(CfgDB.DBDriver, netLogs)
	} else if NetworkLogFrom == "hubble" {
		// ========================== //
		// == Cilium Hubble Relay  == //
		// ========================== //
		log.Info().Msg("Get network log from the Cilium Hubble directly")

		// get flows from hubble relay
		flows := plugin.GetCiliumFlowsFromHubble()
		if len(flows) == 0 {
			return nil
		}

		// convert hubble flows -> network logs (but, in this case, no flow id)
		for _, flow := range flows {
			if log, valid := plugin.ConvertCiliumFlowToKnoxNetworkLog(flow); valid {
				networkLogs = append(networkLogs, log)
			}
		}
	} else if NetworkLogFrom == "file" {
		// =============================== //
		// == File (.json) for testing  == //
		// =============================== //
		log.Info().Msg("Get network logs from the json file : " + NetworkLogFile)
		flows := []*flow.Flow{}

		// Open jsonFile
		logFile, err := os.Open(NetworkLogFile)
		if err != nil {
			log.Error().Msg(err.Error())
			if err := logFile.Close(); err != nil {
				log.Error().Msg(err.Error())
			}
			return nil
		}

		byteValue, err := ioutil.ReadAll(logFile)
		if err != nil {
			log.Error().Msg(err.Error())
		}

		if err := json.Unmarshal(byteValue, &flows); err != nil {
			log.Error().Msg(err.Error())
			return nil
		}

		// replace the pod names in prepared-flows with the working pod names
		pods := cluster.GetPodsFromK8sClient()
		ReplaceMultiubuntuPodName(flows, pods)

		// convert file flows -> network logs (but, in this case, no flow id..)
		for _, flow := range flows {
			if log, valid := plugin.ConvertCiliumFlowToKnoxNetworkLog(flow); valid {
				networkLogs = append(networkLogs, log)
			}
		}

		if err := logFile.Close(); err != nil {
			log.Error().Msg(err.Error())
		}
	} else {
		log.Error().Msgf("Network log source not correct: %s", NetworkLogFrom)
		return nil
	}

	return networkLogs
}

func clusteringNetworkLogs(networkLogs []types.KnoxNetworkLog) map[string][]types.KnoxNetworkLog {
	clusterNameMap := map[string][]types.KnoxNetworkLog{}

	for _, log := range networkLogs {
		if _, ok := clusterNameMap[log.ClusterName]; ok {
			clusterNameMap[log.ClusterName] = append(clusterNameMap[log.ClusterName], log)
		} else {
			clusterNameMap[log.ClusterName] = []types.KnoxNetworkLog{log}
		}
	}

	return clusterNameMap
}

// =========== //
// == Label == //
// =========== //

func descendingLabelCountMap(labelCountMap map[string]int) []LabelCount {
	// sort label count by descending orders
	// but, 2 labels = 2 vs. 1 label 2 --> 2 labels win
	var labelCounts []LabelCount
	for label, count := range labelCountMap {
		numberOfLabels := len(strings.Split(label, ","))
		labelCounts = append(labelCounts, LabelCount{label, float64(count) + float64(numberOfLabels)/100})
	}

	sort.Slice(labelCounts, func(i, j int) bool {
		return labelCounts[i].Count > labelCounts[j].Count
	})

	return labelCounts
}

func containLabel(mergedLabel, targetLabel string) bool {
	labels := strings.Split(mergedLabel, ",")
	targetLabels := strings.Split(targetLabel, ",")

	if len(labels) == 1 { // single label
		for _, target := range targetLabels {
			if mergedLabel == target {
				return true
			}
		}
	} else {
		for i := 2; i <= len(targetLabels); i++ {
			results := combinationLabels(targetLabels, i)
			for _, comb := range results {
				combineLabel := strings.Join(comb, ",")
				if mergedLabel == combineLabel {
					return true
				}
			}
		}
	}

	return false
}

func containLabelByConfiguration(cni string, igLabels []string, flowLabels []string) bool {
	prefix := ""

	if cni == "cilium" {
		prefix = "k8s:"
	}

	for _, label := range igLabels {
		label = prefix + label

		if !libs.ContainsElement(flowLabels, label) {
			return false
		}
	}

	return true
}

func combinationLabels(set []string, n int) (subsets [][]string) {
	length := uint(len(set))

	if n > len(set) {
		n = len(set)
	}

	// Go through all possible combinations of objects
	// from 1 (only first object in subset) to 2^length (all objects in subset)
	for subsetBits := 1; subsetBits < (1 << length); subsetBits++ {
		if n > 0 && bits.OnesCount(uint(subsetBits)) != n {
			continue
		}

		var subset []string

		for object := uint(0); object < length; object++ {
			// checks if object is contained in subset
			// by checking if bit 'object' is set in subsetBits
			if (subsetBits>>object)&1 == 1 {
				// add object to subset
				subset = append(subset, set[object])
			}
		}
		// add subset to subsets
		subsets = append(subsets, subset)
	}

	return subsets
}

func countLabelByCombinations(labelCount map[string]int, mergedLabels string) {
	// split labels
	labels := strings.Split(mergedLabels, ",")

	// sorting string first: a -> b -> c -> ...
	sort.Slice(labels, func(i, j int) bool {
		return labels[i] > labels[j]
	})

	// step 1: count single label
	for _, label := range labels {
		if val, ok := labelCount[label]; ok {
			labelCount[label] = val + 1
		} else {
			labelCount[label] = 1
		}
	}

	if len(labels) < 2 {
		return
	}

	// step 2: count multiple labels (at least, it should be 2)
	for i := 2; i <= len(labels); i++ {
		results := combinationLabels(labels, i)
		for _, comb := range results {
			combineLabel := strings.Join(comb, ",")
			if val, ok := labelCount[combineLabel]; ok {
				labelCount[combineLabel] = val + 1
			} else {
				labelCount[combineLabel] = 1
			}
		}
	}
}

func getMergedSortedLabels(namespace, podName string, pods []types.Pod) string {
	mergedLabels := ""

	for _, pod := range pods {
		// find the src pod
		if namespace == pod.Namespace && podName == pod.PodName {
			// remove common name identities
			labels := []string{}

			for _, label := range pod.Labels {
				/* TODO: do we need to skip the hash labels? */
				labels = append(labels, label)
			}

			// sorting labels alphabetically
			sort.Slice(labels, func(i, j int) bool {
				return labels[i] > labels[j]
			})

			mergedLabels = strings.Join(labels, ",")
			return mergedLabels
		}
	}

	return ""
}

func getLabelsFromPod(podName string, pods []types.Pod) []string {
	for _, pod := range pods {
		if pod.PodName == podName {
			return pod.Labels
		}
	}

	return []string{}
}

func updateDstLabels(dsts []MergedPortDst, pods []types.Pod) []MergedPortDst {
	for i, dst := range dsts {
		matchLabels := getMergedSortedLabels(dst.Namespace, dst.PodName, pods)
		if matchLabels != "" {
			dsts[i].MatchLabels = matchLabels
		}
	}

	return dsts
}

// ====================== //
// == Flow ID Tracking == //
// ====================== //

func trackFlowIDFirst(src SrcSimple, dst Dst, flowID int) {
	trackKey := FlowIDTrackingFirst{Src: src, Dst: dst}

	if flowIDs, ok := FlowIDTrackerFirst[trackKey]; !ok {
		FlowIDTrackerFirst[trackKey] = []int{flowID}
	} else {
		if !libs.ContainsElement(flowIDs, flowID) {
			flowIDs = append(flowIDs, flowID)
			FlowIDTrackerFirst[trackKey] = flowIDs
		}
	}
}

func trackFlowIDSecond(label string, src SrcSimple, dst Dst) {
	// get ids from step 1
	idFromTrack1 := FlowIDTrackerFirst[FlowIDTrackingFirst{Src: src, Dst: dst}]

	track2Key := FlowIDTrackingSecond{AggreagtedSrc: label, Dst: dst}

	if flowIDs, ok := FlowIDTrackerSecond[track2Key]; !ok {
		FlowIDTrackerSecond[track2Key] = idFromTrack1
	} else {
		for _, id := range idFromTrack1 {
			if !libs.ContainsElement(flowIDs, id) {
				flowIDs = append(flowIDs, id)
				FlowIDTrackerSecond[track2Key] = flowIDs
			}
		}
	}
}

func getFlowIDFromTrackMap2(aggregatedLabel string, dst Dst) []int {
	track2Key := FlowIDTrackingSecond{AggreagtedSrc: aggregatedLabel, Dst: dst}
	if val, ok := FlowIDTrackerSecond[track2Key]; ok {
		return val
	}

	return []int{}
}

// ======================== //
// == Domain To IP addrs == //
// ======================== //

func updateDNSFlows(networkLogs []types.KnoxNetworkLog) {
	// step 1: update dnsToIPs map
	for _, log := range networkLogs {
		if log.DNSRes != "" && log.DNSResIPs != nil {
			domainName := log.DNSRes

			// udpate DNS to IPs map
			if ips, ok := DomainToIPs[domainName]; ok {
				for _, ip := range ips {
					if !libs.ContainsElement(ips, ip) {
						ips = append(ips, ip)
					}
				}

				DomainToIPs[domainName] = ips
			} else {
				DomainToIPs[domainName] = ips
			}
		}
	}

	// step 2: update dns query logs
	for i, log := range networkLogs {
		// traffic go to the outside of the cluster,
		if log.DstNamespace == "reserved:world" {
			// filter if the ip is from the DNS query
			dns := getDomainNameFromDNSToIP(log)
			if dns != "" {
				networkLogs[i].DNSQuery = dns
			}
		}
	}
}

func getDomainNameFromDNSToIP(log types.KnoxNetworkLog) string {
	for domain, ips := range DomainToIPs {
		// here, pod name is ip addr (external)
		if libs.ContainsElement(ips, log.DstPodName) {
			return domain
		}
	}

	return ""
}

// ==================================== //
// == Removing an Element from Slice == //
// ==================================== //

func removeSrcFromSlice(srcs []SrcSimple, remove SrcSimple) []SrcSimple {
	cp := make([]SrcSimple, len(srcs))
	copy(cp, srcs)

	for i, src := range srcs {
		if src == remove {
			if i == len(srcs)-1 { // if element is last
				cp = cp[:len(srcs)-1]
			} else {
				cp = append(cp[:i], cp[i+1:]...)
			}
		}
	}

	return cp
}

func removeDstFromSlice(dsts []Dst, remove Dst) []Dst {
	cp := make([]Dst, len(dsts))
	copy(cp, dsts)

	for i, dst := range dsts {
		if dst == remove {
			if i == len(dsts)-1 { // if element is last
				cp = cp[:len(dsts)-1]
			} else {
				cp = append(cp[:i], cp[i+1:]...)
			}
		}
	}

	return cp
}

func removeDstFromMergedDstSlice(dsts []MergedPortDst, remove MergedPortDst) []MergedPortDst {
	cp := make([]MergedPortDst, len(dsts))
	copy(cp, dsts)

	for i, dst := range dsts {
		if reflect.DeepEqual(dst, remove) {
			if i == len(dsts)-1 { // if element is last
				cp = cp[:len(dsts)-1]
			} else {
				cp = append(cp[:i], cp[i+1:]...)
			}
		}
	}

	return cp
}

// =================================== //
// == Kubernetes Services/Endpoints == //
// =================================== //

func checkK8sExternalService(log types.KnoxNetworkLog, endpoints []types.Endpoint) (types.Endpoint, bool) {
	for _, endpoint := range endpoints {
		for _, port := range endpoint.Endpoints {
			if (libs.GetProtocol(log.Protocol) == strings.ToLower(port.Protocol)) &&
				log.DstPort == port.Port &&
				log.DstIP == port.IP {
				return endpoint, true
			}
		}
	}

	return types.Endpoint{}, false
}

func isExposedPort(protocol int, port int) bool {
	if protocol == 6 { // tcp
		if libs.ContainsElement(K8sServiceTCPPorts, port) {
			return true
		}
	} else if protocol == 17 { // udp
		if libs.ContainsElement(K8sServiceUDPPorts, port) {
			return true
		}
	} else if protocol == 132 { // sctp
		if libs.ContainsElement(K8sServiceSCTPPorts, port) {
			return true
		}
	}

	return false
}

func removeKubeDNSPort(toPorts []types.SpecPort) []types.SpecPort {
	filtered := []types.SpecPort{}

	for _, toPort := range toPorts {
		isDNS := false
		for _, dnsSvc := range K8sDNSServices {
			if toPort.Port == strconv.Itoa(dnsSvc.ServicePort) &&
				toPort.Protocol == strings.ToLower(dnsSvc.Protocol) {
				isDNS = true
				break
			}
		}

		if !isDNS {
			filtered = append(filtered, toPort)
		}
	}

	if len(filtered) == 0 {
		return nil
	}

	return filtered
}

func updateServiceEndpoint(services []types.Service, endpoints []types.Endpoint, pods []types.Pod) {
	// step 1: service port update
	for _, service := range services {
		if strings.ToLower(service.Protocol) == "tcp" { // TCP
			if !libs.ContainsElement(K8sServiceTCPPorts, service.ServicePort) {
				K8sServiceTCPPorts = append(K8sServiceTCPPorts, service.ServicePort)
			}
			if !libs.ContainsElement(K8sServiceTCPPorts, service.NodePort) {
				K8sServiceTCPPorts = append(K8sServiceTCPPorts, service.NodePort)
			}
			if !libs.ContainsElement(K8sServiceTCPPorts, service.TargetPort) {
				K8sServiceTCPPorts = append(K8sServiceTCPPorts, service.TargetPort)
			}
		} else if strings.ToLower(service.Protocol) == "udp" { // UDP
			if !libs.ContainsElement(K8sServiceUDPPorts, service.ServicePort) {
				K8sServiceUDPPorts = append(K8sServiceUDPPorts, service.ServicePort)
			}
			if !libs.ContainsElement(K8sServiceUDPPorts, service.NodePort) {
				K8sServiceUDPPorts = append(K8sServiceUDPPorts, service.NodePort)
			}
			if !libs.ContainsElement(K8sServiceUDPPorts, service.TargetPort) {
				K8sServiceUDPPorts = append(K8sServiceUDPPorts, service.TargetPort)
			}
		} else if strings.ToLower(service.Protocol) == "sctp" { // SCTP
			if !libs.ContainsElement(K8sServiceSCTPPorts, service.ServicePort) {
				K8sServiceSCTPPorts = append(K8sServiceSCTPPorts, service.ServicePort)
			}
			if !libs.ContainsElement(K8sServiceSCTPPorts, service.NodePort) {
				K8sServiceSCTPPorts = append(K8sServiceSCTPPorts, service.NodePort)
			}
			if !libs.ContainsElement(K8sServiceSCTPPorts, service.TargetPort) {
				K8sServiceSCTPPorts = append(K8sServiceSCTPPorts, service.TargetPort)
			}
		}
	}

	// step 2: endpoint port update
	for _, endpoint := range endpoints {
		for _, ep := range endpoint.Endpoints {
			if strings.ToLower(ep.Protocol) == "tcp" { // TCP
				if !libs.ContainsElement(K8sServiceTCPPorts, ep.Port) {
					K8sServiceTCPPorts = append(K8sServiceTCPPorts, ep.Port)
				}
			} else if strings.ToLower(ep.Protocol) == "udp" { // UDP
				if !libs.ContainsElement(K8sServiceUDPPorts, ep.Port) {
					K8sServiceUDPPorts = append(K8sServiceUDPPorts, ep.Port)
				}
			} else if strings.ToLower(ep.Protocol) == "sctp" { // SCTP
				if !libs.ContainsElement(K8sServiceSCTPPorts, ep.Port) {
					K8sServiceSCTPPorts = append(K8sServiceSCTPPorts, ep.Port)
				}
			}
		}
	}

	// step 3: save kube-dns to the global variable
	for _, svc := range services {
		if svc.Namespace == "kube-system" && svc.ServiceName == "kube-dns" && svc.Protocol == "UDP" {
			K8sDNSServices = append(K8sDNSServices, svc)
		} else if svc.Namespace == "kube-system" && svc.ServiceName == "kube-dns" && svc.Protocol == "TCP" {
			K8sDNSServices = append(K8sDNSServices, svc)
		}
	}
}

// =============== //
// == Clearance == //
// =============== //

func clearTrackFlowIDMaps() {
	FlowIDTrackerFirst = map[FlowIDTrackingFirst][]int{}
	FlowIDTrackerSecond = map[FlowIDTrackingSecond][]int{}
}

func clearDomainToIPs() {
	DomainToIPs = map[string][]string{}
}

func cleargLabeledSrcsPerDst() {
	LabeledSrcsPerDst = map[string]labeledSrcsPerDstMap{}
}

func clearHTTPAggregator() {
	WildPaths = []string{WildPathDigit, WildPathChar}
	MergedSrcPerMergedDstForHTTP = map[string][]*HTTPDst{}
}

func clearGlobalVariabels() {
	clearDomainToIPs()
	cleargLabeledSrcsPerDst()
	clearHTTPAggregator()
	clearTrackFlowIDMaps()
}

// ================== //
// == File Outputs == //
// ================== //

func WriteNetworkPoliciesToFile(cluster, namespace string, services []types.Service) {
	// retrieve the latest policies from the db
	latestPolicies := libs.GetNetworkPolicies(CfgDB, cluster, namespace, "latest")

	// write discovered policies to files
	libs.WriteKnoxPolicyToYamlFile(namespace, latestPolicies)

	// convert knoxPolicy to CiliumPolicy
	ciliumPolicies := plugin.ConvertKnoxPoliciesToCiliumPolicies(services, latestPolicies)

	// write discovered policies to files
	libs.WriteCiliumPolicyToYamlFile(namespace, ciliumPolicies)
}

// ====================== //
// == Internal Testing == //
// ====================== //

func ReplaceMultiubuntuPodName(flows []*flow.Flow, pods []types.Pod) {
	var pod1Name, pod2Name, pod3Name, pod4Name, pod5Name string
	var kubeDNS string

	for _, pod := range pods {
		if strings.Contains(pod.PodName, "ubuntu-1-deployment") {
			pod1Name = pod.PodName
		}

		if strings.Contains(pod.PodName, "ubuntu-2-deployment") {
			pod2Name = pod.PodName
		}

		if strings.Contains(pod.PodName, "ubuntu-3-deployment") {
			pod3Name = pod.PodName
		}

		if strings.Contains(pod.PodName, "ubuntu-4-deployment") {
			pod4Name = pod.PodName
		}

		if strings.Contains(pod.PodName, "ubuntu-5-deployment") {
			pod5Name = pod.PodName
		}

		if strings.Contains(pod.PodName, "kube-dns") && !strings.Contains(pod.PodName, "kube-dns-autoscaler") {
			kubeDNS = pod.PodName
		}

		if strings.Contains(pod.PodName, "coredns") && !strings.Contains(pod.PodName, "coredns-autoscaler") {
			kubeDNS = pod.PodName
		}
	}

	for i, flow := range flows {
		if strings.Contains(flow.GetSource().GetPodName(), "ubuntu-1-deployment") {
			flows[i].Source.PodName = pod1Name
		}

		if strings.Contains(flow.GetDestination().GetPodName(), "ubuntu-1-deployment") {
			flows[i].Destination.PodName = pod1Name
		}

		///

		if strings.Contains(flow.GetSource().GetPodName(), "ubuntu-2-deployment") {
			flows[i].Source.PodName = pod2Name
		}

		if strings.Contains(flow.GetDestination().GetPodName(), "ubuntu-2-deployment") {
			flows[i].Destination.PodName = pod2Name
		}

		///

		if strings.Contains(flow.GetSource().GetPodName(), "ubuntu-3-deployment") {
			flows[i].Source.PodName = pod3Name
		}

		if strings.Contains(flow.GetDestination().GetPodName(), "ubuntu-3-deployment") {
			flows[i].Destination.PodName = pod3Name
		}

		///

		if strings.Contains(flow.GetSource().GetPodName(), "ubuntu-4-deployment") {
			flows[i].Source.PodName = pod4Name
		}

		if strings.Contains(flow.GetDestination().GetPodName(), "ubuntu-4-deployment") {
			flows[i].Destination.PodName = pod4Name
		}

		///

		if strings.Contains(flow.GetSource().GetPodName(), "ubuntu-5-deployment") {
			flows[i].Source.PodName = pod5Name
		}

		if strings.Contains(flow.GetDestination().GetPodName(), "ubuntu-5-deployment") {
			flows[i].Destination.PodName = pod5Name
		}

		///

		if strings.Contains(flow.GetSource().GetPodName(), "kube-dns") && !strings.Contains(flow.GetSource().GetPodName(), "kube-dns-autoscaler") {
			flows[i].Source.PodName = kubeDNS
		}

		if strings.Contains(flow.GetDestination().GetPodName(), "kube-dns") && !strings.Contains(flow.GetSource().GetPodName(), "kube-dns-autoscaler") {
			flows[i].Destination.PodName = kubeDNS
		}

		///

		if strings.Contains(flow.GetSource().GetPodName(), "coredns") && !strings.Contains(flow.GetSource().GetPodName(), "coredns-autoscaler") {
			flows[i].Source.PodName = kubeDNS
		}

		if strings.Contains(flow.GetDestination().GetPodName(), "coredns") && !strings.Contains(flow.GetSource().GetPodName(), "coredns-autoscaler") {
			flows[i].Destination.PodName = kubeDNS
		}
	}
}
