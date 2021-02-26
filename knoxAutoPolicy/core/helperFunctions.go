package core

import (
	"math/bits"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"github.com/accuknox/knoxAutoPolicy/src/libs"
	types "github.com/accuknox/knoxAutoPolicy/src/types"
	"github.com/cilium/cilium/api/v1/flow"
)

// =========== //
// == Label == //
// =========== //

// descendingLabelCountMap Function
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

// containLabel Function
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

// combinationLabels Function
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

// countLabelByCombinations Function (combination!)
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

// getMergedSortedLabels Function
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

// containLabelByConfiguration func
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

// updateDstLabels Function
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

// clearTrackFlowID function
func clearTrackFlowID() {
	FlowIDTracker = map[FlowIDTracking][]int{}
	FlowIDTracker2 = map[FlowIDTracking2][]int{}
}

// trackFlowID function
func trackFlowID(src SrcSimple, dst Dst, flowID int) {
	trackKey := FlowIDTracking{Src: src, Dst: dst}

	if flowIDs, ok := FlowIDTracker[trackKey]; !ok {
		FlowIDTracker[trackKey] = []int{flowID}
	} else {
		if !libs.ContainsElement(flowIDs, flowID) {
			flowIDs = append(flowIDs, flowID)
			FlowIDTracker[trackKey] = flowIDs
		}
	}
}

// trackFlowID2 function
func trackFlowID2(label string, src SrcSimple, dst Dst) {
	// get ids from step 1
	idFromTrack1 := FlowIDTracker[FlowIDTracking{Src: src, Dst: dst}]

	track2Key := FlowIDTracking2{AggreagtedSrc: label, Dst: dst}

	if flowIDs, ok := FlowIDTracker2[track2Key]; !ok {
		FlowIDTracker2[track2Key] = idFromTrack1
	} else {
		for _, id := range idFromTrack1 {
			if !libs.ContainsElement(flowIDs, id) {
				flowIDs = append(flowIDs, id)
				FlowIDTracker2[track2Key] = flowIDs
			}
		}
	}
}

// getFlowIDFromTrackMap2 function
func getFlowIDFromTrackMap2(aggregatedLabel string, dst Dst) []int {
	track2Key := FlowIDTracking2{AggreagtedSrc: aggregatedLabel, Dst: dst}
	if val, ok := FlowIDTracker2[track2Key]; ok {
		return val
	}

	return []int{}
}

// ======================== //
// == Domain To IP addrs == //
// ======================== //

// getDomainNameFromDNSToIP func
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
// == Egress + Ingress into a Policy == //
// ==================================== //

// removeSelectorFromPolicies Function
func removeSelectorFromPolicies(policies []types.KnoxNetworkPolicy, inSelector types.Selector) []types.KnoxNetworkPolicy {
	cp := make([]types.KnoxNetworkPolicy, len(policies))
	copy(cp, policies)

	for i, policy := range policies {
		selector := policy.Spec.Selector

		matched := true
		for k := range inSelector.MatchLabels {
			if _, exist := selector.MatchLabels[k]; !exist {
				matched = false
			}

			if !matched {
				break
			}
		}

		if matched {
			if i == len(policies)-1 { // if element is last
				cp = cp[:len(policies)-1]
			} else {
				cp = append(cp[:i], cp[i+1:]...)
			}
		}
	}

	return cp
}

// getEgressIngressRules Function
func getEgressIngressRules(policies []types.KnoxNetworkPolicy, inSelector types.Selector) ([]types.Egress, []types.Ingress) {
	egressRules := []types.Egress{}
	ingressRules := []types.Ingress{}

	for _, policy := range policies {
		selector := policy.Spec.Selector

		matched := true
		for k := range inSelector.MatchLabels {
			if _, exist := selector.MatchLabels[k]; !exist {
				matched = false
			}

			if !matched {
				break
			}
		}

		if matched {
			for _, egress := range policy.Spec.Egress {
				egressRules = append(egressRules, egress)
			}
			for _, ingress := range policy.Spec.Ingress {
				ingressRules = append(ingressRules, ingress)
			}
		}
	}

	return egressRules, ingressRules
}

// mergeEgressIngressRules Function
func mergeEgressIngressRules(networkPolicies []types.KnoxNetworkPolicy) []types.KnoxNetworkPolicy {
	mergedNetworkPolicies := []types.KnoxNetworkPolicy{}

	for _, networkPolicy := range networkPolicies {
		selector := networkPolicy.Spec.Selector
		egress, ingress := getEgressIngressRules(networkPolicies, selector)
		networkPolicies = removeSelectorFromPolicies(networkPolicies, selector)

		new := buildNewKnoxPolicy()
		new.Spec.Selector = selector
		if len(egress) > 0 {
			new.Spec.Egress = egress
		}
		if len(ingress) > 0 {
			new.Spec.Ingress = ingress
		}
	}

	return mergedNetworkPolicies
}

// ==================================== //
// == Removing an Element from Slice == //
// ==================================== //

// removeSrcFromSlice Function
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

// removeDstFromSlice Function
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

// removeDstFromMergedDstSlice Function
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

// checkK8sExternalService Function
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

// isExposedPort Function
func isExposedPort(protocol int, port int) bool {
	if protocol == 6 { // tcp
		if libs.ContainsElement(exposedTCPPorts, port) {
			return true
		}
	} else if protocol == 17 { // udp
		if libs.ContainsElement(exposedUDPPorts, port) {
			return true
		}
	} else if protocol == 132 { // sctp
		if libs.ContainsElement(exposedSCTPPorts, port) {
			return true
		}
	}

	return false
}

// removeKubeDNSPort
func removeKubeDNSPort(toPorts []types.SpecPort) []types.SpecPort {
	filtered := []types.SpecPort{}

	for _, toPort := range toPorts {
		isDNS := false
		for _, dnsSvc := range k8sDNSSvc {
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

// updateServiceEndpoint Function
func updateServiceEndpoint(services []types.Service, endpoints []types.Endpoint, pods []types.Pod) {
	// step 1: service port update
	for _, service := range services {
		if strings.ToLower(service.Protocol) == "tcp" { // TCP
			if !libs.ContainsElement(exposedTCPPorts, service.ServicePort) {
				exposedTCPPorts = append(exposedTCPPorts, service.ServicePort)
			}
			if !libs.ContainsElement(exposedTCPPorts, service.NodePort) {
				exposedTCPPorts = append(exposedTCPPorts, service.NodePort)
			}
			if !libs.ContainsElement(exposedTCPPorts, service.TargetPort) {
				exposedTCPPorts = append(exposedTCPPorts, service.TargetPort)
			}
		} else if strings.ToLower(service.Protocol) == "udp" { // UDP
			if !libs.ContainsElement(exposedUDPPorts, service.ServicePort) {
				exposedUDPPorts = append(exposedUDPPorts, service.ServicePort)
			}
			if !libs.ContainsElement(exposedUDPPorts, service.NodePort) {
				exposedUDPPorts = append(exposedUDPPorts, service.NodePort)
			}
			if !libs.ContainsElement(exposedUDPPorts, service.TargetPort) {
				exposedUDPPorts = append(exposedUDPPorts, service.TargetPort)
			}
		} else if strings.ToLower(service.Protocol) == "sctp" { // SCTP
			if !libs.ContainsElement(exposedSCTPPorts, service.ServicePort) {
				exposedSCTPPorts = append(exposedSCTPPorts, service.ServicePort)
			}
			if !libs.ContainsElement(exposedSCTPPorts, service.NodePort) {
				exposedSCTPPorts = append(exposedSCTPPorts, service.NodePort)
			}
			if !libs.ContainsElement(exposedSCTPPorts, service.TargetPort) {
				exposedSCTPPorts = append(exposedSCTPPorts, service.TargetPort)
			}
		}
	}

	// step 2: endpoint port update
	for _, endpoint := range endpoints {
		for _, ep := range endpoint.Endpoints {
			if strings.ToLower(ep.Protocol) == "tcp" { // TCP
				if !libs.ContainsElement(exposedTCPPorts, ep.Port) {
					exposedTCPPorts = append(exposedTCPPorts, ep.Port)
				}
			} else if strings.ToLower(ep.Protocol) == "udp" { // UDP
				if !libs.ContainsElement(exposedUDPPorts, ep.Port) {
					exposedUDPPorts = append(exposedUDPPorts, ep.Port)
				}
			} else if strings.ToLower(ep.Protocol) == "sctp" { // SCTP
				if !libs.ContainsElement(exposedSCTPPorts, ep.Port) {
					exposedSCTPPorts = append(exposedSCTPPorts, ep.Port)
				}
			}
		}
	}

	// step 3: save kube-dns to the global variable
	for _, svc := range services {
		if svc.Namespace == "kube-system" && svc.ServiceName == "kube-dns" && svc.Protocol == "UDP" {
			k8sDNSSvc = append(k8sDNSSvc, svc)
		} else if svc.Namespace == "kube-system" && svc.ServiceName == "kube-dns" && svc.Protocol == "TCP" {
			k8sDNSSvc = append(k8sDNSSvc, svc)
		}
	}
}

// =============== //
// == Clearance == //
// =============== //

func clearDomainToIPs() {
	DomainToIPs = map[string][]string{}
}

func cleargLabeledSrcsPerDst() {
	gLabeledSrcsPerDst = map[string]labeledSrcsPerDstMap{}
}

func clearHTTPAggregator() {
	WildPaths = []string{WildPathDigit, WildPathChar}
	MergedSrcPerMergedDstForHTTP = map[string][]*HTTPDst{}
}

func clearGlobalVariabels() {
	clearDomainToIPs()
	cleargLabeledSrcsPerDst()
	clearHTTPAggregator()
	clearTrackFlowID()
}

// ============= //
// == Testing == //
// ============= //

// ReplaceMultiubuntuPodName ...
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
