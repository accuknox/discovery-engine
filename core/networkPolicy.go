package core

import (
	"net"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"github.com/accuknox/knoxAutoPolicy/libs"
	types "github.com/accuknox/knoxAutoPolicy/types"
)

var skippedLabels = []string{"pod-template-hash"}

var exposedTCPPorts = []int{}
var exposedUDPPorts = []int{}
var exposedSCTPPorts = []int{}

var DefaultSelectorKey string = "container_group_name"

var (
	ICMP int = 1
	TCP  int = 6
	UDP  int = 17
	SCTP int = 132
)

// SrcSimple Structure
type SrcSimple struct {
	MicroserviceName   string
	ContainerGroupName string
	MatchLabels        string
}

// Dst Structure
type Dst struct {
	MicroserviceName   string
	ContainerGroupName string
	MatchLabels        string
	Protocol           int
	DstPort            int
	Action             string
}

// DstSimple Structure
type DstSimple struct {
	MicroserviceName   string
	ContainerGroupName string
	Action             string
}

// MergedDst Structure
type MergedDst struct {
	MicroserviceName   string
	ContainerGroupName string
	MatchLabels        string
	ToPorts            []types.ToPort
	ToCIDRs            []types.ToCIDR
	Action             string
}

// LabelCount Structure
type LabelCount struct {
	Label string
	Count int
}

// ============ //
// == Common == //
// ============ //

// filterLogs Function
func filterLogs(originalLogs []types.NetworkLog, microName string) []types.NetworkLog {
	filteredLogs := []types.NetworkLog{}

	for _, log := range originalLogs {
		// filter microservice name
		if log.SrcMicroserviceName != microName && log.DstMicroserviceName != microName {
			continue
		}

		// filter source is in the external
		if log.SrcMicroserviceName == "external" {
			continue
		}

		// filter cni network logs
		if libs.ContainsElement([]string{"WeaveNet", "Flannel", "Calico"}, log.SrcContainerGroupName) ||
			libs.ContainsElement([]string{"WeaveNet", "Flannel", "Calico"}, log.DstContainerGroupName) {
			continue
		}

		filteredLogs = append(filteredLogs, log)
	}

	return filteredLogs
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
		results := libs.Combinations(labels, i)
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

// containLabel Function
func containLabel(label, targetLabel string) bool {
	labels := strings.Split(label, ",")
	targetLabels := strings.Split(targetLabel, ",")

	if len(labels) == 1 { // single label
		for _, target := range targetLabels {
			if label == target {
				return true
			}
		}
	} else {
		for i := 2; i <= len(targetLabels); i++ {
			results := libs.Combinations(targetLabels, i)
			for _, comb := range results {
				combineLabel := strings.Join(comb, ",")
				if label == combineLabel {
					return true
				}
			}
		}
	}

	return false
}

// descendingLabelCountMap Function
func descendingLabelCountMap(labelCountMap map[string]int) []LabelCount {
	labelCounts := []LabelCount{}
	for label, count := range labelCountMap {
		labelCounts = append(labelCounts, LabelCount{label, count})
	}

	sort.Slice(labelCounts, func(i, j int) bool {
		return labelCounts[i].Count > labelCounts[j].Count
	})

	return labelCounts
}

// removeSrc Function
func removeSrc(srcs []SrcSimple, remove SrcSimple) []SrcSimple {
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

// sortingLableCount Function
func sortingLableCount(labelCountMap map[string]int) []LabelCount {
	// sort label count by descending orders
	var labelCounts []LabelCount
	for label, count := range labelCountMap {
		labelCounts = append(labelCounts, LabelCount{label, count})
	}

	sort.Slice(labelCounts, func(i, j int) bool {
		return labelCounts[i].Count > labelCounts[j].Count
	})

	return labelCounts
}

// updateDstLabels Function
func updateDstLabels(dsts []MergedDst, groups []types.ContainerGroup) []MergedDst {
	for i, dst := range dsts {
		matchLabels := getMergedLabels(dst.MicroserviceName, dst.ContainerGroupName, groups)

		if matchLabels != "" {
			dsts[i].MatchLabels = matchLabels
		}
	}

	return dsts
}

// removeDst Function
func removeDst(dsts []Dst, remove Dst) []Dst {
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

// removeDstMerged Function
func removeDstMerged(dsts []MergedDst, remove MergedDst) []MergedDst {
	cp := make([]MergedDst, len(dsts))
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

// IsExposedPort Function
func IsExposedPort(protocol int, port int) bool {
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

// UpdateExposedPorts Function
func UpdateExposedPorts(services []types.K8sService, contGroups []types.ContainerGroup) {
	// step 1: (k8s) service port update
	for _, service := range services {
		if strings.ToLower(service.Protocol) == "tcp" { // TCP
			if !libs.ContainsElement(exposedTCPPorts, service.ServicePort) {
				exposedTCPPorts = append(exposedTCPPorts, service.ServicePort)
			}
		} else if strings.ToLower(service.Protocol) == "udp" { // UDP
			if !libs.ContainsElement(exposedUDPPorts, service.ServicePort) {
				exposedUDPPorts = append(exposedUDPPorts, service.ServicePort)
			}
		} else if strings.ToLower(service.Protocol) == "sctp" { // SCTP
			if !libs.ContainsElement(exposedSCTPPorts, service.ServicePort) {
				exposedSCTPPorts = append(exposedSCTPPorts, service.ServicePort)
			}
		}
	}

	// step 2: port binding update
	for _, conGroup := range contGroups {
		for _, portBinding := range conGroup.PortBindings {
			if strings.ToLower(portBinding.Protocol) == "tcp" {
				if !libs.ContainsElement(exposedTCPPorts, portBinding.Port) {
					exposedTCPPorts = append(exposedTCPPorts, portBinding.Port)
				}
			} else if strings.ToLower(portBinding.Protocol) == "udp" {
				if !libs.ContainsElement(exposedUDPPorts, portBinding.Port) {
					exposedUDPPorts = append(exposedUDPPorts, portBinding.Port)
				}
			} else if strings.ToLower(portBinding.Protocol) == "sctp" {
				if !libs.ContainsElement(exposedSCTPPorts, portBinding.Port) {
					exposedSCTPPorts = append(exposedSCTPPorts, portBinding.Port)
				}
			}
		}
	}
}

// ============================ //
// == Build Network Policies == //
// ============================ //

func buildNewPolicy(action string) types.KnoxNetworkPolicy {
	policyName := "generated_" + libs.RandSeq(10)

	return types.KnoxNetworkPolicy{
		APIVersion: "v1",
		Kind:       "KnoxNetworkPolicy",
		Metadata:   map[string]string{"name": policyName},
		Spec: types.Spec{
			Selector: types.Selector{
				Identities:  []string{},
				Networks:    []types.PolicyNetwork{},
				MatchNames:  map[string]string{},
				MatchLabels: map[string]string{}},
			Egress: types.Egress{
				Identities:  []string{},
				Networks:    []types.PolicyNetwork{},
				MatchNames:  map[string]string{},
				MatchLabels: map[string]string{}},
			Action: action,
		},
	}
}

// BuildNetworkPolicies Function
func BuildNetworkPolicies(microName string, mergedSrcPerMergedDst map[string][]MergedDst) []types.KnoxNetworkPolicy {
	networkPolicies := []types.KnoxNetworkPolicy{}

	for mergedSrc, mergedDsts := range mergedSrcPerMergedDst {
		for _, dst := range mergedDsts {
			policy := buildNewPolicy(dst.Action)

			// set selector labels
			srcs := strings.Split(mergedSrc, ",")
			for _, src := range srcs {
				kv := strings.Split(src, "=")
				if len(kv) != 2 {
					continue
				}

				srcKey := kv[0]
				srcVal := kv[1]

				policy.Spec.Selector.MatchLabels[srcKey] = srcVal
			}

			// set egress labels
			if dst.MatchLabels != "" {
				dsts := strings.Split(dst.MatchLabels, ",")
				for _, dst := range dsts {
					kv := strings.Split(dst, "=")
					if len(kv) != 2 {
						continue
					}

					dstkey := kv[0]
					dstval := kv[1]

					policy.Spec.Egress.MatchLabels[dstkey] = dstval
				}

				if dst.ToPorts != nil && len(dst.ToPorts) > 0 {
					for i, toPort := range dst.ToPorts {
						if toPort.Ports == "0" {
							dst.ToPorts[i].Ports = ""
						}
					}
					policy.Spec.Egress.ToPorts = dst.ToPorts
				}
			} else if dst.MicroserviceName == "external" {
				cidr := types.ToCIDR{
					CIDR: dst.ContainerGroupName,
				}

				policy.Spec.Egress.ToCIDRs = []types.ToCIDR{cidr}
			} else {
				continue
			}

			networkPolicies = append(networkPolicies, policy)
		}
	}

	return networkPolicies
}

// =========================================== //
// == Step 1: Grouping Network Logs Per Dst == //
// =========================================== //

// getSimpleDst Function
func getSimpleDst(log types.NetworkLog, cidrBits int) (Dst, bool) {
	dstPort := 0
	dstGroupName := ""

	if IsExposedPort(log.Protocol, log.DstPort) { // if exposed tcp, udp, or sctp
		dstPort = log.DstPort
	} else if log.Protocol == TCP && log.SynFlag { // if tcp + syn flag
		dstPort = log.DstPort
	} else if log.Protocol == ICMP { // if icmp,
		if log.SrcPort != 8 { // srcport == type (8: icmp request)
			return Dst{}, false
		}
	} else {
		return Dst{}, false
	}

	// if dst is out of cluster, get cidr/bits
	if log.DstMicroserviceName == "external" && net.ParseIP(log.DstContainerGroupName) != nil {
		ipNetwork := log.DstContainerGroupName + "/" + strconv.Itoa(cidrBits)
		_, network, _ := net.ParseCIDR(ipNetwork)
		dstGroupName = network.String()
	} else {
		dstGroupName = log.DstContainerGroupName
	}

	dst := Dst{
		MicroserviceName:   log.DstMicroserviceName,
		ContainerGroupName: dstGroupName,
		Protocol:           log.Protocol,
		DstPort:            dstPort,
		Action:             log.Action,
	}

	return dst, true
}

// groupingLogsPerDst Function
func groupingLogsPerDst(networkLogs []types.NetworkLog, cidrBits int) map[Dst][]types.NetworkLog {
	perDst := map[Dst][]types.NetworkLog{}

	for _, log := range networkLogs {
		dst, valid := getSimpleDst(log, cidrBits)
		if !valid {
			continue
		}

		if _, ok := perDst[dst]; !ok {
			perDst[dst] = []types.NetworkLog{log}
		} else {
			perDst[dst] = append(perDst[dst], log)
		}
	}

	return perDst
}

// FlowCount Structure
type FlowCount struct {
	Dst   Dst
	Count int
}

// subtractReverseDstCount Function
func subtractReverseDstCount(flowCounts []FlowCount, reverse Dst, count int) {
	for i, flowCount := range flowCounts {
		if flowCount.Dst == reverse {
			flowCounts[i].Count -= count
			break
		}
	}
}

// getReverseFlows Function
func getReverseFlows(dst Dst, originLogs []types.NetworkLog) []Dst {
	reverses := []Dst{}

	for _, log := range originLogs {
		port := 0
		if IsExposedPort(log.Protocol, log.DstPort) {
			port = log.DstPort
		}

		match := Dst{
			MicroserviceName:   log.DstMicroserviceName,
			ContainerGroupName: log.DstContainerGroupName,
			Protocol:           log.Protocol,
			DstPort:            port,
			Action:             log.Action,
		}

		if dst == match {
			reverse := Dst{
				MicroserviceName:   log.SrcMicroserviceName,
				ContainerGroupName: log.SrcContainerGroupName,
				Protocol:           log.Protocol,
				DstPort:            0, // src port may be 0
				Action:             log.Action,
			}

			reverses = append(reverses, reverse)
		}
	}

	return reverses
}

// removingReserveFlow Function
func removingReserveFlow(perDst map[Dst][]types.NetworkLog, originLogs []types.NetworkLog) {
	perDstLogsCount := map[Dst]int{}

	// count each dst flows and container group
	for dst, logs := range perDst {
		perDstLogsCount[dst] = len(logs)
	}

	var flowCounts []FlowCount
	for k, v := range perDstLogsCount {
		flowCounts = append(flowCounts, FlowCount{k, v})
	}

	// sorting flow count map by descending order
	sort.Slice(flowCounts, func(i, j int) bool {
		return flowCounts[i].Count > flowCounts[j].Count
	})

	// enumerating dst flows by descending order
	for _, flowCount := range flowCounts {
		if flowCount.Count <= 1 {
			// if flow count <= 1, skip
			continue
		}

		reverseflows := getReverseFlows(flowCount.Dst, originLogs)
		for _, reverse := range reverseflows {
			if _, ok := perDst[reverse]; ok {
				count := len(perDst[reverse])                       // get count of reverse flow
				delete(perDst, reverse)                             // delete reverse flow from perDstLogs
				subtractReverseDstCount(flowCounts, reverse, count) // count update
			}
		}
	}
}

// ========================================== //
// == Step 3: Grouping Src Based on Labels == //
// ========================================== //

// mergingSrcByLabels Function
func mergingSrcByLabels(perDstSrcLabel map[Dst][]SrcSimple) map[Dst][]string {
	perDstGroupedSrc := map[Dst][]string{}

	for dst, srcs := range perDstSrcLabel {
		// first, count each src label (a=b:1 a=b,c=d:2 e=f:1, ... )
		labelCountMap := map[string]int{}
		for _, src := range srcs {
			countLabelByCombinations(labelCountMap, src.MatchLabels)
		}

		// sorting label by descending order (e=f:10, f=e:9, d=s:5, ...)
		countsPerLabel := descendingLabelCountMap(labelCountMap)

		// enumerating src label by descending order
		for _, perLabel := range countsPerLabel {
			if perLabel.Count >= 2 {
				// merge if at least match count >= 2
				// it could be single (a=b) or combined (a=b,c=d)
				label := perLabel.Label

				// if 'src' contains the label, remove 'src' from srcs
				for _, src := range srcs {
					if containLabel(label, src.MatchLabels) {
						srcs = removeSrc(srcs, src)
					}
				}

				if perDstGroupedSrc[dst] == nil {
					perDstGroupedSrc[dst] = []string{}
				}

				// append the label (the removed src included) to the dst
				if !libs.ContainsElement(perDstGroupedSrc[dst], label) {
					perDstGroupedSrc[dst] = append(perDstGroupedSrc[dst], label)
				}
			}
		}

		// if there is remained src, add its match label
		for _, src := range srcs {
			perDstGroupedSrc[dst] = append(perDstGroupedSrc[dst], src.MatchLabels)
		}
	}

	return perDstGroupedSrc
}

// ====================================== //
// == Step 2: Replacing Src to Labeled == //
// ====================================== //

// getMergedLabels Function
func getMergedLabels(microName, groupName string, groups []types.ContainerGroup) string {
	mergedLabels := ""

	for _, group := range groups {
		// find the container group of src
		if microName == group.MicroserviceName && groupName == group.ContainerGroupName {
			// remove common name identities
			labels := []string{}

			for _, label := range group.Labels {
				if !libs.ContainsElement(skippedLabels, strings.Split(label, "=")[0]) {
					labels = append(labels, label)
				}
			}

			sort.Slice(labels, func(i, j int) bool {
				return labels[i] > labels[j]
			})

			mergedLabels = strings.Join(labels, ",")
			return mergedLabels
		}
	}

	return mergedLabels
}

// extractingSrcFromLogs Function
func extractingSrcFromLogs(perDst map[Dst][]types.NetworkLog, conGroups []types.ContainerGroup) map[Dst][]SrcSimple {
	perDstSrcLabel := map[Dst][]SrcSimple{}

	for dst, logs := range perDst {
		srcs := []SrcSimple{}

		for _, log := range logs {
			// get merged matchlables: "a=b,c=d,e=f"
			mergedLabels := getMergedLabels(log.SrcMicroserviceName, log.SrcContainerGroupName, conGroups)

			src := SrcSimple{
				MicroserviceName:   log.SrcMicroserviceName,
				ContainerGroupName: log.SrcContainerGroupName,
				MatchLabels:        mergedLabels}

			// remove redundant
			if !libs.ContainsElement(srcs, src) {
				srcs = append(srcs, src)
			}
		}

		perDstSrcLabel[dst] = srcs
	}

	return perDstSrcLabel
}

// =========================================== //
// == Step 4: Merging Dst's Protocol + Port == //
// =========================================== //

// mergingProtocolPorts Function
func mergingProtocolPorts(mergedDsts []MergedDst, dst Dst) []MergedDst {
	for i, dstPort := range mergedDsts {
		simple1 := DstSimple{MicroserviceName: dstPort.MicroserviceName,
			ContainerGroupName: dstPort.ContainerGroupName,
			Action:             dstPort.Action}

		simple2 := DstSimple{MicroserviceName: dst.MicroserviceName,
			ContainerGroupName: dst.ContainerGroupName,
			Action:             dst.Action}

		if simple1 == simple2 { // matched, append protocol+port info
			port := types.ToPort{Protocol: libs.GetProtocol(dst.Protocol),
				Ports: strconv.Itoa(dst.DstPort)}

			mergedDsts[i].ToPorts = append(mergedDsts[i].ToPorts, port)

			return mergedDsts
		}
	}

	// if not matched, create new one,
	port := types.ToPort{Protocol: libs.GetProtocol(dst.Protocol),
		Ports: strconv.Itoa(dst.DstPort)}

	mergedDst := MergedDst{
		MicroserviceName:   dst.MicroserviceName,
		ContainerGroupName: dst.ContainerGroupName,
		Action:             dst.Action,
		ToPorts:            []types.ToPort{port},
	}

	mergedDsts = append(mergedDsts, mergedDst)

	return mergedDsts
}

// mergingDstToPorts Function
func mergingDstToPorts(perDstGroupedSrc map[Dst][]string) map[string][]MergedDst {
	mergedSrcPerMergedDst := map[string][]MergedDst{}

	// conver perDst -> perSrc
	mergedSrcPerDst := map[string][]Dst{}
	for dst, mergedSrcs := range perDstGroupedSrc {
		for _, mergedSrc := range mergedSrcs {
			if mergedSrcPerDst[mergedSrc] == nil {
				mergedSrcPerDst[mergedSrc] = make([]Dst, 0)
			}

			if !libs.ContainsElement(mergedSrcPerDst[mergedSrc], dst) {
				mergedSrcPerDst[mergedSrc] = append(mergedSrcPerDst[mergedSrc], dst)
			}
		}
	}

	for mergedSrc, dsts := range mergedSrcPerDst {
		// first, convert dst -> dstSimple, and count each dstSimple
		dstSimpleCounts := map[DstSimple]int{}
		for _, dst := range dsts {
			dstSimple := DstSimple{MicroserviceName: dst.MicroserviceName,
				ContainerGroupName: dst.ContainerGroupName,
				Action:             dst.Action}

			if val, ok := dstSimpleCounts[dstSimple]; !ok {
				dstSimpleCounts[dstSimple] = 1
			} else {
				dstSimpleCounts[dstSimple] = val + 1
			}
		}

		// sort dstCount by descending order
		type dstCount struct {
			DstSimple DstSimple
			Count     int
		}

		var dstCounts []dstCount
		for dst, count := range dstSimpleCounts {
			dstCounts = append(dstCounts, dstCount{dst, count})
		}

		sort.Slice(dstCounts, func(i, j int) bool {
			return dstCounts[i].Count > dstCounts[j].Count
		})

		if mergedSrcPerMergedDst[mergedSrc] == nil {
			mergedSrcPerMergedDst[mergedSrc] = []MergedDst{}
		}

		// if dst is matched dstSimple, remove it from origin dst list
		for _, dstCount := range dstCounts {
			if dstCount.Count >= 2 { // at least match count >= 2
				for _, dst := range dsts {
					simple := DstSimple{MicroserviceName: dst.MicroserviceName,
						ContainerGroupName: dst.ContainerGroupName,
						Action:             dst.Action}

					if dstCount.DstSimple == simple {
						// merge protocol + port
						mergedSrcPerMergedDst[mergedSrc] = mergingProtocolPorts(mergedSrcPerMergedDst[mergedSrc], dst)
						// and then, remove dst
						dsts = removeDst(dsts, dst)
					}
				}
			}
		}

		mergedSrcPerDst[mergedSrc] = dsts
	}

	// if not merged dsts remains, append it by default
	for mergedSrc, dsts := range mergedSrcPerDst {
		for _, dst := range dsts {
			mergedSrcPerMergedDst[mergedSrc] = mergingProtocolPorts(mergedSrcPerMergedDst[mergedSrc], dst)
		}
	}

	return mergedSrcPerMergedDst
}

// ========================================= //
// == Step 5: Grouping Dst based on Label == //
// ========================================= //

// groupingDstMergeds Function
func groupingDstMergeds(label string, dsts []MergedDst) MergedDst {
	merged := MergedDst{MatchLabels: label}
	merged.ToPorts = []types.ToPort{}

	for _, dst := range dsts {
		merged.Action = dst.Action
		merged.MicroserviceName = dst.MicroserviceName

		for _, toport := range dst.ToPorts {
			if !libs.ContainsElement(merged.ToPorts, toport) {
				merged.ToPorts = append(merged.ToPorts, toport)
			}
		}
	}

	return merged
}

// mergingDstByLabels Function
func mergingDstByLabels(mergedSrcPerMergedProtoDst map[string][]MergedDst, conGroups []types.ContainerGroup) map[string][]MergedDst {
	perGroupedSrcGroupedDst := map[string][]MergedDst{}

	for mergedSrc, mergedProtoPort := range mergedSrcPerMergedProtoDst {
		// dst merged label count
		mergedProtoPort = updateDstLabels(mergedProtoPort, conGroups)
		labelCountMap := map[string]int{}

		// count each dst label
		for _, dst := range mergedProtoPort {
			countLabelByCombinations(labelCountMap, dst.MatchLabels)
		}

		// sort label count by descending orders
		labelCounts := sortingLableCount(labelCountMap)

		// remove matched label dsts
		for _, labelCount := range labelCounts {
			if labelCount.Count >= 2 {
				// at least match count >= 2
				label := labelCount.Label

				groupedDsts := make([]MergedDst, 0)
				for _, dst := range mergedProtoPort {
					if containLabel(label, dst.MatchLabels) {
						groupedDsts = append(groupedDsts, dst)
						mergedProtoPort = removeDstMerged(mergedProtoPort, dst)
					}
				}

				if perGroupedSrcGroupedDst[mergedSrc] == nil {
					perGroupedSrcGroupedDst[mergedSrc] = []MergedDst{}
				}

				// groupingDsts -> one merged grouping dst
				groupedDst := groupingDstMergeds(label, groupedDsts)
				perGroupedSrcGroupedDst[mergedSrc] = append(perGroupedSrcGroupedDst[mergedSrc], groupedDst)
			}
		}

		// not grouped dst remains, append it
		for _, mergedDst := range mergedProtoPort {
			if perGroupedSrcGroupedDst[mergedSrc] == nil {
				perGroupedSrcGroupedDst[mergedSrc] = []MergedDst{}
			}
			perGroupedSrcGroupedDst[mergedSrc] = append(perGroupedSrcGroupedDst[mergedSrc], mergedDst)
		}
	}

	return perGroupedSrcGroupedDst
}

// =============================== //
// == Network Policy Generation == //
// =============================== //

// GenerateNetworkPolicies Function
func GenerateNetworkPolicies(microserviceName string,
	cidrBits int, // for CIDR policy, 32 bits -> per IP
	networkLogs []types.NetworkLog,
	k8sServices []types.K8sService,
	containerGroups []types.ContainerGroup) []types.KnoxNetworkPolicy {
	networkLogs = filterLogs(networkLogs, microserviceName)

	// step 1: update exposed ports (k8s service, docker-compose portbinding)
	UpdateExposedPorts(k8sServices, containerGroups)

	// step 2: {dst: [network logs (src+dst)]}
	logsPerDst := groupingLogsPerDst(networkLogs, cidrBits)

	// step 3: {dst: [network logs (src+dst)]} -> {dst: [srcs]}
	labeledSrcPerDst := extractingSrcFromLogs(logsPerDst, containerGroups)

	// step 4: {dst: [srcs]} -> {dst: [merged srcs]}
	mergedSrcPerDst := mergingSrcByLabels(labeledSrcPerDst)

	// step 5: merging protocols and ports for the same destinations
	mergedSrcPerMergedProtoDst := mergingDstToPorts(mergedSrcPerDst)

	// step 6: grouping dst based on labels
	mergedSrcPerMergedDst := mergingDstByLabels(mergedSrcPerMergedProtoDst, containerGroups)

	// step 7: building network policies
	networkPolicies := BuildNetworkPolicies(microserviceName, mergedSrcPerMergedDst)

	return networkPolicies
}
