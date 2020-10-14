package core

import (
	"reflect"
	"sort"
	"strconv"
	"strings"

	bl "github.com/seungsoo-lee/knoxAutoPolicy/libs"
	types "github.com/seungsoo-lee/knoxAutoPolicy/types"
)

var skipLabels = []string{"host_name", "microservice_name", "container_group_name", "container_name", "image_name"}

var exposedTCPPorts = []int{}
var exposedUDPPorts = []int{}
var exposedSCTPPorts = []int{}

// Src Structure
type Src struct {
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

// DstMerged Structure
type DstMerged struct {
	MicroserviceName   string
	ContainerGroupName string
	MatchLabels        string
	ToPorts            []types.ToPort
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
		// filter egress
		if log.Direction != "egress" {
			continue
		}

		// filter microservice name
		if log.SrcMicroserviceName != microName || log.DstMicroserviceName != microName {
			continue
		}

		// filter cni network logs
		if bl.ContainsElement([]string{"WeaveNet", "Flannel", "Calico"}, log.SrcContainerGroupName) {
			continue
		}

		if bl.ContainsElement([]string{"WeaveNet", "Flannel", "Calico"}, log.DstContainerGroupName) {
			continue
		}

		filteredLogs = append(filteredLogs, log)
	}

	return filteredLogs
}

// countLabel Function
func countLabel(labelCount map[string]int, mergedLabels string) {
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
		results := bl.Combinations(labels, i)
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
			results := bl.Combinations(targetLabels, i)
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
func removeSrc(srcs []Src, remove Src) []Src {
	cp := make([]Src, len(srcs))
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
func updateDstLabels(dsts []DstMerged, groups []types.ContainerGroup) []DstMerged {
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
func removeDstMerged(dsts []DstMerged, remove DstMerged) []DstMerged {
	cp := make([]DstMerged, len(dsts))
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
		if bl.ContainsElement(exposedTCPPorts, port) {
			return true
		}
	} else if protocol == 17 { // udp
		if bl.ContainsElement(exposedUDPPorts, port) {
			return true
		}
	} else if protocol == 132 { // sctp
		if bl.ContainsElement(exposedSCTPPorts, port) {
			return true
		}
	}

	return false
}

// UpdateExposedPorts Function
func UpdateExposedPorts(services []types.K8sService, contGroups []types.ContainerGroup) {
	// step 1: (k8s) service port update
	for _, service := range services {
		if service.Protocol == "tcp" { // TCP
			if !bl.ContainsElement(exposedTCPPorts, service.ServicePort) {
				exposedTCPPorts = append(exposedTCPPorts, service.ServicePort)
			}
		} else if service.Protocol == "udp" { // UDP
			if !bl.ContainsElement(exposedUDPPorts, service.ServicePort) {
				exposedUDPPorts = append(exposedUDPPorts, service.ServicePort)
			}
		} else if service.Protocol == "sctp" { // SCTP
			if !bl.ContainsElement(exposedSCTPPorts, service.ServicePort) {
				exposedSCTPPorts = append(exposedSCTPPorts, service.ServicePort)
			}
		}
	}

	// step 2: port binding update
	for _, conGroup := range contGroups {
		for _, portBinding := range conGroup.PortBindings {
			if portBinding.Protocol == "tcp" {
				if !bl.ContainsElement(exposedTCPPorts, portBinding.Port) {
					exposedTCPPorts = append(exposedTCPPorts, portBinding.Port)
				}
			} else if portBinding.Protocol == "udp" {
				if !bl.ContainsElement(exposedUDPPorts, portBinding.Port) {
					exposedUDPPorts = append(exposedUDPPorts, portBinding.Port)
				}
			} else if portBinding.Protocol == "sctp" {
				if !bl.ContainsElement(exposedSCTPPorts, portBinding.Port) {
					exposedSCTPPorts = append(exposedSCTPPorts, portBinding.Port)
				}
			}
		}
	}
}

// ============================ //
// == Build Network Policies == //
// ============================ //

// BuildNetworkPolicies Function
func BuildNetworkPolicies(microName string, perGroupedSrcGroupedDst map[string][]DstMerged) []types.NetworkPolicy {
	networkPolicies := []types.NetworkPolicy{}

	for groupedSrc, dsts := range perGroupedSrcGroupedDst {
		for _, dst := range dsts {
			policyName := "generated_" + bl.RandSeq(10)

			policy := types.NetworkPolicy{
				APIVersion: "v1",
				Kind:       "BastionNetworkPolicy",
				Metadata:   map[string]string{"name": policyName, "microservice_name": microName},
				Priority:   32768,
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
					SSCFunctions: []types.SSCFunction{},
					Action:       dst.Action,
				},
				UpdatedTime: bl.GetDateTimeZero(),
			}

			srcs := strings.Split(groupedSrc, ",")
			for _, src := range srcs {
				srcKey := strings.Split(src, "=")[0]
				srcVal := strings.Split(src, "=")[1]

				policy.Spec.Selector.MatchLabels[srcKey] = srcVal
			}

			if dst.MatchLabels != "" {
				dstkey := strings.Split(dst.MatchLabels, "=")[0]
				dstval := strings.Split(dst.MatchLabels, "=")[1]
				policy.Spec.Egress.MatchLabels[dstkey] = dstval
			} else {
				// by default
				policy.Spec.Egress.MatchNames["container_group_name"] = dst.ContainerGroupName
			}

			if dst.ToPorts != nil && len(dst.ToPorts) > 0 {
				for i, toPort := range dst.ToPorts {
					if toPort.Ports == "0" {
						dst.ToPorts[i].Ports = ""
					}
				}
				policy.Spec.Egress.ToPorts = dst.ToPorts
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
func getSimpleDst(log types.NetworkLog) Dst {
	port := 0

	if IsExposedPort(log.Protocol, log.DstPort) {
		port = log.DstPort
	}

	dst := Dst{
		MicroserviceName:   log.DstMicroserviceName,
		ContainerGroupName: log.DstContainerGroupName,
		Protocol:           log.Protocol,
		DstPort:            port,
		Action:             log.Action,
	}

	return dst
}

// groupingNetLogsPerDst Function
func groupingNetLogsPerDst(networkLogs []types.NetworkLog) map[Dst][]types.NetworkLog {
	perDst := map[Dst][]types.NetworkLog{}

	for _, log := range networkLogs {
		dst := getSimpleDst(log)

		if _, ok := perDst[dst]; !ok {
			perDst[dst] = []types.NetworkLog{log}
		} else {
			perDst[dst] = append(perDst[dst], log)
		}
	}

	return perDst
}

// ==================================== //
// == Step 2: Removing Reverse Flows == //
// ==================================== //

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
	for dst, count := range perDst {
		perDstLogsCount[dst] = len(count)
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

// getMergedLabels Function
func getMergedLabels(microName, groupName string, groups []types.ContainerGroup) string {
	matchLabels := ""

	for _, group := range groups {
		// find the container group of src
		if microName == group.MicroserviceName && groupName == group.ContainerGroupName {
			// remove common name identities
			identities := []string{}

			for _, label := range group.Labels {
				identities = append(identities, label)
			}

			sort.Slice(identities, func(i, j int) bool {
				return identities[i] > identities[j]
			})

			matchLabels = strings.Join(identities, ",")
			return matchLabels
		}
	}

	return matchLabels
}

// replacingLogsToSrc Function
func replacingLogsToSrc(perDst map[Dst][]types.NetworkLog, conGroups []types.ContainerGroup) map[Dst][]Src {
	perDstSrcLabel := map[Dst][]Src{}

	for dst, logs := range perDst {
		srcs := []Src{}

		for _, log := range logs {
			// get merged matchlables (,)
			mergedLabels := getMergedLabels(log.SrcMicroserviceName, log.SrcContainerGroupName, conGroups)

			src := Src{
				MicroserviceName:   log.SrcMicroserviceName,
				ContainerGroupName: log.SrcContainerGroupName,
				MatchLabels:        mergedLabels}

			if !bl.ContainsElement(srcs, src) {
				srcs = append(srcs, src)
			}
		}

		perDstSrcLabel[dst] = srcs
	}

	return perDstSrcLabel
}

// groupingSrc Function
func groupingSrc(perDstSrcLabel map[Dst][]Src) map[Dst][]string {
	perDstGroupedSrc := map[Dst][]string{}

	for dst, srcs := range perDstSrcLabel {
		// count each src label first
		labelCountMap := map[string]int{}
		for _, src := range srcs {
			countLabel(labelCountMap, src.MatchLabels)
		}

		// sorting label by descending order
		labelCounts := descendingLabelCountMap(labelCountMap)

		// enumerating src label by descending order
		for _, labelCount := range labelCounts {
			if labelCount.Count >= 2 { // at least match count >= 2
				// it could be single or combined
				label := labelCount.Label

				// if src contains the label, remove src from srcs
				for _, src := range srcs {
					if containLabel(label, src.MatchLabels) {
						srcs = removeSrc(srcs, src)
					}
				}

				if perDstGroupedSrc[dst] == nil {
					perDstGroupedSrc[dst] = []string{}
				}

				// append the label to the dst
				if !bl.ContainsElement(perDstGroupedSrc[dst], label) {
					perDstGroupedSrc[dst] = append(perDstGroupedSrc[dst], label)
				}
			}
		}

		// it src who not contains the label, append group name by default
		for _, src := range srcs {
			if !bl.ContainsElement(perDstGroupedSrc[dst], "container_group_name="+src.ContainerGroupName) {
				perDstGroupedSrc[dst] = append(perDstGroupedSrc[dst], "container_group_name="+src.ContainerGroupName)
			}
		}
	}

	return perDstGroupedSrc
}

// ========================================= //
// == Step 4: Merging Dst Protocol + Port == //
// ========================================= //

// mergingDstProtocolPorts Function
func mergingDstProtocolPorts(dstMergeds []DstMerged, dst Dst) []DstMerged {
	for i, dstPort := range dstMergeds {
		simple1 := DstSimple{MicroserviceName: dstPort.MicroserviceName,
			ContainerGroupName: dstPort.ContainerGroupName,
			Action:             dstPort.Action}

		simple2 := DstSimple{MicroserviceName: dst.MicroserviceName,
			ContainerGroupName: dst.ContainerGroupName,
			Action:             dst.Action}

		if simple1 == simple2 { // matched, append protocol+port info
			port := types.ToPort{Protocol: bl.GetProtocol(dst.Protocol),
				Ports: strconv.Itoa(dst.DstPort)}

			dstMergeds[i].ToPorts = append(dstMergeds[i].ToPorts, port)

			return dstMergeds
		}
	}

	// if not matched, create new one,
	port := types.ToPort{Protocol: bl.GetProtocol(dst.Protocol),
		Ports: strconv.Itoa(dst.DstPort)}

	dstMerged := DstMerged{
		MicroserviceName:   dst.MicroserviceName,
		ContainerGroupName: dst.ContainerGroupName,
		Action:             dst.Action,
		ToPorts:            []types.ToPort{port},
	}

	dstMergeds = append(dstMergeds, dstMerged)

	return dstMergeds
}

// mergingDst Function
func mergingDst(perDstGroupedSrc map[Dst][]string) map[string][]DstMerged {
	// conver perDst -> perSrc
	perGroupedSrcDst := map[string][]Dst{}
	for dst, groupedSrcs := range perDstGroupedSrc {
		for _, groupedSrc := range groupedSrcs {
			if perGroupedSrcDst[groupedSrc] == nil {
				perGroupedSrcDst[groupedSrc] = make([]Dst, 0)
			}

			if !bl.ContainsElement(perGroupedSrcDst[groupedSrc], dst) {
				perGroupedSrcDst[groupedSrc] = append(perGroupedSrcDst[groupedSrc], dst)
			}
		}
	}

	perGroupedSrcGroupedDst := map[string][]DstMerged{}
	for groupedSrc, dsts := range perGroupedSrcDst {
		// dst -> dst simple and count each dst simple
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

		if perGroupedSrcGroupedDst[groupedSrc] == nil {
			perGroupedSrcGroupedDst[groupedSrc] = []DstMerged{}
		}

		// if dst is matched dst simple, remove it from origin dst
		for _, dstCount := range dstCounts {
			if dstCount.Count >= 2 { // at least match count >= 2
				for _, dst := range dsts {
					simple := DstSimple{MicroserviceName: dst.MicroserviceName,
						ContainerGroupName: dst.ContainerGroupName,
						Action:             dst.Action}

					if dstCount.DstSimple == simple {
						// merge protocol + port
						perGroupedSrcGroupedDst[groupedSrc] = mergingDstProtocolPorts(perGroupedSrcGroupedDst[groupedSrc], dst)
						// remove dst
						dsts = removeDst(dsts, dst)
					}
				}
			}
		}

		perGroupedSrcDst[groupedSrc] = dsts
	}

	// if not merged dsts remains, append it by default
	for groupedSrc, dsts := range perGroupedSrcDst {
		for _, dst := range dsts {
			perGroupedSrcGroupedDst[groupedSrc] = mergingDstProtocolPorts(perGroupedSrcGroupedDst[groupedSrc], dst)
		}
	}

	return perGroupedSrcGroupedDst
}

// ========================================= //
// == Step 5: Grouping Dst based on Label == //
// ========================================= //

// groupingDstMergeds Function
func groupingDstMergeds(label string, dsts []DstMerged) DstMerged {
	merged := DstMerged{MatchLabels: label}
	merged.ToPorts = []types.ToPort{}

	for _, dst := range dsts {
		merged.Action = dst.Action
		merged.MicroserviceName = dst.MicroserviceName

		for _, toport := range dst.ToPorts {
			if !bl.ContainsElement(merged.ToPorts, toport) {
				merged.ToPorts = append(merged.ToPorts, toport)
			}
		}
	}

	return merged
}

// groupingDst Function
func groupingDst(perGroupedSrcMergedDst map[string][]DstMerged, conGroups []types.ContainerGroup) map[string][]DstMerged {
	perGroupedSrcGroupedDst := map[string][]DstMerged{}

	for groupedSrc, dstMergeds := range perGroupedSrcMergedDst {
		// dst merged label count
		dstMergeds = updateDstLabels(dstMergeds, conGroups)
		labelCountMap := map[string]int{}

		// count each dst label
		for _, dst := range dstMergeds {
			countLabel(labelCountMap, dst.MatchLabels)
		}

		// sort label count by descending orders
		labelCounts := sortingLableCount(labelCountMap)

		// remove matched label dsts
		for _, labelCount := range labelCounts {
			if labelCount.Count >= 2 { // at least match count >= 2
				label := labelCount.Label

				groupedDsts := make([]DstMerged, 0)
				for _, dst := range dstMergeds {
					if containLabel(label, dst.MatchLabels) {
						groupedDsts = append(groupedDsts, dst)
						dstMergeds = removeDstMerged(dstMergeds, dst)
					}
				}

				if perGroupedSrcGroupedDst[groupedSrc] == nil {
					perGroupedSrcGroupedDst[groupedSrc] = []DstMerged{}
				}

				// groupingDsts -> one merged grouping dst
				groupedDst := groupingDstMergeds(label, groupedDsts)
				perGroupedSrcGroupedDst[groupedSrc] = append(perGroupedSrcGroupedDst[groupedSrc], groupedDst)
			}
		}

		// not grouped dst remains
		for _, dst := range dstMergeds {
			dst.MatchLabels = "" // clear match labels
			perGroupedSrcGroupedDst[groupedSrc] = append(perGroupedSrcGroupedDst[groupedSrc], dst)
		}
	}

	return perGroupedSrcGroupedDst
}

// =============================== //
// == Network Policy Generation == //
// =============================== //

// GenerateNetworkPolicies Function
func GenerateNetworkPolicies(microserviceName string,
	networkLogs []types.NetworkLog,
	k8sServices []types.K8sService,
	containerGroups []types.ContainerGroup) []types.NetworkPolicy {
	networkLogs = filterLogs(networkLogs, microserviceName)

	// step 0: update exposed ports (k8s service, docker-compose portbinding)
	UpdateExposedPorts(k8sServices, containerGroups)

	// step 1: {dst: [network logs (src+dst)]}
	perDst := groupingNetLogsPerDst(networkLogs)

	// step 2: removing reverse flows from perDst
	removingReserveFlow(perDst, networkLogs)

	// step 3-1: {dst: [network logs (src+dst)]} -> {dst: [srcs]}
	perDstSrcLabel := replacingLogsToSrc(perDst, containerGroups)

	// step 3-2: {dst: srcs} -> {dst: [grouped src labels]}
	perDstGroupedSrc := groupingSrc(perDstSrcLabel)

	// step 4: merging protocols and ports for the same destinations
	perGroupedSrcMergedDst := mergingDst(perDstGroupedSrc)

	// step 5: grouping dst based on labels
	perGroupedSrcGroupedDst := groupingDst(perGroupedSrcMergedDst, containerGroups)

	// finalize network policies
	policies := BuildNetworkPolicies(microserviceName, perGroupedSrcGroupedDst)

	return policies
}
