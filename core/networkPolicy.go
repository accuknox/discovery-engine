package core

import (
	"net"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	libs "github.com/accuknox/knoxAutoPolicy/libs"
	types "github.com/accuknox/knoxAutoPolicy/types"
)

var DefaultSelectorKey string = "container_group_name"

var skippedLabels = []string{"pod-template-hash"}

var exposedTCPPorts = []int{}
var exposedUDPPorts = []int{}
var exposedSCTPPorts = []int{}

var externals = []string{"reserved:world", "external"}

// protocol
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
	External           string
	ContainerGroupName string
	MatchLabels        string
	Protocol           int
	DstPort            int

	Action string
}

// DstSimple Structure
type DstSimple struct {
	MicroserviceName   string
	ContainerGroupName string
	Exteranl           string

	Action string
}

// MergedPortDst Structure
type MergedPortDst struct {
	MicroserviceName   string
	ContainerGroupName string
	External           string
	MatchLabels        string
	ToPorts            []types.SpecPort

	Action string
}

// LabelCount Structure
type LabelCount struct {
	Label string
	Count int
}

// ============ //
// == Common == //
// ============ //

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
func updateDstLabels(dsts []MergedPortDst, groups []types.ContainerGroup) []MergedPortDst {
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
func removeDstMerged(dsts []MergedPortDst, remove MergedPortDst) []MergedPortDst {
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
func UpdateExposedPorts(services []types.K8sService, endpoints []types.K8sEndpoint, contGroups []types.ContainerGroup) {
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

	// step 2: (k8s) endpoint port update
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

	// step 3: port binding update
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

func buildNewEgressPolicy() types.KnoxNetworkPolicy {
	policyName := "autogen-egress-" + libs.RandSeq(10)

	return types.KnoxNetworkPolicy{
		APIVersion: "v1",
		Kind:       "KnoxNetworkPolicy",
		Metadata: map[string]string{
			"name": policyName},
		Spec: types.Spec{
			Selector: types.Selector{
				MatchLabels: map[string]string{}},
			Egress: types.Egress{},
			Action: "allow",
		},
	}
}

func buildNewIngressPolicy(action string) types.KnoxNetworkPolicy {
	policyName := "autogen-ingress-" + libs.RandSeq(10)

	ingress := types.KnoxNetworkPolicy{
		APIVersion: "v1",
		Kind:       "KnoxNetworkPolicy",
		Metadata: map[string]string{
			"name": policyName},
		Spec: types.Spec{
			Selector: types.Selector{
				MatchLabels: map[string]string{}},
			Ingress: types.Ingress{},
			Action:  action,
		},
	}

	return ingress
}

func buildNewIngressPolicyFromEgress(egress types.KnoxNetworkPolicy) types.KnoxNetworkPolicy {
	policyName := "autogen-ingress-" + libs.RandSeq(10)

	ingress := types.KnoxNetworkPolicy{
		APIVersion: "v1",
		Kind:       "KnoxNetworkPolicy",
		Metadata: map[string]string{
			"name":      policyName,
			"namespace": egress.Spec.Egress.MatchLabels["k8s:io.kubernetes.pod.namespace"]},
		Spec: types.Spec{
			Selector: types.Selector{
				MatchLabels: map[string]string{}},
			Ingress: types.Ingress{
				MatchLabels: map[string]string{}},
			Action: egress.Spec.Action,
		},
	}

	// update selector labels from egress match labels
	for k, v := range egress.Spec.Egress.MatchLabels {
		if k != "k8s:io.kubernetes.pod.namespace" {
			ingress.Spec.Selector.MatchLabels[k] = v
		}
	}

	// update ingress labels from selector match labels
	for k, v := range egress.Spec.Selector.MatchLabels {
		ingress.Spec.Ingress.MatchLabels[k] = v
	}

	return ingress
}

// BuildNetworkPolicies Function
func BuildNetworkPolicies(microName string, services []types.K8sService, mergedSrcPerMergedDst map[string][]MergedPortDst) []types.KnoxNetworkPolicy {
	networkPolicies := []types.KnoxNetworkPolicy{}

	for mergedSrc, mergedDsts := range mergedSrcPerMergedDst {
		for _, dst := range mergedDsts {
			egressPolicy := buildNewEgressPolicy()
			egressPolicy.Metadata["namespace"] = microName

			// set selector matchLabels
			srcs := strings.Split(mergedSrc, ",")
			for _, src := range srcs {
				kv := strings.Split(src, "=")
				if len(kv) != 2 { // double check if it is k=v
					continue
				}

				srcKey := kv[0]
				srcVal := kv[1]

				egressPolicy.Spec.Selector.MatchLabels[srcKey] = srcVal
			}

			// set egress matchLabels
			if dst.MatchLabels != "" {
				egressPolicy.Spec.Egress.MatchLabels = map[string]string{}

				dsts := strings.Split(dst.MatchLabels, ",")
				for _, dest := range dsts {
					kv := strings.Split(dest, "=")
					if len(kv) != 2 {
						continue
					}

					dstkey := kv[0]
					dstval := kv[1]

					egressPolicy.Spec.Egress.MatchLabels[dstkey] = dstval
				}
				// although same namespace, speficy namespace
				egressPolicy.Spec.Egress.MatchLabels["k8s:io.kubernetes.pod.namespace"] = dst.MicroserviceName

				// if toPorts exist, add it
				if dst.ToPorts != nil && len(dst.ToPorts) > 0 {
					for i, toPort := range dst.ToPorts {
						if toPort.Ports == "0" {
							dst.ToPorts[i].Ports = ""
						}
					}
					egressPolicy.Spec.Egress.ToPorts = dst.ToPorts
				}
				networkPolicies = append(networkPolicies, egressPolicy)

				// add dependent ingress policy if not kube-system
				if dst.MicroserviceName != "kube-system" {
					ingressPolicy := buildNewIngressPolicyFromEgress(egressPolicy)
					ingressPolicy.Spec.Ingress.MatchLabels["k8s:io.kubernetes.pod.namespace"] = microName

					networkPolicies = append(networkPolicies, ingressPolicy)
				}
			} else if dst.MicroserviceName == "reserved:cidr" && dst.External != "" {
				// cidr policy
				cidr := types.SpecCIDR{
					CIDRs: strings.Split(dst.External, ","),
					Ports: dst.ToPorts,
				}

				egressPolicy.Spec.Egress.ToCIDRs = []types.SpecCIDR{cidr}
				networkPolicies = append(networkPolicies, egressPolicy)
			} else if dst.MicroserviceName == "reserved:dns" && dst.External != "" {
				// dns policy
				fqdn := types.SpecFQDN{
					Matchnames: strings.Split(dst.External, ","),
					ToPorts:    dst.ToPorts,
				}

				egressPolicy.Spec.Egress.ToFQDNs = []types.SpecFQDN{fqdn}
				networkPolicies = append(networkPolicies, egressPolicy)
			} else if dst.External != "" { // external services (not internal k8s service)
				// service policy
				service := types.SpecService{
					ServiceName: dst.External,
					Namespace:   dst.MicroserviceName,
				}

				egressPolicy.Spec.Egress.ToServices = []types.SpecService{service}
				networkPolicies = append(networkPolicies, egressPolicy)
			} else if strings.HasPrefix(dst.MicroserviceName, "reserved:") && dst.MatchLabels == "" {
				// entity policy (for Cilium only)
				if dst.MicroserviceName == "reserved:host" { // host is allowed by default in Cilium
					continue
				}

				// handle for entity policy in Cilium
				egressPolicy.Spec.Egress.ToEndtities = []string{strings.Split(dst.MicroserviceName, ":")[1]}
				networkPolicies = append(networkPolicies, egressPolicy)

				// add ingress policy as well (TODO: reserve...)
				ingress := buildNewIngressPolicy(dst.Action)
				ingress.Metadata["namespace"] = microName
				for k, v := range egressPolicy.Spec.Selector.MatchLabels {
					ingress.Spec.Selector.MatchLabels[k] = v
				}

				reserved := strings.Split(dst.MicroserviceName, ":")[1]
				if reserved == "remote-node" {
					ingress.Spec.Ingress.FromEntities = []string{"world"}
				} else {
					ingress.Spec.Ingress.FromEntities = []string{reserved}
				}

				networkPolicies = append(networkPolicies, ingress)
			}
		}
	}

	// update generated time
	genTime := time.Now().Unix()
	for i, _ := range networkPolicies {
		networkPolicies[i].GeneratedTime = genTime
	}

	return networkPolicies
}

// =========================================== //
// == Step 1: Grouping Network Logs Per Dst == //
// =========================================== //

// checkExternalService Function
func checkExternalService(log types.NetworkLog, endpoints []types.K8sEndpoint) (types.K8sEndpoint, bool) {
	for _, endpoint := range endpoints {
		for _, port := range endpoint.Endpoints {
			if (libs.GetProtocol(log.Protocol) == strings.ToLower(port.Protocol)) &&
				log.DstPort == port.Port &&
				log.DstIP == port.IP {
				return endpoint, true
			}
		}
	}

	return types.K8sEndpoint{}, false
}

// getSimpleDst Function
func getSimpleDst(log types.NetworkLog, endpoints []types.K8sEndpoint, cidrBits int) (Dst, bool) {
	dstPort := 0
	external := ""

	// check if dst is L7 dns query
	if log.DNSQuery != "" {
		dst := Dst{
			MicroserviceName:   "reserved:dns",
			ContainerGroupName: log.DstContainerGroupName,
			External:           log.DNSQuery,
			Protocol:           log.Protocol,
			DstPort:            log.DstPort,
			Action:             log.Action,
		}

		return dst, true
	}

	// check if dst is out of cluster
	if libs.ContainsElement(externals, log.DstMicroserviceName) && net.ParseIP(log.DstContainerGroupName) != nil {
		// check if it is the external service policy
		if endpoint, valid := checkExternalService(log, endpoints); valid {
			log.DstMicroserviceName = endpoint.MicroserviceName
			external = endpoint.EndpointName
		} else { // else, handle it as cidr policy
			log.DstMicroserviceName = "reserved:cidr"
			ipNetwork := log.DstContainerGroupName + "/" + strconv.Itoa(cidrBits)
			_, network, _ := net.ParseCIDR(ipNetwork)
			external = network.String()
		}

		dst := Dst{
			MicroserviceName:   log.DstMicroserviceName,
			ContainerGroupName: log.DstContainerGroupName,
			External:           external,
			Protocol:           log.Protocol,
			DstPort:            log.DstPort,
			Action:             log.Action,
		}

		return dst, true
	}

	// handle pod -> pod or pod -> entity as below
	// check dst port number is exposed or not (tcp, udp, or sctp)
	if IsExposedPort(log.Protocol, log.DstPort) {
		dstPort = log.DstPort
	}

	// if dst port is unexposed and not reserved, it's invalid
	if dstPort == 0 && !strings.HasPrefix(log.DstMicroserviceName, "reserved:") {
		return Dst{}, false
	}

	dst := Dst{
		MicroserviceName:   log.DstMicroserviceName,
		ContainerGroupName: log.DstContainerGroupName,
		Protocol:           log.Protocol,
		DstPort:            dstPort,
		Action:             log.Action,
	}

	return dst, true
}

// groupingLogsPerDst Function
func groupingLogsPerDst(networkLogs []types.NetworkLog, endpoints []types.K8sEndpoint, cidrBits int) map[Dst][]types.NetworkLog {
	perDst := map[Dst][]types.NetworkLog{}

	for _, log := range networkLogs {
		dst, valid := getSimpleDst(log, endpoints, cidrBits)
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

	return ""
}

// extractingSrcFromLogs Function
func extractingSrcFromLogs(perDst map[Dst][]types.NetworkLog, conGroups []types.ContainerGroup) map[Dst][]SrcSimple {
	perDstSrcLabel := map[Dst][]SrcSimple{}

	for dst, logs := range perDst {
		srcs := []SrcSimple{}

		for _, log := range logs {
			// get merged matchlables: "a=b,c=d,e=f"
			mergedLabels := getMergedLabels(log.SrcMicroserviceName, log.SrcContainerGroupName, conGroups)
			if mergedLabels == "" {
				continue
			}

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
func mergingProtocolPorts(mergedDsts []MergedPortDst, dst Dst) []MergedPortDst {
	for i, dstPort := range mergedDsts {
		simple1 := DstSimple{MicroserviceName: dstPort.MicroserviceName,
			ContainerGroupName: dstPort.ContainerGroupName,
			Exteranl:           dstPort.External,
			Action:             dstPort.Action}

		simple2 := DstSimple{MicroserviceName: dst.MicroserviceName,
			ContainerGroupName: dst.ContainerGroupName,
			Exteranl:           dst.External,
			Action:             dst.Action}

		if simple1 == simple2 { // matched, append protocol+port info
			port := types.SpecPort{Protocol: libs.GetProtocol(dst.Protocol),
				Ports: strconv.Itoa(dst.DstPort)}

			mergedDsts[i].ToPorts = append(mergedDsts[i].ToPorts, port)

			return mergedDsts
		}
	}

	// if not matched, create new one,
	port := types.SpecPort{Protocol: libs.GetProtocol(dst.Protocol),
		Ports: strconv.Itoa(dst.DstPort)}

	mergedDst := MergedPortDst{
		MicroserviceName:   dst.MicroserviceName,
		ContainerGroupName: dst.ContainerGroupName,
		External:           dst.External,
		Action:             dst.Action,
		ToPorts:            []types.SpecPort{port},
	}

	mergedDsts = append(mergedDsts, mergedDst)

	return mergedDsts
}

// mergingDstSpecs Function
func mergingDstSpecs(mergedSrcsPerDst map[Dst][]string) map[string][]MergedPortDst {
	mergedSrcPerMergedDst := map[string][]MergedPortDst{}

	// convert {dst: [srcs]} -> {src: [dsts]}
	dstsPerMergedSrc := map[string][]Dst{}
	for dst, mergedSrcs := range mergedSrcsPerDst {
		for _, mergedSrc := range mergedSrcs {
			if dstsPerMergedSrc[mergedSrc] == nil {
				dstsPerMergedSrc[mergedSrc] = make([]Dst, 0)
			}

			if !libs.ContainsElement(dstsPerMergedSrc[mergedSrc], dst) {
				dstsPerMergedSrc[mergedSrc] = append(dstsPerMergedSrc[mergedSrc], dst)
			}
		}
	}

	for mergedSrc, dsts := range dstsPerMergedSrc {
		// convert dst -> dstSimple, and count each dstSimple
		dstSimpleCounts := map[DstSimple]int{}

		for _, dst := range dsts {
			dstSimple := DstSimple{MicroserviceName: dst.MicroserviceName,
				ContainerGroupName: dst.ContainerGroupName,
				Exteranl:           dst.External,
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
			mergedSrcPerMergedDst[mergedSrc] = []MergedPortDst{}
		}

		// if dst is matched dstSimple, remove it from origin dst list
		for _, dstCount := range dstCounts {
			if dstCount.Count >= 2 { // at least match count >= 2
				for _, dst := range dsts {
					simple := DstSimple{MicroserviceName: dst.MicroserviceName,
						ContainerGroupName: dst.ContainerGroupName,
						Exteranl:           dst.External,
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

		dstsPerMergedSrc[mergedSrc] = dsts
	}

	// if not merged dsts remains, append it by default
	for mergedSrc, dsts := range dstsPerMergedSrc {
		for _, dst := range dsts {
			mergedSrcPerMergedDst[mergedSrc] = mergingProtocolPorts(mergedSrcPerMergedDst[mergedSrc], dst)
		}
	}

	// merge dns
	for mergedSrc, dsts := range mergedSrcPerMergedDst {
		newDsts := []MergedPortDst{}
		mergedDns := []string{}
		mergedDnsToPorts := []types.SpecPort{}

		for _, dst := range dsts {
			if dst.MicroserviceName == "reserved:dns" {
				mergedDns = append(mergedDns, dst.External)
				for _, port := range dst.ToPorts {
					if !libs.ContainsElement(mergedDnsToPorts, port) {
						mergedDnsToPorts = append(mergedDnsToPorts, port)
					}
				}
			} else {
				newDsts = append(newDsts, dst)
			}
		}

		if len(mergedDns) > 0 {
			newDns := MergedPortDst{
				MicroserviceName: "reserved:dns",
				External:         strings.Join(mergedDns, ","),
				ToPorts:          mergedDnsToPorts,
				Action:           "allow",
			}
			newDsts = append(newDsts, newDns)
		}

		mergedSrcPerMergedDst[mergedSrc] = newDsts
	}

	// merge cidr
	for mergedSrc, dsts := range mergedSrcPerMergedDst {
		newDsts := []MergedPortDst{}
		mergedCidrs := []string{}
		mergedCidrToPorts := []types.SpecPort{}

		for _, dst := range dsts {
			if dst.MicroserviceName == "reserved:cidr" {
				mergedCidrs = append(mergedCidrs, dst.External)
				for _, port := range dst.ToPorts {
					if !libs.ContainsElement(mergedCidrToPorts, port) {
						mergedCidrToPorts = append(mergedCidrToPorts, port)
					}
				}
			} else {
				newDsts = append(newDsts, dst)
			}
		}

		if len(mergedCidrs) > 0 {
			newDns := MergedPortDst{
				MicroserviceName: "reserved:cidr",
				External:         strings.Join(mergedCidrs, ","),
				ToPorts:          mergedCidrToPorts,
				Action:           "allow",
			}
			newDsts = append(newDsts, newDns)
		}

		mergedSrcPerMergedDst[mergedSrc] = newDsts
	}

	return mergedSrcPerMergedDst
}

// ========================================= //
// == Step 5: Grouping Dst based on Label == //
// ========================================= //

// groupingDstMergeds Function
func groupingDstMergeds(label string, dsts []MergedPortDst) MergedPortDst {
	merged := MergedPortDst{MatchLabels: label}
	merged.ToPorts = []types.SpecPort{}

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
func mergingDstByLabels(mergedSrcPerMergedProtoDst map[string][]MergedPortDst, conGroups []types.ContainerGroup) map[string][]MergedPortDst {
	perGroupedSrcGroupedDst := map[string][]MergedPortDst{}

	for mergedSrc, mergedProtoPortDsts := range mergedSrcPerMergedProtoDst {
		// label update
		mergedProtoPortDsts = updateDstLabels(mergedProtoPortDsts, conGroups)

		// count each dst label
		labelCountMap := map[string]int{}
		for _, dst := range mergedProtoPortDsts {
			if dst.MatchLabels == "" {
				continue
			}

			countLabelByCombinations(labelCountMap, dst.MatchLabels)
		}

		// sort label count by descending orders
		labelCounts := sortingLableCount(labelCountMap)

		// fetch matched label dsts
		for _, labelCount := range labelCounts {
			if labelCount.Count >= 2 {
				// at least match count >= 2
				label := labelCount.Label

				groupedDsts := make([]MergedPortDst, 0)
				for _, dst := range mergedProtoPortDsts {
					if containLabel(label, dst.MatchLabels) {
						groupedDsts = append(groupedDsts, dst)
						mergedProtoPortDsts = removeDstMerged(mergedProtoPortDsts, dst)
					}
				}

				if perGroupedSrcGroupedDst[mergedSrc] == nil {
					perGroupedSrcGroupedDst[mergedSrc] = []MergedPortDst{}
				}

				// groupingDsts -> one merged grouping dst
				groupedDst := groupingDstMergeds(label, groupedDsts)
				perGroupedSrcGroupedDst[mergedSrc] = append(perGroupedSrcGroupedDst[mergedSrc], groupedDst)
			}
		}

		// not grouped dst remains, append it
		for _, mergedDst := range mergedProtoPortDsts {
			if perGroupedSrcGroupedDst[mergedSrc] == nil {
				perGroupedSrcGroupedDst[mergedSrc] = []MergedPortDst{}
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
	cidrBits int, // for CIDR policy (32 bits -> per IP)
	networkLogs []types.NetworkLog,
	k8sServices []types.K8sService,
	k8sEndpoints []types.K8sEndpoint,
	containerGroups []types.ContainerGroup) []types.KnoxNetworkPolicy {

	// step 1: update exposed ports (k8s service, docker-compose portbinding)
	UpdateExposedPorts(k8sServices, k8sEndpoints, containerGroups)

	// step 2: [network logs] -> {dst: [network logs (src+dst)]}
	logsPerDst := groupingLogsPerDst(networkLogs, k8sEndpoints, cidrBits)

	// step 3: {dst: [network logs (src+dst)]} -> {dst: [srcs (labeled)]}
	labeledSrcsPerDst := extractingSrcFromLogs(logsPerDst, containerGroups)

	// step 4: {dst: [srcs (labeled)]} -> {dst: [merged srcs (labeled + merged)]}
	mergedSrcsPerDst := mergingSrcByLabels(labeledSrcsPerDst)

	// step 5: {merged_src: [dsts (merged proto/port)]} merging protocols and ports for the same destinations
	mergedSrcPerMergedProtoDst := mergingDstSpecs(mergedSrcsPerDst)

	// step 6: {merged_src: [dsts (merged proto/port + labeld)] grouping dst based on labels
	mergedSrcPerMergedDst := mergingDstByLabels(mergedSrcPerMergedProtoDst, containerGroups)

	// step 7: building network policies
	networkPolicies := BuildNetworkPolicies(microserviceName, k8sServices, mergedSrcPerMergedDst)

	return networkPolicies
}
