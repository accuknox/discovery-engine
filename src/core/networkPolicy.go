package core

import (
	"net"
	"net/http"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	libs "github.com/accuknox/knoxAutoPolicy/src/libs"
	plugin "github.com/accuknox/knoxAutoPolicy/src/plugin"
	types "github.com/accuknox/knoxAutoPolicy/src/types"

	"github.com/robfig/cron"
	"github.com/rs/zerolog/log"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

var httpMethods = []string{
	http.MethodGet,
	http.MethodHead,
	http.MethodPost,
	http.MethodPut,
	http.MethodPatch,
	http.MethodDelete,
	http.MethodConnect,
	http.MethodOptions,
	http.MethodTrace,
}

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
	ContainerGroupName string
	Additional         string
	MatchLabels        string
	Protocol           int
	DstPort            int

	Action string
}

// DstSimple Structure
type DstSimple struct {
	MicroserviceName   string
	ContainerGroupName string
	Additional         string

	Action string
}

// MergedPortDst Structure
type MergedPortDst struct {
	MicroserviceName   string
	ContainerGroupName string
	Additional         string
	MatchLabels        string
	ToPorts            []types.SpecPort

	Action string
}

// LabelCount Structure
type LabelCount struct {
	Label string
	Count float64
}

// ============ //
// == Common == //
// ============ //

// checkHTTP Function
func checkHTTP(additionalInfo string) bool {
	isHTTP := false
	for _, m := range httpMethods {
		if strings.Contains(additionalInfo, m) {
			isHTTP = true
		}
	}

	return isHTTP
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

// updateExposedPorts Function
func updateExposedPorts(services []types.K8sService, endpoints []types.K8sEndpoint, contGroups []types.ContainerGroup) {
	// step 1: (k8s) service port update
	for _, service := range services {
		if strings.ToLower(service.Protocol) == "tcp" { // TCP
			if !libs.ContainsElement(exposedTCPPorts, service.ServicePort) {
				exposedTCPPorts = append(exposedTCPPorts, service.ServicePort)
			}
			if !libs.ContainsElement(exposedTCPPorts, service.NodePort) {
				exposedTCPPorts = append(exposedTCPPorts, service.NodePort)
			}
			if !libs.ContainsElement(exposedTCPPorts, service.ContainerPort) {
				exposedTCPPorts = append(exposedTCPPorts, service.ContainerPort)
			}
		} else if strings.ToLower(service.Protocol) == "udp" { // UDP
			if !libs.ContainsElement(exposedUDPPorts, service.ServicePort) {
				exposedUDPPorts = append(exposedUDPPorts, service.ServicePort)
			}
			if !libs.ContainsElement(exposedUDPPorts, service.NodePort) {
				exposedUDPPorts = append(exposedUDPPorts, service.NodePort)
			}
			if !libs.ContainsElement(exposedUDPPorts, service.ContainerPort) {
				exposedUDPPorts = append(exposedUDPPorts, service.ContainerPort)
			}
		} else if strings.ToLower(service.Protocol) == "sctp" { // SCTP
			if !libs.ContainsElement(exposedSCTPPorts, service.ServicePort) {
				exposedSCTPPorts = append(exposedSCTPPorts, service.ServicePort)
			}
			if !libs.ContainsElement(exposedSCTPPorts, service.NodePort) {
				exposedSCTPPorts = append(exposedSCTPPorts, service.NodePort)
			}
			if !libs.ContainsElement(exposedSCTPPorts, service.ContainerPort) {
				exposedSCTPPorts = append(exposedSCTPPorts, service.ContainerPort)
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

// buildNewKnoxPolicy Function
func buildNewKnoxPolicy() types.KnoxNetworkPolicy {
	return types.KnoxNetworkPolicy{
		APIVersion: "v1",
		Kind:       "KnoxNetworkPolicy",
		Metadata:   map[string]string{},
		Spec: types.Spec{
			Selector: types.Selector{
				MatchLabels: map[string]string{}},
			Action: "allow",
		},
	}
}

// buildNewKnoxEgressPolicy Function
func buildNewKnoxEgressPolicy() types.KnoxNetworkPolicy {
	policy := buildNewKnoxPolicy()
	policy.Metadata["name"] = "egress"
	policy.Spec.Egress = []types.Egress{}

	return policy
}

// buildNewKnoxIngressPolicy Function
func buildNewKnoxIngressPolicy() types.KnoxNetworkPolicy {
	policy := buildNewKnoxPolicy()
	policy.Metadata["name"] = "ingress"
	policy.Spec.Ingress = []types.Ingress{}

	return policy
}

// buildNewIngressPolicyFromEgress Function
func buildNewIngressPolicyFromEgress(egress types.Egress, selector types.Selector) types.KnoxNetworkPolicy {
	ingress := buildNewKnoxIngressPolicy()

	// update selector labels from egress match labels
	for k, v := range egress.MatchLabels {
		if k != "k8s:io.kubernetes.pod.namespace" {
			ingress.Spec.Selector.MatchLabels[k] = v
		} else {
			ingress.Metadata["namespace"] = v
		}
	}

	// update ingress labels from selector match labels
	ingress.Spec.Ingress = append(ingress.Spec.Ingress, types.Ingress{MatchLabels: map[string]string{}})
	for k, v := range selector.MatchLabels {
		ingress.Spec.Ingress[0].MatchLabels[k] = v
	}

	return ingress
}

// removeSelectorFromPolicies Function
func removeSelectorFromPolicies(policies []types.KnoxNetworkPolicy, inSelector types.Selector) []types.KnoxNetworkPolicy {
	cp := make([]types.KnoxNetworkPolicy, len(policies))
	copy(cp, policies)

	for i, policy := range policies {
		selector := policy.Spec.Selector

		matched := true
		for k, _ := range inSelector.MatchLabels {
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
		for k, _ := range inSelector.MatchLabels {
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

// MergeEgressIngressRules Function
func MergeEgressIngressRules(networkPolicies []types.KnoxNetworkPolicy) []types.KnoxNetworkPolicy {
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

// buildNetworkPolicies Function
func buildNetworkPolicies(microName string, services []types.K8sService, mergedSrcPerMergedDst map[string][]MergedPortDst) []types.KnoxNetworkPolicy {
	networkPolicies := []types.KnoxNetworkPolicy{}

	for mergedSrc, mergedDsts := range mergedSrcPerMergedDst {
		for _, dst := range mergedDsts {
			egressPolicy := buildNewKnoxEgressPolicy()
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

			egressRule := types.Egress{}

			// ================= //
			// L3/L4 label-based //
			// ================= //
			if dst.MatchLabels != "" {
				egressRule.MatchLabels = map[string]string{}

				dsts := strings.Split(dst.MatchLabels, ",")
				for _, dest := range dsts {
					kv := strings.Split(dest, "=")
					if len(kv) != 2 {
						continue
					}

					dstkey := kv[0]
					dstval := kv[1]

					egressRule.MatchLabels[dstkey] = dstval
				}

				// although same namespace, speficy namespace
				egressRule.MatchLabels["k8s:io.kubernetes.pod.namespace"] = dst.MicroserviceName

				// ===================== //
				// build L4 toPorts rule //
				// ===================== //
				if dst.ToPorts != nil && len(dst.ToPorts) > 0 {
					for i, toPort := range dst.ToPorts {
						if toPort.Ports == "0" {
							dst.ToPorts[i].Ports = ""
						}

						// =============== //
						// build HTTP rule //
						// =============== //
						if toPort.Protocol == "tcp" && checkHTTP(dst.Additional) {
							egressRule.ToHTTPs = []types.SpecHTTP{}

							httpElements := strings.Split(dst.Additional, "||")
							for _, http := range httpElements {
								method, path := strings.Split(http, "|")[0], strings.Split(http, "|")[1]
								httpRule := types.SpecHTTP{
									Method: method,
									Path:   path,
								}
								egressRule.ToHTTPs = append(egressRule.ToHTTPs, httpRule)
							}
						}
					}

					egressRule.ToPorts = dst.ToPorts
				}

				egressPolicy.Spec.Egress = append(egressPolicy.Spec.Egress, egressRule)
				networkPolicies = append(networkPolicies, egressPolicy)

				// add dependent ingress policy if not kube-system
				if dst.MicroserviceName != "kube-system" {
					ingressPolicy := buildNewIngressPolicyFromEgress(egressRule, egressPolicy.Spec.Selector)
					ingressPolicy.Spec.Ingress[0].MatchLabels["k8s:io.kubernetes.pod.namespace"] = microName

					networkPolicies = append(networkPolicies, ingressPolicy)
				}
			} else if dst.MicroserviceName == "reserved:cidr" && dst.Additional != "" {
				// =============== //
				// build CIDR rule //
				// =============== //
				cidrSlice := strings.Split(dst.Additional, ",")
				sort.Strings(cidrSlice)
				cidr := types.SpecCIDR{
					CIDRs: cidrSlice,
					Ports: dst.ToPorts,
				}

				egressRule.ToCIDRs = []types.SpecCIDR{cidr}
				egressPolicy.Spec.Egress = append(egressPolicy.Spec.Egress, egressRule)
				networkPolicies = append(networkPolicies, egressPolicy)
			} else if dst.MicroserviceName == "reserved:dns" && dst.Additional != "" {
				// =============== //
				// build FQDN rule //
				// =============== //
				fqdn := types.SpecFQDN{
					Matchnames: strings.Split(dst.Additional, ","),
					ToPorts:    dst.ToPorts,
				}

				egressRule.ToFQDNs = []types.SpecFQDN{fqdn}
				egressPolicy.Spec.Egress = append(egressPolicy.Spec.Egress, egressRule)
				networkPolicies = append(networkPolicies, egressPolicy)
			} else if dst.Additional != "" {
				// ================== //
				// build Service rule //
				// ================== //

				// external services (not internal k8s service)
				service := types.SpecService{
					ServiceName: dst.Additional,
					Namespace:   dst.MicroserviceName,
				}

				egressRule.ToServices = []types.SpecService{service}
				egressPolicy.Spec.Egress = append(egressPolicy.Spec.Egress, egressRule)
				networkPolicies = append(networkPolicies, egressPolicy)
			} else if strings.HasPrefix(dst.MicroserviceName, "reserved:") && dst.MatchLabels == "" {
				// ================= //
				// build Entity rule //
				// ================= //

				if dst.MicroserviceName == "reserved:host" { // host is allowed by default in Cilium
					continue
				}

				// handle for entity policy in Cilium
				egressRule.ToEndtities = []string{strings.Split(dst.MicroserviceName, ":")[1]}
				egressPolicy.Spec.Egress = append(egressPolicy.Spec.Egress, egressRule)
				networkPolicies = append(networkPolicies, egressPolicy)

				// add ingress policy as well (TODO: reserve...)
				ingressPolicy := buildNewKnoxIngressPolicy()
				ingressPolicy.Metadata["namespace"] = microName
				for k, v := range egressPolicy.Spec.Selector.MatchLabels {
					ingressPolicy.Spec.Selector.MatchLabels[k] = v
				}

				ingressRule := types.Ingress{}

				reserved := strings.Split(dst.MicroserviceName, ":")[1]
				if reserved == "remote-node" {
					ingressRule.FromEntities = []string{"world"}
				} else {
					ingressRule.FromEntities = []string{reserved}
				}

				ingressPolicy.Spec.Ingress = append(ingressPolicy.Spec.Ingress, ingressRule)
				networkPolicies = append(networkPolicies, ingressPolicy)
			}
		}
	}

	// a policy <- egress + ingress
	// mergedPolicies := MergeEgressIngressRules(networkPolicies)

	return networkPolicies
}

// =========================================== //
// == Step 1: Grouping Network Logs Per Dst == //
// =========================================== //

// checkExternalService Function
func checkExternalService(log types.KnoxNetworkLog, endpoints []types.K8sEndpoint) (types.K8sEndpoint, bool) {
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
func getSimpleDst(log types.KnoxNetworkLog, endpoints []types.K8sEndpoint, cidrBits int) (Dst, bool) {
	dstPort := 0
	externalInfo := ""

	// check if dst is L7 dns query
	if log.DNSQuery != "" {
		dst := Dst{
			MicroserviceName:   "reserved:dns",
			ContainerGroupName: log.DstPodName,
			Additional:         log.DNSQuery,
			Protocol:           log.Protocol,
			DstPort:            log.DstPort,
			Action:             log.Action,
		}

		return dst, true
	}

	// check if dst is out of cluster [external service / CIDR]
	if libs.ContainsElement(externals, log.DstNamespace) && net.ParseIP(log.DstPodName) != nil {
		// check if it is the external service policy
		if endpoint, valid := checkExternalService(log, endpoints); valid {
			log.DstNamespace = endpoint.MicroserviceName
			externalInfo = endpoint.EndpointName
		} else { // else, handle it as cidr policy
			log.DstNamespace = "reserved:cidr"
			ipNetwork := log.DstPodName + "/" + strconv.Itoa(cidrBits)
			_, network, _ := net.ParseCIDR(ipNetwork)
			externalInfo = network.String()
		}

		dst := Dst{
			MicroserviceName: log.DstNamespace,
			Additional:       externalInfo,
			Protocol:         log.Protocol,
			DstPort:          log.DstPort,
			Action:           log.Action,
		}

		return dst, true
	}

	// handle pod -> pod or pod -> entity
	// check dst port number is exposed or not (tcp, udp, or sctp)
	if IsExposedPort(log.Protocol, log.DstPort) {
		dstPort = log.DstPort
	}

	// if dst port is unexposed and not reserved, it's invalid
	if dstPort == 0 && !strings.HasPrefix(log.DstNamespace, "reserved:") {
		return Dst{}, false
	}

	// check HTTP
	httpInfo := ""
	if log.HTTPMethod != "" && log.HTTPPath != "" {
		httpInfo = log.HTTPMethod + "|" + log.HTTPPath
	}

	dst := Dst{
		MicroserviceName:   log.DstNamespace,
		ContainerGroupName: log.DstPodName,
		Protocol:           log.Protocol,
		DstPort:            dstPort,
		Action:             log.Action,
	}

	if httpInfo != "" {
		dst.Additional = httpInfo
	}

	return dst, true
}

// groupingLogsPerDst Function
func groupingLogsPerDst(networkLogs []types.KnoxNetworkLog, endpoints []types.K8sEndpoint, cidrBits int) map[Dst][]types.KnoxNetworkLog {
	perDst := map[Dst][]types.KnoxNetworkLog{}

	for _, log := range networkLogs {
		dst, valid := getSimpleDst(log, endpoints, cidrBits)
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
		if dst.Protocol == 6 && checkHTTP(dst.Additional) {
			dstCopy := dst

			dstCopy.Additional = ""
			for tcp := range perDst {
				if dstCopy == tcp {
					delete(perDst, tcp)
				}
			}
		}
	}

	return perDst
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
func extractingSrcFromLogs(perDst map[Dst][]types.KnoxNetworkLog, conGroups []types.ContainerGroup) map[Dst][]SrcSimple {
	perDstSrcLabel := map[Dst][]SrcSimple{}

	for dst, logs := range perDst {
		srcs := []SrcSimple{}

		for _, log := range logs {
			// get merged matchlables: "a=b,c=d,e=f"
			mergedLabels := getMergedLabels(log.SrcNamespace, log.SrcPodName, conGroups)
			if mergedLabels == "" {
				continue
			}

			src := SrcSimple{
				MicroserviceName:   log.SrcNamespace,
				ContainerGroupName: log.SrcPodName,
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
			Additional:         dstPort.Additional,
			Action:             dstPort.Action}

		simple2 := DstSimple{MicroserviceName: dst.MicroserviceName,
			ContainerGroupName: dst.ContainerGroupName,
			Additional:         dst.Additional,
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
		Additional:         dst.Additional,
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
				Additional:         dst.Additional,
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
						Additional:         dst.Additional,
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
				mergedDns = append(mergedDns, dst.Additional)
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
				Additional:       strings.Join(mergedDns, ","),
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
				mergedCidrs = append(mergedCidrs, dst.Additional)
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
				Additional:       strings.Join(mergedCidrs, ","),
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
		if dst.Additional != "" {
			if merged.Additional != "" {
				merged.Additional = merged.Additional + "||" + dst.Additional
			} else {
				merged.Additional = dst.Additional
			}
		}

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
		labelCounts := descendingLabelCountMap(labelCountMap)

		// fetch matched label dsts
		for _, labelCount := range labelCounts {
			if labelCount.Count >= 2 {
				// at least match count >= 2
				label := labelCount.Label

				selectedDsts := make([]MergedPortDst, 0)
				for _, dst := range mergedProtoPortDsts {
					if containLabel(label, dst.MatchLabels) {
						selectedDsts = append(selectedDsts, dst)
						mergedProtoPortDsts = removeDstMerged(mergedProtoPortDsts, dst)
					}
				}

				if len(selectedDsts) != 0 {
					if perGroupedSrcGroupedDst[mergedSrc] == nil {
						perGroupedSrcGroupedDst[mergedSrc] = []MergedPortDst{}
					}

					// groupingDsts -> one merged grouping dst
					groupedDst := groupingDstMergeds(label, selectedDsts)
					perGroupedSrcGroupedDst[mergedSrc] = append(perGroupedSrcGroupedDst[mergedSrc], groupedDst)
				}
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

// ====================== //
// == Duplicatie Check == //
// ====================== //

// removeDuplicatedName Function
func removeDuplicatedName(networkPolicies []types.KnoxNetworkPolicy) []types.KnoxNetworkPolicy {
	autoPolicyNames := []string{}

	newPolicies := []types.KnoxNetworkPolicy{}

	for _, policy := range networkPolicies {
		if !libs.ContainsElement(newPolicies, policy) {
			newPolicies = append(newPolicies, policy)
		}
	}

	// update generated time
	genTime := time.Now().Unix()
	for i := range newPolicies {
		newPolicies[i].GeneratedTime = genTime
	}

	// update unique policy name
	for i := range newPolicies {
		policyType := newPolicies[i].Metadata["name"]

		newName := "autogen-" + policyType + "-" + libs.RandSeq(10)
		for libs.ContainsElement(autoPolicyNames, newName) {
			newName = "autogen-" + policyType + "-" + libs.RandSeq(10)
		}
		autoPolicyNames = append(autoPolicyNames, newName)

		newPolicies[i].Metadata["name"] = newName
	}

	return newPolicies
}

// =============================== //
// == Network Policy Generation == //
// =============================== //

// network flow between [ startTime <= time < endTime ]
var startTime int64 = 0
var endTime int64 = 0

var cidrBits int = 24
var skipNamespaces []string

func init() {
	// init time filter
	endTime = time.Now().Unix()
	startTime = 0
	skipNamespaces = []string{"kube-system", "kube-public", "kube-node-lease"}
}

// updateTimeInterval function
func updateTimeInterval(lastDoc map[string]interface{}) {
	// time filter update for next interval
	ts := lastDoc["timestamp"].(primitive.DateTime)
	startTime = ts.Time().Unix() + 1
	endTime = time.Now().Unix()
}

// DiscoverNetworkPolicies Function
func DiscoverNetworkPolicies(microserviceName string,
	cidrBits int, // for CIDR policy (32 bits -> per IP)
	networkLogs []types.KnoxNetworkLog,
	services []types.K8sService,
	endpoints []types.K8sEndpoint,
	containerGroups []types.ContainerGroup) []types.KnoxNetworkPolicy {

	// step 1: update exposed ports (k8s service, docker-compose portbinding)
	updateExposedPorts(services, endpoints, containerGroups)

	// step 2: [network logs] -> {dst: [network logs (src+dst)]}
	logsPerDst := groupingLogsPerDst(networkLogs, endpoints, cidrBits)

	// step 3: {dst: [network logs (src+dst)]} -> {dst: [srcs (labeled)]}
	labeledSrcsPerDst := extractingSrcFromLogs(logsPerDst, containerGroups)

	// step 4: {dst: [srcs (labeled)]} -> {dst: [merged srcs (labeled + merged)]}
	mergedSrcsPerDst := mergingSrcByLabels(labeledSrcsPerDst)

	// step 5: {merged_src: [dsts (merged proto/port)]} merging protocols and ports for the same destinations
	mergedSrcPerMergedProtoDst := mergingDstSpecs(mergedSrcsPerDst)

	// step 6: {merged_src: [dsts (merged proto/port + labeld)] grouping dst based on labels
	mergedSrcPerMergedDst := mergingDstByLabels(mergedSrcPerMergedProtoDst, containerGroups)

	// step 7: building network policies
	networkPolicies := buildNetworkPolicies(microserviceName, services, mergedSrcPerMergedDst)

	// step 8: removing duplication policies
	deduplicatedName := removeDuplicatedName(networkPolicies)

	return deduplicatedName
}

// CronJobDaemon function
func CronJobDaemon() {
	// init cron job
	c := cron.New()
	c.AddFunc("@every 0h1m0s", StartToDiscoverNetworkPolicies) // time interval
	c.Start()

	sig := libs.GetOSSigChannel()
	<-sig
	log.Info().Msg("Got a signal to terminate the auto policy discovery")

	c.Stop() // Stop the scheduler (does not stop any jobs already running).
}

// StartToDiscoverNetworkPolicies function
func StartToDiscoverNetworkPolicies() {
	// get network traffic from  knox aggregation Databse
	docs, err := libs.GetTrafficFlowFromMongo(startTime, endTime)
	if err != nil {
		log.Err(err)
		return
	}

	if len(docs) < 1 {
		log.Info().Msgf("Traffic flow is not exist: %s ~ %s",
			time.Unix(startTime, 0).Format(libs.TimeFormSimple),
			time.Unix(endTime, 0).Format(libs.TimeFormSimple))

		startTime = endTime
		endTime = time.Now().Unix()
		return
	}

	log.Info().Msgf("the total number of traffic flow from db: %d", len(docs))

	updateTimeInterval(docs[len(docs)-1])

	// get k8s services
	services := libs.GetServices()

	// get k8s endpoints
	endpoints := libs.GetEndpoints()

	// get all the namespaces from k8s
	namespaces := libs.GetK8sNamespaces()

	// iterate each namespace
	for _, namespace := range namespaces {
		if namespace == "kube-system" {
			continue
		}

		// convert cilium network traffic -> network log, and filter traffic
		networkLogs := plugin.ConvertCiliumFlowsToKnoxLogs(namespace, docs)
		if len(networkLogs) == 0 {
			continue
		}

		log.Info().Msgf("policy discovery started for namespace: %s", namespace)

		// get pod information
		pods := libs.GetConGroups(namespace)

		// generate network policies
		policies := DiscoverNetworkPolicies(namespace, cidrBits, networkLogs, services, endpoints, pods)
		deduplication := []types.KnoxNetworkPolicy{}

		if len(policies) > 0 {
			// insert discovered policies to db
			deduplication = libs.InsertPoliciesToMongoDB(policies)

			// write discovered policies to files
			libs.WriteCiliumPolicyToYamlFile(namespace, deduplication)
		}

		log.Info().Msgf("policy discovery done    for namespace: %s, %d policies generated", namespace, len(deduplication))
	}
}
