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

var externals = []string{"reserved:world", "external"}
var skippedLabels = []string{"pod-template-hash"}

var exposedTCPPorts = []int{}
var exposedUDPPorts = []int{}
var exposedSCTPPorts = []int{}

var kubeDNSSvc []types.Service

// protocol
const (
	ICMP int = 1
	TCP  int = 6
	UDP  int = 17
	SCTP int = 132
)

// SrcSimple Structure
type SrcSimple struct {
	Namespace   string
	PodName     string
	MatchLabels string
}

// Dst Structure
type Dst struct {
	Namespace   string
	PodName     string
	Additional  string
	MatchLabels string
	Protocol    int
	DstPort     int

	Action string
}

// DstSimple Structure
type DstSimple struct {
	Namespace  string
	PodName    string
	Additional string

	Action string
}

// MergedPortDst Structure
type MergedPortDst struct {
	Namespace   string
	PodName     string
	Additional  string
	MatchLabels string
	ToPorts     []types.SpecPort

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
func updateDstLabels(dsts []MergedPortDst, pods []types.Pod) []MergedPortDst {
	for i, dst := range dsts {
		matchLabels := getMergedLabels(dst.Namespace, dst.PodName, pods)
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
			kubeDNSSvc = append(kubeDNSSvc, svc)
		} else if svc.Namespace == "kube-system" && svc.ServiceName == "kube-dns" && svc.Protocol == "TCP" {
			kubeDNSSvc = append(kubeDNSSvc, svc)
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

// removeKubeDNSPort
func removeKubeDNSPort(toPorts []types.SpecPort) []types.SpecPort {
	filtered := []types.SpecPort{}

	for _, toPort := range toPorts {
		isDNS := false
		for _, dnsSvc := range kubeDNSSvc {
			if toPort.Ports == strconv.Itoa(dnsSvc.ServicePort) &&
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

// buildNetworkPolicies Function
func buildNetworkPolicies(namespace string, services []types.Service, mergedSrcPerMergedDst map[string][]MergedPortDst) []types.KnoxNetworkPolicy {
	networkPolicies := []types.KnoxNetworkPolicy{}

	for mergedSrc, mergedDsts := range mergedSrcPerMergedDst {
		for _, dst := range mergedDsts {
			egressPolicy := buildNewKnoxEgressPolicy()
			egressPolicy.Metadata["namespace"] = namespace

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
				egressRule.MatchLabels["k8s:io.kubernetes.pod.namespace"] = dst.Namespace

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
				if dst.Namespace != "kube-system" {
					ingressPolicy := buildNewIngressPolicyFromEgress(egressRule, egressPolicy.Spec.Selector)
					ingressPolicy.Spec.Ingress[0].MatchLabels["k8s:io.kubernetes.pod.namespace"] = namespace

					networkPolicies = append(networkPolicies, ingressPolicy)
				}
			} else if dst.Namespace == "reserved:cidr" && dst.Additional != "" {
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
			} else if dst.Namespace == "reserved:dns" && dst.Additional != "" {
				// =============== //
				// build FQDN rule //
				// =============== //
				dst.ToPorts = removeKubeDNSPort(dst.ToPorts)

				fqdnSlice := strings.Split(dst.Additional, ",")
				sort.Strings(fqdnSlice)
				fqdn := types.SpecFQDN{
					MatchNames: fqdnSlice,
					// ToPorts:    dst.ToPorts // TODO: if FQDN != CIDR..
				}

				egressRule.ToFQDNs = []types.SpecFQDN{fqdn}
				egressPolicy.Spec.Egress = append(egressPolicy.Spec.Egress, egressRule)
				networkPolicies = append(networkPolicies, egressPolicy)
			} else if dst.Additional != "" {
				// ================== //
				// build Service rule //
				// ================== //

				// external services (NOT internal k8s service)
				service := types.SpecService{
					ServiceName: dst.Additional,
					Namespace:   dst.Namespace,
				}

				egressRule.ToServices = []types.SpecService{service}
				egressPolicy.Spec.Egress = append(egressPolicy.Spec.Egress, egressRule)
				networkPolicies = append(networkPolicies, egressPolicy)
			} else if strings.HasPrefix(dst.Namespace, "reserved:") && dst.MatchLabels == "" {
				// ================= //
				// build Entity rule //
				// ================= //

				// handle for entity policy in Cilium
				egressRule.ToEndtities = []string{strings.Split(dst.Namespace, ":")[1]}
				egressPolicy.Spec.Egress = append(egressPolicy.Spec.Egress, egressRule)
				networkPolicies = append(networkPolicies, egressPolicy)

				// add ingress policy as well (TODO: reserve...)
				ingressPolicy := buildNewKnoxIngressPolicy()
				ingressPolicy.Metadata["namespace"] = namespace
				for k, v := range egressPolicy.Spec.Selector.MatchLabels {
					ingressPolicy.Spec.Selector.MatchLabels[k] = v
				}

				ingressRule := types.Ingress{}

				reserved := strings.Split(dst.Namespace, ":")[1]
				if reserved == "remote-node" {
					ingressRule.FromEntities = []string{"remote-node"}
				} else {
					ingressRule.FromEntities = []string{reserved}
				}

				ingressPolicy.Spec.Ingress = append(ingressPolicy.Spec.Ingress, ingressRule)
				networkPolicies = append(networkPolicies, ingressPolicy)
			}
		}
	}

	return networkPolicies
}

// =========================================== //
// == Step 1: Grouping Network Logs Per Dst == //
// =========================================== //

// checkExternalService Function
func checkExternalService(log types.KnoxNetworkLog, endpoints []types.Endpoint) (types.Endpoint, bool) {
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

// getSimpleDst Function
func getSimpleDst(log types.KnoxNetworkLog, endpoints []types.Endpoint, cidrBits int) (Dst, bool) {
	dstPort := 0
	externalInfo := ""

	// check if dst is L7 dns query
	if log.DNSQuery != "" {
		dst := Dst{
			Namespace:  "reserved:dns",
			PodName:    log.DstPodName,
			Additional: log.DNSQuery,
			Protocol:   log.Protocol,
			DstPort:    log.DstPort,
			Action:     log.Action,
		}

		return dst, true
	}

	// check if dst is out of cluster [external service / CIDR]
	if libs.ContainsElement(externals, log.DstNamespace) && net.ParseIP(log.DstPodName) != nil {
		// check if it is the external service policy
		if endpoint, valid := checkExternalService(log, endpoints); valid {
			log.DstNamespace = endpoint.Namespace
			externalInfo = endpoint.EndpointName
		} else if names, err := net.LookupAddr(log.DstPodName); err == nil {
			dnsname := strings.TrimSuffix(names[0], ".")
			// if ip addr can be converted to a domain name, handle it as "reserved:dns"
			dst := Dst{
				Namespace: "reserved:dns",
				// ContainerGroupName: log.DstPodName,
				Additional: dnsname,
				Protocol:   log.Protocol,
				DstPort:    log.DstPort,
				Action:     log.Action,
			}

			return dst, true
		} else { // else, handle it as cidr policy
			log.DstNamespace = "reserved:cidr"
			ipNetwork := log.DstPodName + "/" + strconv.Itoa(cidrBits)
			_, network, _ := net.ParseCIDR(ipNetwork)
			externalInfo = network.String()
		}

		dst := Dst{
			Namespace:  log.DstNamespace,
			Additional: externalInfo,
			Protocol:   log.Protocol,
			DstPort:    log.DstPort,
			Action:     log.Action,
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
		Namespace: log.DstNamespace,
		PodName:   log.DstPodName,
		Protocol:  log.Protocol,
		DstPort:   dstPort,
		Action:    log.Action,
	}

	if httpInfo != "" {
		dst.Additional = httpInfo
	}

	return dst, true
}

// groupingLogsPerDst Function
func groupingLogsPerDst(networkLogs []types.KnoxNetworkLog, endpoints []types.Endpoint, cidrBits int) map[Dst][]types.KnoxNetworkLog {
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
func getMergedLabels(namespace, podName string, pods []types.Pod) string {
	mergedLabels := ""

	for _, pod := range pods {
		// find the container group of src
		if namespace == pod.Namespace && podName == pod.PodName {
			// remove common name identities
			labels := []string{}

			for _, label := range pod.Labels {
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
func extractingSrcFromLogs(perDst map[Dst][]types.KnoxNetworkLog, pods []types.Pod) map[Dst][]SrcSimple {
	perDstSrcLabel := map[Dst][]SrcSimple{}

	for dst, logs := range perDst {
		srcs := []SrcSimple{}

		for _, log := range logs {
			// get merged matchlables: "a=b,c=d,e=f"
			mergedLabels := getMergedLabels(log.SrcNamespace, log.SrcPodName, pods)
			if mergedLabels == "" {
				continue
			}

			src := SrcSimple{
				Namespace:   log.SrcNamespace,
				PodName:     log.SrcPodName,
				MatchLabels: mergedLabels}

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
		simple1 := DstSimple{Namespace: dstPort.Namespace,
			PodName:    dstPort.PodName,
			Additional: dstPort.Additional,
			Action:     dstPort.Action}

		simple2 := DstSimple{Namespace: dst.Namespace,
			PodName:    dst.PodName,
			Additional: dst.Additional,
			Action:     dst.Action}

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
		Namespace:  dst.Namespace,
		PodName:    dst.PodName,
		Additional: dst.Additional,
		Action:     dst.Action,
		ToPorts:    []types.SpecPort{port},
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
			dstSimple := DstSimple{Namespace: dst.Namespace,
				PodName:    dst.PodName,
				Additional: dst.Additional,
				Action:     dst.Action}

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
					simple := DstSimple{Namespace: dst.Namespace,
						PodName:    dst.PodName,
						Additional: dst.Additional,
						Action:     dst.Action}

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
			if dst.Namespace == "reserved:dns" {
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
				Namespace:  "reserved:dns",
				Additional: strings.Join(mergedDns, ","),
				ToPorts:    mergedDnsToPorts,
				Action:     "allow",
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
			if dst.Namespace == "reserved:cidr" {
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
				Namespace:  "reserved:cidr",
				Additional: strings.Join(mergedCidrs, ","),
				ToPorts:    mergedCidrToPorts,
				Action:     "allow",
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
		merged.Namespace = dst.Namespace
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
func mergingDstByLabels(mergedSrcPerMergedProtoDst map[string][]MergedPortDst, pods []types.Pod) map[string][]MergedPortDst {
	perGroupedSrcGroupedDst := map[string][]MergedPortDst{}

	for mergedSrc, mergedProtoPortDsts := range mergedSrcPerMergedProtoDst {
		// label update
		mergedProtoPortDsts = updateDstLabels(mergedProtoPortDsts, pods)

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

// ======================= //
// == Policy Name Check == //
// ======================= //

// generatePolicyName Function
func generatePolicyName(networkPolicies []types.KnoxNetworkPolicy) []types.KnoxNetworkPolicy {
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

	// update policy name
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

var cidrBits int = 32

func init() {
	// init time filter
	endTime = time.Now().Unix()
	startTime = 0
}

// updateTimeInterval function
func updateTimeInterval(lastDoc map[string]interface{}) {
	// time filter update for next interval
	ts := lastDoc["timestamp"].(primitive.DateTime)
	startTime = ts.Time().Unix() + 1
	endTime = time.Now().Unix()
}

// DiscoverNetworkPolicies Function
func DiscoverNetworkPolicies(namespace string,
	cidrBits int, // for CIDR policy (24bits in default, 32 bits -> per IP)
	networkLogs []types.KnoxNetworkLog,
	services []types.Service,
	endpoints []types.Endpoint,
	pods []types.Pod) []types.KnoxNetworkPolicy {

	// step 1: update exposed ports (k8s service, docker-compose portbinding)
	updateServiceEndpoint(services, endpoints, pods)

	// step 2: [network logs] -> {dst: [network logs (src+dst)]}
	logsPerDst := groupingLogsPerDst(networkLogs, endpoints, cidrBits)

	// step 3: {dst: [network logs (src+dst)]} -> {dst: [srcs (labeled)]}
	labeledSrcsPerDst := extractingSrcFromLogs(logsPerDst, pods)

	// step 4: {dst: [srcs (labeled)]} -> {dst: [merged srcs (labeled + merged)]}
	mergedSrcsPerDst := mergingSrcByLabels(labeledSrcsPerDst)

	// step 5: {merged_src: [dsts (merged proto/port)]} merging protocols and ports for the same destinations
	mergedSrcPerMergedProtoDst := mergingDstSpecs(mergedSrcsPerDst)

	// step 6: {merged_src: [dsts (merged proto/port + labeld)] grouping dst based on labels
	mergedSrcPerMergedDst := mergingDstByLabels(mergedSrcPerMergedProtoDst, pods)

	// step 7: building network policies
	networkPolicies := buildNetworkPolicies(namespace, services, mergedSrcPerMergedDst)

	// step 8: removing duplication policies
	namedPolicies := generatePolicyName(networkPolicies)

	return namedPolicies
}

// StartToDiscoverNetworkPolicies function
func StartToDiscoverNetworkPolicies() {
	// get network traffic from  knox aggregation Databse
	log.Info().Msg("try to get network traffic from the database")
	docs, err := libs.GetTrafficFlowFromMongo(startTime, endTime)
	if err != nil {
		log.Info().Msg(err.Error())
		return
	}

	if len(docs) < 1 {
		log.Info().Msgf("traffic flow not exist: %s ~ %s",
			time.Unix(startTime, 0).Format(libs.TimeFormSimple),
			time.Unix(endTime, 0).Format(libs.TimeFormSimple))

		endTime = time.Now().Unix()
		return
	}

	log.Info().Msgf("the total number of traffic flow from database: [%d]", len(docs))

	updateTimeInterval(docs[len(docs)-1])

	// get k8s services
	services := libs.GetServices()

	// get k8s endpoints
	endpoints := libs.GetEndpoints()

	// get k8s pods
	pods := libs.GetPods()

	// get k8s namespaces
	namespaces := libs.GetNamespaces()

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

		log.Info().Msgf("policy discovery started for namespace: [%s]", namespace)

		// get existing policies in db
		existingPolicies, _ := libs.GetNetworkPolicies()

		// discover network policies
		discoveredPolicies := DiscoverNetworkPolicies(namespace, cidrBits, networkLogs, services, endpoints, pods)

		// remove duplication
		newPolicies := DeduplicatePolicies(existingPolicies, discoveredPolicies)

		if len(newPolicies) > 0 {
			// insert discovered policies to db
			libs.InsertPoliciesToMongoDB(newPolicies)

			// write discovered policies to files
			libs.WriteCiliumPolicyToYamlFile(namespace, services, newPolicies)

			log.Info().Msgf("policy discovery done for namespace: [%s], [%d] policies discovered", namespace, len(newPolicies))
		} else {
			log.Info().Msgf("policy discovery done for namespace: [%s], no policy discovered", namespace)
		}
	}
}

// CronJob function
func CronJob() {
	log.Info().Msg("auto discovery cron job started")

	// init cron job
	c := cron.New()
	c.AddFunc("@every 0h1m0s", StartToDiscoverNetworkPolicies) // time interval
	c.Start()

	sig := libs.GetOSSigChannel()
	<-sig
	log.Info().Msg("Got a signal to terminate the auto policy discovery")

	c.Stop() // Stop the scheduler (does not stop any jobs already running).
}

// StartToDiscover function
func StartToDiscover() {
	// first time, call StartToDiscoverNetworkPolicies
	StartToDiscoverNetworkPolicies()

	// after than, call cron job
	CronJob()
}
