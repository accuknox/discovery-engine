package core

import (
	"net"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/accuknox/knoxAutoPolicy/src/libs"
	"github.com/accuknox/knoxAutoPolicy/src/plugin"
	"github.com/accuknox/knoxAutoPolicy/src/types"

	"github.com/cilium/cilium/api/v1/flow"
	"github.com/google/go-cmp/cmp"

	"github.com/robfig/cron"
	"github.com/rs/zerolog/log"
)

// ================================== //
// == Discovery Policy/Rule Types  == //
// ================================== //

// const values
const (
	// discovery policy type
	Egress        = 1
	Ingress       = 2
	EgressIngress = 3

	// status
	StatusRunning = "running"
	StatusIdle    = "idle"
)

// ======================= //
// == Gloabl Variables  == //
// ======================= //

// Status global worker
var Status string

var cronJob *cron.Cron

var waitG sync.WaitGroup
var stopChan chan struct{}

var exposedTCPPorts = []int{}
var exposedUDPPorts = []int{}
var exposedSCTPPorts = []int{}

var externals = []string{"reserved:world", "external"}

type labeledSrcsPerDstMap map[Dst][]SrcSimple          // key: simple Dst, value: simple Src
var gLabeledSrcsPerDst map[string]labeledSrcsPerDstMap // key: namespace, value: LabeledSrcsPerDstMap
var dnsToIPs map[string][]string                       // key: domain name, value: ip addresses
var k8sDNSSvc []types.Service                          // kube-dns

// init Function
func init() {
	stopChan = make(chan struct{})
	waitG = sync.WaitGroup{}

	dnsToIPs = map[string][]string{}
	gLabeledSrcsPerDst = map[string]labeledSrcsPerDstMap{}
	Status = "idle"
}

// ====================== //
// == Inner Structure  == //
// ====================== //

// SrcSimple Structure
type SrcSimple struct {
	Namespace   string
	PodName     string
	MatchLabels string
}

// DstSimple Structure
type DstSimple struct {
	Namespace  string
	PodName    string
	Additional string

	Action string
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

// MergedPortDst Structure
type MergedPortDst struct {
	Namespace   string
	PodName     string
	Additionals []string
	MatchLabels string
	ToPorts     []types.SpecPort
	HTTPTree    map[string]*Node

	Action string
}

// HTTPDst Structure
type HTTPDst struct {
	Namespace   string
	MatchLabels string
	ToPorts     []types.SpecPort
	HTTPTree    map[string]map[string]*Node
}

// LabelCount Structure
type LabelCount struct {
	Label string
	Count float64
}

// ======================= //
// == Helper Functions  == //
// ======================= //

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

// removeDstMergedSlice Function
func removeDstMergedSlice(dsts []MergedPortDst, remove MergedPortDst) []MergedPortDst {
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

// updateDNSToIPs function
func updateDNSToIPs(flows []*flow.Flow, dnsToIPs map[string][]string) {
	for _, flow := range flows {
		if flow.GetL7() != nil && flow.L7.GetDns() != nil {
			// if DSN response includes IPs
			if flow.L7.GetType() == 2 && len(flow.L7.GetDns().Ips) > 0 {
				// if internal services, skip
				if strings.HasSuffix(flow.L7.GetDns().GetQuery(), "svc.cluster.local.") {
					continue
				}

				query := strings.TrimSuffix(flow.L7.GetDns().GetQuery(), ".")
				ips := flow.L7.GetDns().GetIps()

				// udpate DNS to IPs map
				if val, ok := dnsToIPs[query]; ok {
					for _, ip := range ips {
						if !libs.ContainsElement(val, ip) {
							val = append(val, ip)
						}
					}

					dnsToIPs[query] = val
				} else {
					dnsToIPs[query] = ips
				}
			}
		}
	}
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

// ============================ //
// == Build Network Policies == //
// ============================ //

// buildNewKnoxPolicy Function
func buildNewKnoxPolicy() types.KnoxNetworkPolicy {
	return types.KnoxNetworkPolicy{
		APIVersion: "v1",
		Kind:       "KnoxNetworkPolicy",
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

// buildNewKnoxEgressPolicy Function
func buildNewKnoxEgressPolicy() types.KnoxNetworkPolicy {
	policy := buildNewKnoxPolicy()
	policy.Metadata["type"] = "egress"
	policy.Spec.Egress = []types.Egress{}

	return policy
}

// buildNewKnoxIngressPolicy Function
func buildNewKnoxIngressPolicy() types.KnoxNetworkPolicy {
	policy := buildNewKnoxPolicy()
	policy.Metadata["type"] = "ingress"
	policy.Spec.Ingress = []types.Ingress{}

	return policy
}

// buildNewIngressPolicyFromEgressPolicy Function
func buildNewIngressPolicyFromEgressPolicy(egress types.Egress, selector types.Selector) types.KnoxNetworkPolicy {
	ingress := buildNewKnoxIngressPolicy()
	ingress.Metadata["rule"] = "matchLabels"

	// update selector labels from egress match labels
	for k, v := range egress.MatchLabels {
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
	if len(egress.ToPorts) > 0 {
		ingress.Metadata["rule"] = ingress.Metadata["rule"] + "+toPorts"

		cpy := make([]types.SpecPort, len(egress.ToPorts))
		copy(cpy, egress.ToPorts)
		ingress.Spec.Ingress[0].ToPorts = cpy

		if len(egress.ToHTTPs) > 0 {
			ingress.Metadata["rule"] = ingress.Metadata["rule"] + "+toHTTPs"

			cpyHTTP := make([]types.SpecHTTP, len(egress.ToHTTPs))
			copy(cpyHTTP, egress.ToHTTPs)
			ingress.Spec.Ingress[0].ToHTTPs = cpyHTTP
		}
	}

	return ingress
}

// buildNewIngressPolicyFromSameSelector Function
func buildNewIngressPolicyFromSameSelector(namespace string, selector types.Selector) types.KnoxNetworkPolicy {
	ingress := buildNewKnoxIngressPolicy()
	ingress.Metadata["namespace"] = namespace
	for k, v := range selector.MatchLabels {
		ingress.Spec.Selector.MatchLabels[k] = v
	}

	return ingress
}

// doublecheckIngressEntities function for dropped packet
func doublecheckIngressEntities(namespace string, mergedSrcPerMergedDst map[string][]MergedPortDst, networkPolicies []types.KnoxNetworkPolicy) []types.KnoxNetworkPolicy {
	for mergedSrc, mergedDsts := range mergedSrcPerMergedDst {
		// if src inlcudes "reserved" prefix, it means Ingress Policy
		if strings.Contains(mergedSrc, "reserved") {
			entity := strings.Split(mergedSrc, "=")[1]

			for _, dst := range mergedDsts {
				included := true

				ingressPolicy := buildNewKnoxIngressPolicy()
				ingressPolicy.Metadata["namespace"] = namespace
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
				ingressRule.FromEntities = []string{entity}
				ingressPolicy.Spec.Ingress = append(ingressPolicy.Spec.Ingress, ingressRule)

				for _, policy := range networkPolicies {
					if cmp.Equal(&ingressPolicy.Spec.Selector, &policy.Spec.Selector) &&
						policy.Metadata["rule"] == "fromEntities" {

						if !libs.ContainsElement(policy.Spec.Ingress[0].FromEntities, entity) {
							included = false
							break
						}
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

// buildNetworkPolicies Function
func buildNetworkPolicies(namespace string, services []types.Service, mergedSrcPerMergedDst map[string][]MergedPortDst) []types.KnoxNetworkPolicy {
	networkPolicies := []types.KnoxNetworkPolicy{}

	for mergedSrc, mergedDsts := range mergedSrcPerMergedDst {
		// if src inlcudes "reserved" prefix, process later
		if strings.Contains(mergedSrc, "reserved") {
			continue
		}

		for _, dst := range mergedDsts {
			egressPolicy := buildNewKnoxEgressPolicy()
			egressPolicy.Metadata["namespace"] = namespace

			// ======== //
			// Selector //
			// ======== //
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

			// sorting toPorts
			if len(dst.ToPorts) > 0 {
				sort.Slice(dst.ToPorts, func(i, j int) bool {
					return dst.ToPorts[i].Port < dst.ToPorts[j].Port
				})
			}

			egressRule := types.Egress{}

			// ================= //
			// L3/L4 label-based //
			// ================= //
			if dst.MatchLabels != "" {
				egressPolicy.Metadata["rule"] = "matchLabels"

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

				// although they have same namespace, speficy namespace for clarity
				egressRule.MatchLabels["k8s:io.kubernetes.pod.namespace"] = dst.Namespace

				// ===================== //
				// build L4 toPorts rule //
				// ===================== //
				if dst.ToPorts != nil && len(dst.ToPorts) > 0 {
					for i, toPort := range dst.ToPorts {
						if toPort.Port == "0" {
							dst.ToPorts[i].Port = ""
						}

						// =============== //
						// build HTTP rule //
						// =============== //
						if toPort.Protocol == "tcp" && libs.CheckSpecHTTP(dst.Additionals) {
							egressRule.ToHTTPs = []types.SpecHTTP{}

							sort.Strings(dst.Additionals)

							for _, http := range dst.Additionals {
								method, path := strings.Split(http, "|")[0], strings.Split(http, "|")[1]
								httpRule := types.SpecHTTP{
									Method: method,
									Path:   path,
								}

								// if path includes wild card (.*), check aggreagted
								if strings.Contains(path, "*") {
									httpRule.Aggregated = true
								} else {
									httpRule.Aggregated = false
								}

								if !strings.Contains(egressPolicy.Metadata["rule"], "toHTTPs") {
									egressPolicy.Metadata["rule"] = egressPolicy.Metadata["rule"] + "+toHTTPs"
								}
								egressRule.ToHTTPs = append(egressRule.ToHTTPs, httpRule)
							}
						}
					}

					if !strings.Contains(egressPolicy.Metadata["rule"], "toPorts") {
						egressPolicy.Metadata["rule"] = egressPolicy.Metadata["rule"] + "+toPorts"
					}
					egressRule.ToPorts = dst.ToPorts
				}

				egressPolicy.Spec.Egress = append(egressPolicy.Spec.Egress, egressRule)

				if Cfg.DiscoveryPolicyTypes&Egress > 0 {
					networkPolicies = append(networkPolicies, egressPolicy)
				}

				if Cfg.DiscoveryPolicyTypes&Ingress > 0 && dst.Namespace != "kube-system" {
					ingressPolicy := buildNewIngressPolicyFromEgressPolicy(egressRule, egressPolicy.Spec.Selector)
					ingressPolicy.Spec.Ingress[0].MatchLabels["k8s:io.kubernetes.pod.namespace"] = namespace
					networkPolicies = append(networkPolicies, ingressPolicy)
				}
			} else if dst.Namespace == "reserved:cidr" && len(dst.Additionals) > 0 {
				egressPolicy.Metadata["rule"] = "toCIDRs"

				// =============== //
				// build CIDR rule //
				// =============== //
				cidrSlice := strings.Split(dst.Additionals[0], ",")
				sort.Strings(cidrSlice)
				cidr := types.SpecCIDR{
					CIDRs: cidrSlice,
				}
				egressRule.ToCIDRs = []types.SpecCIDR{cidr}

				if len(dst.ToPorts) > 0 {
					egressPolicy.Metadata["rule"] = egressPolicy.Metadata["rule"] + "+toPorts"
					egressRule.ToPorts = dst.ToPorts
				}

				egressPolicy.Spec.Egress = append(egressPolicy.Spec.Egress, egressRule)

				if Cfg.DiscoveryPolicyTypes&Egress > 0 {
					networkPolicies = append(networkPolicies, egressPolicy)
				}

				if Cfg.DiscoveryPolicyTypes&Ingress > 0 {
					// add ingress policy
					ingressPolicy := buildNewIngressPolicyFromSameSelector(namespace, egressPolicy.Spec.Selector)
					ingressPolicy.Metadata["rule"] = "toCIDRs"

					ingressRule := types.Ingress{}

					fromcidr := types.SpecCIDR{
						CIDRs: cidrSlice,
					}

					ingressRule.FromCIDRs = []types.SpecCIDR{fromcidr}
					ingressPolicy.Spec.Ingress = append(ingressPolicy.Spec.Ingress, ingressRule)
					networkPolicies = append(networkPolicies, ingressPolicy)
				}
			} else if dst.Namespace == "reserved:dns" && len(dst.Additionals) > 0 {
				egressPolicy.Metadata["rule"] = "toFQDNs"

				// =============== //
				// build FQDN rule //
				// =============== //
				if Cfg.DiscoveryPolicyTypes&Egress > 0 {
					sort.Strings(dst.Additionals)
					fqdn := types.SpecFQDN{
						MatchNames: dst.Additionals,
					}

					if len(dst.ToPorts) > 0 {
						egressPolicy.Metadata["rule"] = egressPolicy.Metadata["rule"] + "+toPorts"
						egressRule.ToPorts = dst.ToPorts
					}

					egressRule.ToFQDNs = []types.SpecFQDN{fqdn}
					egressPolicy.Spec.Egress = append(egressPolicy.Spec.Egress, egressRule)
					networkPolicies = append(networkPolicies, egressPolicy)
				}
			} else if strings.HasPrefix(dst.Namespace, "reserved:entity") && dst.MatchLabels == "" {
				egressPolicy.Metadata["rule"] = "toEntities"

				// ================= //
				// build Entity rule //
				// ================= //
				sort.Strings(dst.Additionals)

				// handle for entity policy in Cilium
				egressRule.ToEndtities = dst.Additionals
				egressPolicy.Spec.Egress = append(egressPolicy.Spec.Egress, egressRule)

				if Cfg.DiscoveryPolicyTypes&Egress > 0 {
					networkPolicies = append(networkPolicies, egressPolicy)
				}

				// add ingress policy
				if Cfg.DiscoveryPolicyTypes&Ingress > 0 {
					ingressPolicy := buildNewIngressPolicyFromSameSelector(namespace, egressPolicy.Spec.Selector)
					ingressPolicy.Metadata["rule"] = "fromEntities"
					ingressRule := types.Ingress{}
					ingressRule.FromEntities = dst.Additionals
					ingressPolicy.Spec.Ingress = append(ingressPolicy.Spec.Ingress, ingressRule)
					networkPolicies = append(networkPolicies, ingressPolicy)
				}
			} else if len(dst.Additionals) > 0 {
				egressPolicy.Metadata["rule"] = "toServices"

				// ================== //
				// build Service rule //
				// ================== //
				if Cfg.DiscoveryPolicyTypes&Egress > 0 {
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
		}
	}

	// double check ingress entities for dropped packet
	if Cfg.DiscoveryPolicyTypes&Ingress > 0 {
		networkPolicies = doublecheckIngressEntities(namespace, mergedSrcPerMergedDst, networkPolicies)
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

	// check DNS
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

	// check HTTP
	if log.HTTPMethod != "" && log.HTTPPath != "" {
		externalInfo = log.HTTPMethod + "|" + log.HTTPPath
	}

	// check CIDR (out of cluster)
	if libs.ContainsElement(externals, log.DstNamespace) && net.ParseIP(log.DstPodName) != nil {
		if endpoint, valid := checkExternalService(log, endpoints); valid {
			// 1. check if it is the external service policy
			log.DstNamespace = endpoint.Namespace
			externalInfo = endpoint.EndpointName
		} else if names, err := net.LookupAddr(log.DstPodName); err == nil {
			// 2. check if it can be reversed to the domain name,
			log.DstNamespace = "reserved:dns"
			dnsname := strings.TrimSuffix(names[0], ".")
			externalInfo = dnsname
		} else {
			// 3. else, handle it as cidr policy
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
	if isExposedPort(log.Protocol, log.DstPort) {
		dstPort = log.DstPort
	}

	// if dst port is unexposed and namespace is not reserved, it's invalid
	if dstPort == 0 && !strings.HasPrefix(log.DstNamespace, "reserved:") {
		return Dst{}, false
	}

	dst := Dst{
		Namespace:  log.DstNamespace,
		PodName:    log.DstPodName,
		Additional: externalInfo,
		Protocol:   log.Protocol,
		DstPort:    dstPort,
		Action:     log.Action,
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
		if dst.Protocol == 6 && libs.CheckHTTPMethod(dst.Additional) {
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
			libs.CountLabelByCombinations(labelCountMap, src.MatchLabels)
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
					if libs.ContainLabel(label, src.MatchLabels) {
						srcs = removeSrcFromSlice(srcs, src)
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
		// find the src pod
		if namespace == pod.Namespace && podName == pod.PodName {
			// remove common name identities
			labels := []string{}

			for _, label := range pod.Labels {
				/* TODO: do we need to skip the hash labels? */
				labels = append(labels, label)
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
func extractingSrcFromLogs(labeledSrcsPerDst map[Dst][]SrcSimple, perDst map[Dst][]types.KnoxNetworkLog, pods []types.Pod) map[Dst][]SrcSimple {
	for dst, logs := range perDst {
		srcs := []SrcSimple{}

		for _, log := range logs {
			src := SrcSimple{}

			// if src is reserved:
			if strings.Contains(log.SrcNamespace, "reserved:") {
				k := strings.Split(log.SrcNamespace, ":")[0]
				v := strings.Split(log.SrcNamespace, ":")[1]

				src = SrcSimple{
					Namespace:   log.SrcNamespace,
					PodName:     log.SrcPodName,
					MatchLabels: k + "=" + v}
			} else {
				// else get merged matchlables: "a=b,c=d,e=f"
				mergedLabels := getMergedLabels(log.SrcNamespace, log.SrcPodName, pods)
				if mergedLabels == "" {
					continue
				}

				src = SrcSimple{
					Namespace:   log.SrcNamespace,
					PodName:     log.SrcPodName,
					MatchLabels: mergedLabels}
			}

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
			labeledSrcsPerDst[dst] = srcs
		}
	}

	return labeledSrcsPerDst
}

// =========================================== //
// == Step 4: Merging Dst's Protocol + Port == //
// =========================================== //

// mergeCIDR function
func mergeCIDR(mergedSrcPerMergedDst map[string][]MergedPortDst) {
	// merge reserve dst per each merged Src
	for mergedSrc, dsts := range mergedSrcPerMergedDst {
		newDsts := []MergedPortDst{}

		// dns To SpecPorts
		cidrs := map[string][]types.SpecPort{}

		// step 1: get cidr
		for _, dst := range dsts {
			if dst.Namespace == "reserved:cidr" {
				for _, cidrAddr := range dst.Additionals {
					if exist, ok := cidrs[cidrAddr]; !ok {
						// if not exist, create cidr, and move toPorts
						if len(dst.ToPorts) > 0 {
							cidrs[cidrAddr] = dst.ToPorts
						} else {
							cidrs[cidrAddr] = []types.SpecPort{}
						}
					} else {
						// if exist, check duplicated toPorts
						for _, port := range dst.ToPorts {
							if !libs.ContainsElement(exist, port) {
								exist = append(exist, port)
							}
						}

						// update toPorts
						cidrs[cidrAddr] = exist
					}
				}
			} else {
				// if no reserved:cidr
				newDsts = append(newDsts, dst)
			}
		}

		// step 2: update mergedSrcPerMergedDst
		for cidr, toPorts := range cidrs {
			newDNS := MergedPortDst{
				Namespace:   "reserved:cidr",
				Additionals: []string{cidr},
				ToPorts:     toPorts,
				Action:      "allow",
			}
			newDsts = append(newDsts, newDNS)
		}

		mergedSrcPerMergedDst[mergedSrc] = newDsts
	}
}

// mergeFQDN function
func mergeFQDN(mergedSrcPerMergedDst map[string][]MergedPortDst) {
	// merge same dns per each merged Src
	for mergedSrc, dsts := range mergedSrcPerMergedDst {
		newDsts := []MergedPortDst{}

		// dns To SpecPorts
		dns := map[string][]types.SpecPort{}

		// step 1: get dns
		for _, dst := range dsts {
			if dst.Namespace == "reserved:dns" {
				for _, domainName := range dst.Additionals {
					if exist, ok := dns[domainName]; !ok {
						// if not exist, create dns, and move toPorts
						if len(dst.ToPorts) > 0 {
							dns[domainName] = dst.ToPorts
						} else {
							dns[domainName] = []types.SpecPort{}
						}
					} else {
						// if exist, check duplicated toPorts
						for _, port := range dst.ToPorts {
							if !libs.ContainsElement(exist, port) {
								exist = append(exist, port)
							}
						}

						// update toPorts
						dns[domainName] = exist
					}
				}
			} else {
				// if no reserved:dns
				newDsts = append(newDsts, dst)
			}
		}

		// step 2: update mergedSrcPerMergedDst
		for dns, toPorts := range dns {
			newDNS := MergedPortDst{
				Namespace:   "reserved:dns",
				Additionals: []string{dns},
				ToPorts:     toPorts,
				Action:      "allow",
			}
			newDsts = append(newDsts, newDNS)
		}

		mergedSrcPerMergedDst[mergedSrc] = newDsts
	}
}

// mergeEntities function
func mergeEntities(mergedSrcPerMergedDst map[string][]MergedPortDst) {
	// merge same entities per each merged Src
	for mergedSrc, dsts := range mergedSrcPerMergedDst {
		remains := []MergedPortDst{}

		// step 1: get entities
		entities := []string{}
		for _, dst := range dsts {
			if strings.HasPrefix(dst.Namespace, "reserved:") &&
				!strings.Contains(dst.Namespace, "cidr") &&
				!strings.Contains(dst.Namespace, "dns") {
				entity := strings.Split(dst.Namespace, ":")[1]

				if !libs.ContainsElement(entities, entity) {
					entities = append(entities, entity)
				}
			} else {
				// if no reserved:entity
				remains = append(remains, dst)
			}
		}

		// step 2: update mergedSrcPerMergedDst
		if len(entities) > 0 {
			newDNS := MergedPortDst{
				Namespace:   "reserved:entity",
				Additionals: entities,
				Action:      "allow",
			}
			remains = append(remains, newDNS)
		}

		mergedSrcPerMergedDst[mergedSrc] = remains
	}
}

// mergingProtocolPorts Function
func mergingProtocolPorts(mergedDsts []MergedPortDst, dst Dst) []MergedPortDst {
	for i, dstPort := range mergedDsts {
		simple1 := DstSimple{Namespace: dstPort.Namespace,
			PodName:    dstPort.PodName,
			Additional: dstPort.Additionals[0],
			Action:     dstPort.Action}

		simple2 := DstSimple{Namespace: dst.Namespace,
			PodName:    dst.PodName,
			Additional: dst.Additional,
			Action:     dst.Action}

		if simple1 == simple2 { // matched, append protocol+port info
			port := types.SpecPort{Protocol: libs.GetProtocol(dst.Protocol),
				Port: strconv.Itoa(dst.DstPort)}

			mergedDsts[i].ToPorts = append(mergedDsts[i].ToPorts, port)

			return mergedDsts
		}
	}

	// if not matched, create new one,
	port := types.SpecPort{Protocol: libs.GetProtocol(dst.Protocol),
		Port: strconv.Itoa(dst.DstPort)}

	mergedDst := MergedPortDst{
		Namespace:   dst.Namespace,
		PodName:     dst.PodName,
		Additionals: []string{dst.Additional},
		Action:      dst.Action,
		ToPorts:     []types.SpecPort{port},
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
						dsts = removeDstFromSlice(dsts, dst)
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

	// fqdn merging
	mergeFQDN(mergedSrcPerMergedDst)

	// cidr merging
	mergeCIDR(mergedSrcPerMergedDst)

	// entities merged (for Cilium)
	mergeEntities(mergedSrcPerMergedDst)

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

		if len(dst.Additionals) > 0 {
			if merged.Additionals != nil {
				for _, additional := range dst.Additionals {
					if additional != "" && !libs.ContainsElement(merged.Additionals, additional) {
						merged.Additionals = append(merged.Additionals, additional)
					}
				}
			} else {
				merged.Additionals = dst.Additionals
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
	mergedSrcPerMergedDst := map[string][]MergedPortDst{}

	for mergedSrc, mergedProtoPortDsts := range mergedSrcPerMergedProtoDst {
		// label update
		mergedProtoPortDsts = updateDstLabels(mergedProtoPortDsts, pods)

		// count each dst label
		labelCountMap := map[string]int{}
		for _, dst := range mergedProtoPortDsts {
			if dst.MatchLabels == "" {
				continue
			}

			libs.CountLabelByCombinations(labelCountMap, dst.MatchLabels)
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
					if libs.ContainLabel(label, dst.MatchLabels) {
						selectedDsts = append(selectedDsts, dst)
						mergedProtoPortDsts = removeDstMergedSlice(mergedProtoPortDsts, dst)
					}
				}

				if len(selectedDsts) != 0 {
					if mergedSrcPerMergedDst[mergedSrc] == nil {
						mergedSrcPerMergedDst[mergedSrc] = []MergedPortDst{}
					}

					// groupingDsts -> one merged grouping dst
					groupedDst := groupingDstMergeds(label, selectedDsts)
					mergedSrcPerMergedDst[mergedSrc] = append(mergedSrcPerMergedDst[mergedSrc], groupedDst)
				}
			}
		}

		// not grouped dst remains, append it
		for _, mergedDst := range mergedProtoPortDsts {
			if mergedSrcPerMergedDst[mergedSrc] == nil {
				mergedSrcPerMergedDst[mergedSrc] = []MergedPortDst{}
			}
			mergedSrcPerMergedDst[mergedSrc] = append(mergedSrcPerMergedDst[mergedSrc], mergedDst)
		}
	}

	return mergedSrcPerMergedDst
}

// ======================= //
// == Policy Name Check == //
// ======================= //

// generatePolicyName Function
func generatePolicyName(networkPolicies []types.KnoxNetworkPolicy) []types.KnoxNetworkPolicy {
	clusterName := libs.GetClusterName()
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
		polType := newPolicies[i].Metadata["type"]

		newName := "autopol-" + polType + "-" + libs.RandSeq(15)
		for libs.ContainsElement(autoPolicyNames, newName) {
			newName = "autopol-" + polType + "-" + libs.RandSeq(15)
		}
		autoPolicyNames = append(autoPolicyNames, newName)

		newPolicies[i].Metadata["name"] = newName
		newPolicies[i].Metadata["cluster_name"] = clusterName
	}

	return newPolicies
}

// ================================== //
// == labeledSrcsPerDst Map Update == //
// ================================== //

// UpdateLabeledSrcsPerDst function
func UpdateLabeledSrcsPerDst(labeledSrcsPerDst map[Dst][]SrcSimple) map[Dst][]SrcSimple {
	// only maintains pod-to-pod in cluster
	for dst := range labeledSrcsPerDst {
		// remove cidr because cidr can be outdated
		if dst.Namespace == "reserved:cidr" {
			delete(labeledSrcsPerDst, dst)
		}

		// remove additional is not "", which means.. http,fqdn, ....
		if dst.Additional != "" {
			delete(labeledSrcsPerDst, dst)
		}
	}

	return labeledSrcsPerDst
}

// ============================== //
// == Discover Network Policy  == //
// ============================== //

// DiscoverNetworkPolicies Function
func DiscoverNetworkPolicies(namespace string,
	cidrBits int, // for CIDR policy (24bits in default, 32 bits -> per IP)
	networkLogs []types.KnoxNetworkLog,
	services []types.Service,
	endpoints []types.Endpoint,
	pods []types.Pod) []types.KnoxNetworkPolicy {

	// step 1: [network logs] -> {dst: [network logs (src+dst)]}
	logsPerDst := groupingLogsPerDst(networkLogs, endpoints, cidrBits)

	/*
		step 2: {dst: [network logs (src+dst)]} -> {dst: [srcs (labeled)]}
		we keep labeledSrcsPerDst map for aggregating the merged policy set in the future
	*/
	labeledSrcsPerDst := map[Dst][]SrcSimple{}
	if val, ok := gLabeledSrcsPerDst[namespace]; ok {
		labeledSrcsPerDst = extractingSrcFromLogs(val, logsPerDst, pods)
	} else {
		labeledSrcsPerDst = extractingSrcFromLogs(labeledSrcsPerDst, logsPerDst, pods)
	}

	// step 3: {dst: [srcs (labeled)]} -> {dst: [merged srcs (labeled + merged)]}
	mergedSrcsPerDst := mergingSrcByLabels(labeledSrcsPerDst)

	// step 4: {merged_src: [dsts (merged proto/port)]} merging protocols and ports for the same destinations
	mergedSrcPerMergedProtoDst := mergingDstSpecs(mergedSrcsPerDst)

	// step 5: {merged_src: [dsts (merged proto/port + labeld)] grouping dst based on labels
	mergedSrcPerMergedDst := mergingDstByLabels(mergedSrcPerMergedProtoDst, pods)

	// step 6: aggregate HTTP rule (method+path)
	AggregateHTTPRules(mergedSrcPerMergedDst)

	// step 7: building network policies
	networkPolicies := buildNetworkPolicies(namespace, services, mergedSrcPerMergedDst)

	// step 8: generate random policy name
	namedPolicies := generatePolicyName(networkPolicies)

	// step 9: update labeledSrcsPerDst map (remove cidr dst/additionals)
	gLabeledSrcsPerDst[namespace] = UpdateLabeledSrcsPerDst(labeledSrcsPerDst)

	return namedPolicies
}

// ==================== //
// == Preprocessing  == //
// ==================== //

// getHaveToCheckItems func
func getHaveToCheckItems(igFlows types.IgnoringFlows) int {
	check := 0

	if igFlows.IgSourceNamespace != "" {
		check = check | 1<<0 // 1
	}

	if len(igFlows.IgSourceLabels) > 0 {
		check = check | 1<<1 // 2
	}

	if igFlows.IgDestinationNamespace != "" {
		check = check | 1<<2 // 4
	}

	if len(igFlows.IgDestinationLabels) > 0 {
		check = check | 1<<3 // 8
	}

	if igFlows.IgProtocol != "" {
		check = check | 1<<4 // 16
	}

	if igFlows.IgPortNumber != "" {
		check = check | 1<<5 // 32
	}

	return check
}

// containLabels func
func containLabels(cni string, igLabels []string, flowLabels []string) bool {
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

// PrefilterFlows func
func PrefilterFlows(flows []*flow.Flow) []*flow.Flow {
	filteredFlows := []*flow.Flow{}

	for _, flow := range flows {
		ignored := false

		for _, igFlow := range Cfg.IgnoringFlows {
			checkItems := getHaveToCheckItems(igFlow)

			checkedItems := 0

			// 1. check src namespace
			if (checkItems&1 > 0) && igFlow.IgSourceNamespace == flow.Source.Namespace {
				checkedItems = checkedItems | 1<<0
			}

			// 2. check src pod labels
			if (checkItems&2 > 0) && containLabels("cilium", igFlow.IgSourceLabels, flow.Source.Labels) {
				checkedItems = checkedItems | 1<<1
			}

			// 3. check dest namespace
			if (checkItems&4 > 0) && igFlow.IgDestinationNamespace == flow.Destination.Namespace {
				checkedItems = checkedItems | 1<<2
			}

			// 4. check dest pod labels
			if (checkItems&8 > 0) && containLabels("cilium", igFlow.IgDestinationLabels, flow.Destination.Labels) {
				checkedItems = checkedItems | 1<<3
			}

			// 5. check protocol
			if (checkItems&16 > 0) && flow.GetL4() != nil && plugin.GetProtocolStr(flow.GetL4()) == igFlow.IgProtocol {
				checkedItems = checkedItems | 1<<4
			}

			// 6. check port number
			if (checkItems&32 > 0) && flow.GetL4() != nil {
				if strings.Contains(flow.GetL4().String(), igFlow.IgPortNumber) {
					checkedItems = checkedItems | 1<<5
				}
			}

			if checkItems == checkedItems {
				ignored = true
				break
			}
		}

		if !ignored {
			filteredFlows = append(filteredFlows, flow)
		}
	}

	return filteredFlows
}

// GetCiliumFlows func
func GetCiliumFlows() []*flow.Flow {
	ciliumFlows := []*flow.Flow{}

	if Cfg.NetworkLogFrom == "db" {
		log.Info().Msg("Get network traffic from the database")

		flows := libs.GetTrafficFlowFromDB(Cfg.ConfigDB, Cfg.OneTimeJobTimeSelection)
		if len(flows) == 0 {
			return nil
		}

		// convert db flows -> cilium flows
		ciliumFlows = plugin.ConvertDocsToCiliumFlows(Cfg.ConfigDB.DBDriver, flows)
	} else if Cfg.NetworkLogFrom == "hubble" { // from hubble directly
		log.Info().Msg("Get network traffic from the Cilium Hubble directly")

		flows := plugin.GetCiliumFlowsFromHubble()
		if len(flows) == 0 {
			return nil
		}

		ciliumFlows = flows
	} else {
		log.Error().Msgf("Network log source not correct: %s", Cfg.NetworkLogFrom)
		return nil
	}

	return ciliumFlows
}

// StartToDiscoveryWorker function
func StartToDiscoveryWorker() {
	// get network flows
	networkFlows := GetCiliumFlows()
	if networkFlows == nil {
		return
	}

	// filter ignoring network flows
	networkFlows = PrefilterFlows(networkFlows)

	// get k8s services
	services := libs.GetServices()

	// get k8s endpoints
	endpoints := libs.GetEndpoints()

	// get k8s pods
	pods := libs.GetPods()

	// get k8s namespaces
	namespaces := libs.GetNamespaces()

	// get existing policies in db
	existingPolicies := libs.GetNetworkPolicies(Cfg.ConfigDB, "", "latest")

	// update exposed ports (k8s service, docker-compose portbinding)
	updateServiceEndpoint(services, endpoints, pods)

	// update DNS to IPs
	updateDNSToIPs(networkFlows, dnsToIPs)

	// iterate each namespace
	for _, namespace := range namespaces {
		// skip uninterested namespaces
		if libs.ContainsElement(SkipNamespaces, namespace) {
			continue
		}

		// convert cilium network traffic -> network log, and filter traffic
		networkLogs := plugin.ConvertCiliumFlowsToKnoxLogs(namespace, networkFlows, dnsToIPs)
		if len(networkLogs) == 0 {
			continue
		}

		log.Info().Msgf("Policy discovery started for namespace: [%s]", namespace)

		// discover network policies based on the network logs
		discoveredPolicies := DiscoverNetworkPolicies(namespace, Cfg.CIDRBits, networkLogs, services, endpoints, pods)

		// remove duplication
		newPolicies := DeduplicatePolicies(existingPolicies, discoveredPolicies, dnsToIPs)

		if len(newPolicies) > 0 {
			// insert discovered policies to db
			libs.InsertDiscoveredPolicies(Cfg.ConfigDB, newPolicies)

			if strings.Contains(Cfg.DiscoveredPolicyTo, "file") {

				// retrieve the latest policies from the db
				policies := libs.GetNetworkPolicies(Cfg.ConfigDB, namespace, "latest")

				// convert knoxPolicy to CiliumPolicy
				ciliumPolicies := plugin.ConvertKnoxPoliciesToCiliumPolicies(services, policies)

				// write discovered policies to files
				libs.WriteCiliumPolicyToYamlFile(namespace, ciliumPolicies)

				// write discovered policies to files
				libs.WriteKnoxPolicyToYamlFile(namespace, policies)
			}

			log.Info().Msgf("Policy discovery done    for namespace: [%s], [%d] policies discovered", namespace, len(newPolicies))
		} else {
			log.Info().Msgf("Policy discovery done    for namespace: [%s], no policy discovered", namespace)
		}
	}

	if Cfg.OperationMode != 2 && Status == StatusRunning {
		Status = StatusIdle
	}
}

// ============== //
// == Cron Job == //
// ============== //

// StartCronJob function
func StartCronJob() {
	// if network from hubble
	if Cfg.NetworkLogFrom == "hubble" {
		go plugin.StartHubbleRelay(stopChan, &waitG, Cfg.ConfigCiliumHubble)
		waitG.Add(1)
	}

	// init cron job
	cronJob = cron.New()
	err := cronJob.AddFunc(Cfg.CronJobTimeInterval, StartToDiscoveryWorker) // time interval
	if err != nil {
		log.Error().Msg(err.Error())
		return
	}

	cronJob.Start()

	log.Info().Msg("Auto discovery cron job started")
}

// StopCronJob function
func StopCronJob() {
	if cronJob != nil {
		log.Info().Msg("Got a signal to terminate the auto policy discovery")

		close(stopChan)
		waitG.Wait()

		cronJob.Stop() // Stop the scheduler (does not stop any jobs already running).

		cronJob = nil
	}
}

// ====================== //
// == Discovery Worker == //
// ====================== //

// StartWorker ...
func StartWorker() {
	if Status != StatusIdle {
		log.Info().Msg("There is no idle discovery worker")
		return
	}
	Status = StatusRunning

	if Cfg.OperationMode == 1 { // every time intervals
		StartCronJob()
	} else { // one-time generation
		StartToDiscoveryWorker()
		log.Info().Msgf("Auto discovery onetime job done")
	}
}

// StopWorker ...
func StopWorker() {
	if Status != StatusRunning {
		log.Info().Msg("There is no running discovery worker")
		return
	}
	Status = StatusIdle

	if Cfg.OperationMode == 1 { // every time intervals
		StopCronJob()
	} else { // one-time generation

	}
}
