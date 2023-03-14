package networkpolicy

import (
	"strconv"
	"strings"

	"github.com/accuknox/auto-policy-discovery/src/common"
	"github.com/accuknox/auto-policy-discovery/src/libs"
	types "github.com/accuknox/auto-policy-discovery/src/types"

	"github.com/google/go-cmp/cmp"
)

// ============================= //
// == Get Latest Policy in DB == //
// ============================= //

func includeSelectorLabels(newSelectorLabels map[string]string, existSelectorLabels map[string]string) bool {
	includeSelector := true

	for k, v := range newSelectorLabels {

		if existSelectorLabels[k] != v {
			includeSelector = false
			break
		}
	}

	return includeSelector
}

func GetLatestCIDRPolicy(existingPolicies []types.KnoxNetworkPolicy, policy types.KnoxNetworkPolicy) []types.KnoxNetworkPolicy {
	latestPolicies := []types.KnoxNetworkPolicy{}

	for _, exist := range existingPolicies {
		existPolicyType := exist.Metadata["type"]
		existRule := exist.Metadata["rule"]

		if exist.Metadata["namespace"] == policy.Metadata["namespace"] &&
			existPolicyType == policy.Metadata["type"] &&
			existRule == policy.Metadata["rule"] &&
			exist.Metadata["status"] == "latest" {

			// check selector matchLabels, if not matched, next existing rule
			if !includeSelectorLabels(policy.Spec.Selector.MatchLabels, exist.Spec.Selector.MatchLabels) {
				continue
			}

			// check cidr list
			matchCIDRs := true
			for _, cidr := range policy.Spec.Egress[0].ToCIDRs[0].CIDRs {
				for _, existCidr := range exist.Spec.Egress[0].ToCIDRs[0].CIDRs {
					if cidr != existCidr {
						matchCIDRs = false
					}
				}
			}

			if matchCIDRs {
				latestPolicies = append(latestPolicies, exist)
			}
		}
	}

	return latestPolicies
}

func GetLatestFQDNPolicy(existingPolicies []types.KnoxNetworkPolicy, policy types.KnoxNetworkPolicy) []types.KnoxNetworkPolicy {
	latestPolicies := []types.KnoxNetworkPolicy{}

	for _, exist := range existingPolicies {
		existPolicyType := exist.Metadata["type"]
		existRule := exist.Metadata["rule"]

		if exist.Metadata["namespace"] == policy.Metadata["namespace"] &&
			existPolicyType == policy.Metadata["type"] &&
			existRule == policy.Metadata["rule"] &&
			exist.Metadata["status"] == "latest" {

			// check selector matchLabels, if not matched, next existing rule
			if !includeSelectorLabels(policy.Spec.Selector.MatchLabels, exist.Spec.Selector.MatchLabels) {
				continue
			}

			// check FQDN list
			matchFQDN := true
			for _, dns := range policy.Spec.Egress[0].ToFQDNs[0].MatchNames {
				for _, existDNS := range exist.Spec.Egress[0].ToFQDNs[0].MatchNames {
					if dns != existDNS {
						matchFQDN = false
					}
				}
			}

			if matchFQDN {
				latestPolicies = append(latestPolicies, exist)
			}
		}
	}

	return latestPolicies
}

func GetLatestHTTPPolicy(existingPolicies []types.KnoxNetworkPolicy, policy types.KnoxNetworkPolicy) []types.KnoxNetworkPolicy {
	latestPolicies := []types.KnoxNetworkPolicy{}

	for _, exist := range existingPolicies {
		namespace := exist.Metadata["namespace"]
		policyType := exist.Metadata["type"]
		rule := exist.Metadata["rule"]
		status := exist.Metadata["status"]

		if namespace == policy.Metadata["namespace"] &&
			policyType == policy.Metadata["type"] &&
			rule == policy.Metadata["rule"] &&
			strings.Contains(rule, "toHTTPs") &&
			status == "latest" {

			// check selector matchLabels, if not matched, next existing rule
			if !includeSelectorLabels(policy.Spec.Selector.MatchLabels, exist.Spec.Selector.MatchLabels) {
				continue
			}

			// check matchLabels & toPorts
			newMatchLabels := map[string]string{}
			newCIDRs := []string{}
			newFQDNs := []string{}
			newEntities := []string{}
			newToPorts := []types.SpecPort{}

			existMatchLabels := map[string]string{}
			existCIDRs := []string{}
			existFQDNs := []string{}
			existEntities := []string{}
			existToPorts := []types.SpecPort{}

			if policyType == PolicyTypeEgress {
				newMatchLabels = policy.Spec.Egress[0].MatchLabels
				if strings.Contains(rule, "toCIDRs") {
					newCIDRs = policy.Spec.Egress[0].ToCIDRs[0].CIDRs
				}
				if strings.Contains(rule, "toFQDNs") {
					newFQDNs = policy.Spec.Egress[0].ToFQDNs[0].MatchNames
				}
				newEntities = policy.Spec.Egress[0].ToEntities
				newToPorts = policy.Spec.Egress[0].ToPorts

				existMatchLabels = exist.Spec.Egress[0].MatchLabels
				if strings.Contains(rule, "toCIDRs") {
					existCIDRs = exist.Spec.Egress[0].ToCIDRs[0].CIDRs
				}
				if strings.Contains(rule, "toFQDNs") {
					existFQDNs = exist.Spec.Egress[0].ToFQDNs[0].MatchNames
				}
				existEntities = exist.Spec.Egress[0].ToEntities
				existToPorts = exist.Spec.Egress[0].ToPorts
			} else {
				newMatchLabels = policy.Spec.Ingress[0].MatchLabels
				newEntities = policy.Spec.Ingress[0].FromEntities
				newToPorts = policy.Spec.Ingress[0].ToPorts

				existMatchLabels = exist.Spec.Ingress[0].MatchLabels
				existEntities = exist.Spec.Ingress[0].FromEntities
				existToPorts = exist.Spec.Ingress[0].ToPorts
			}

			if strings.Contains(rule, "matchLabels") {
				// check matchLabels
				matchLabels := true
				for k, v := range newMatchLabels {
					if existMatchLabels[k] != v {
						matchLabels = false
						break
					}
				}
				if !matchLabels {
					continue
				}
			} else if strings.Contains(rule, "toCIDRs") && policyType == PolicyTypeEgress {
				// check CIDRs
				matchCIDRs := true
				for _, cidr := range newCIDRs {
					if !libs.ContainsElement(existCIDRs, cidr) {
						matchCIDRs = false
						break
					}
				}
				if !matchCIDRs {
					continue
				}
			} else if strings.Contains(rule, "toFQDNs") && policyType == PolicyTypeEgress {
				// check FQDNs
				matchFQDNs := true
				for _, fqdn := range newFQDNs {
					if !libs.ContainsElement(existFQDNs, fqdn) {
						matchFQDNs = false
						break
					}
				}
				if !matchFQDNs {
					continue
				}
			} else if strings.Contains(rule, "toEntities") || strings.Contains(rule, "fromEntities") {
				// check From/To Entities
				matchEntities := true
				for _, entity := range newEntities {
					if !libs.ContainsElement(existEntities, entity) {
						matchEntities = false
						break
					}
				}
				if !matchEntities {
					continue
				}
			} else {
				// unknown type
				continue
			}

			// check toPorts
			matchToPorts := true
			for _, toPort := range newToPorts {
				if !libs.ContainsElement(existToPorts, toPort) {
					matchToPorts = false
					break
				}
			}
			if !matchToPorts {
				continue
			}

			latestPolicies = append(latestPolicies, exist)
		}
	}
	return latestPolicies
}

func GetLatestMatchLabelsPolicy(existingPolicies []types.KnoxNetworkPolicy, policy types.KnoxNetworkPolicy) []types.KnoxNetworkPolicy {
	latestPolicies := []types.KnoxNetworkPolicy{}

	for _, exist := range existingPolicies {
		existPolicyType := exist.Metadata["type"]

		if exist.Metadata["namespace"] == policy.Metadata["namespace"] &&
			exist.Metadata["type"] == policy.Metadata["type"] &&
			exist.Metadata["rule"] == policy.Metadata["rule"] &&
			exist.Metadata["status"] == "latest" {

			// check selector matchLabels, if not matched, next existing rule
			if !includeSelectorLabels(policy.Spec.Selector.MatchLabels, exist.Spec.Selector.MatchLabels) {
				continue
			}

			newMatchLabels := map[string]string{}
			existMatchLabels := map[string]string{}

			if existPolicyType == "egress" {
				newMatchLabels = policy.Spec.Egress[0].MatchLabels
				existMatchLabels = exist.Spec.Egress[0].MatchLabels
			} else {
				newMatchLabels = policy.Spec.Ingress[0].MatchLabels
				existMatchLabels = exist.Spec.Ingress[0].MatchLabels
			}

			matchLabels := true

			// check target matchLabels
			for k, v := range newMatchLabels {

				if existMatchLabels[k] != v {
					matchLabels = false
					break
				}
			}

			if matchLabels {
				latestPolicies = append(latestPolicies, exist)
			}
		}
	}

	return latestPolicies
}

func GetLatestEntityPolicy(existingPolicies []types.KnoxNetworkPolicy, policy types.KnoxNetworkPolicy) []types.KnoxNetworkPolicy {
	latestPolicies := []types.KnoxNetworkPolicy{}

	for _, exist := range existingPolicies {
		existPolicyType := exist.Metadata["type"]
		existRule := exist.Metadata["rule"]

		if exist.Metadata["namespace"] == policy.Metadata["namespace"] &&
			existPolicyType == policy.Metadata["type"] &&
			existRule == policy.Metadata["rule"] &&
			exist.Metadata["status"] == "latest" {

			// check selector matchLabels, if not matched, next existing rule
			if !includeSelectorLabels(policy.Spec.Selector.MatchLabels, exist.Spec.Selector.MatchLabels) {
				continue
			}

			latestPolicies = append(latestPolicies, exist)
		}
	}

	return latestPolicies
}

// ============================ //
// == Update Outdated Policy == //
// ============================ //

func updateOutdatedPolicy(outdatedPolicy types.KnoxNetworkPolicy, newPolicy *types.KnoxNetworkPolicy) {
	for _, id := range outdatedPolicy.FlowIDs {
		if !libs.ContainsElement(newPolicy.FlowIDs, id) {
			newPolicy.FlowIDs = append(newPolicy.FlowIDs, id)
		}
	}

	libs.UpdateOutdatedNetworkPolicy(CfgDB, outdatedPolicy.Metadata["name"], newPolicy.Metadata["name"])
}

func includedHTTPPath(httpRules []types.SpecHTTP, targetRule types.SpecHTTP) bool {
	included := false

	for _, httpRule := range httpRules {
		if httpRule.Method != targetRule.Method {
			continue
		}

		if httpRule.Path == targetRule.Path {
			included = true
			break
		}
	}

	return included
}

func UpdateHTTP(newPolicy types.KnoxNetworkPolicy, existingPolicies []types.KnoxNetworkPolicy) (types.KnoxNetworkPolicy, bool) {
	// case 1: if there is no latest, policy is new one
	latestPolicies := GetLatestHTTPPolicy(existingPolicies, newPolicy)
	if len(latestPolicies) == 0 {
		return newPolicy, true
	}

	newHTTPs := []types.SpecHTTP{}
	if newPolicy.Metadata["type"] == PolicyTypeEgress {
		newHTTPs = newPolicy.Spec.Egress[0].ToHTTPs
	} else {
		newHTTPs = newPolicy.Spec.Ingress[0].ToHTTPs
	}

	updated := false

	for _, latestPolicy := range latestPolicies {
		existHTTPs := []types.SpecHTTP{}
		if newPolicy.Metadata["type"] == PolicyTypeEgress {
			existHTTPs = latestPolicy.Spec.Egress[0].ToHTTPs
		} else {
			existHTTPs = latestPolicy.Spec.Ingress[0].ToHTTPs
		}

		// case 2: policy has toHTTPs, which are all includes in latest
		includedAllRules := true
		for _, rule := range newHTTPs {
			if !includedHTTPPath(existHTTPs, rule) {
				includedAllRules = false
				break
			}
		}

		// case 2: policy has toHTTPs which are all included in latest one
		if includedAllRules {
			continue // next existPolicy
		}

		// case 3: policy has toHTTPs which are not included in latest one
		if !includedAllRules {
			for _, http := range existHTTPs {
				if !libs.ContainsElement(newHTTPs, http) {
					newHTTPs = append(newHTTPs, http)
				}
			}
		}

		// annotate the outdated policy
		updateOutdatedPolicy(latestPolicy, &newPolicy)
		updated = true
	}

	// at least one updated
	if updated {
		if newPolicy.Metadata["type"] == PolicyTypeEgress {
			newPolicy.Spec.Egress[0].ToHTTPs = newHTTPs
		} else {
			newPolicy.Spec.Ingress[0].ToHTTPs = newHTTPs
		}

		return newPolicy, true
	}

	return newPolicy, false
}

func UpdateToPorts(newPolicy types.KnoxNetworkPolicy, existingPolicies []types.KnoxNetworkPolicy) (types.KnoxNetworkPolicy, bool) {
	// case 1: if there is no latest, policy is new one
	latestPolicies := []types.KnoxNetworkPolicy{}
	if strings.Contains(newPolicy.Metadata["rule"], "toCIDRs") {
		latestPolicies = GetLatestCIDRPolicy(existingPolicies, newPolicy)
	} else if strings.Contains(newPolicy.Metadata["rule"], "toFQDNs") {
		latestPolicies = GetLatestFQDNPolicy(existingPolicies, newPolicy)
	} else {
		return newPolicy, false
	}

	if len(latestPolicies) == 0 {
		return newPolicy, false
	}

	newToPorts := []types.SpecPort{}
	newICMPs := []types.SpecICMP{}
	if newPolicy.Metadata["type"] == PolicyTypeEgress {
		newToPorts = newPolicy.Spec.Egress[0].ToPorts
		newICMPs = newPolicy.Spec.Egress[0].ICMPs
	} else {
		newToPorts = newPolicy.Spec.Ingress[0].ToPorts
		newICMPs = newPolicy.Spec.Ingress[0].ICMPs
	}

	updated := false

	for _, latestPolicy := range latestPolicies {
		existToPorts := []types.SpecPort{}
		existICMPs := []types.SpecICMP{}
		if newPolicy.Metadata["type"] == PolicyTypeEgress {
			existToPorts = latestPolicy.Spec.Egress[0].ToPorts
			existICMPs = latestPolicy.Spec.Egress[0].ICMPs
		} else {
			existToPorts = latestPolicy.Spec.Ingress[0].ToPorts
			existICMPs = latestPolicy.Spec.Ingress[0].ICMPs
		}

		includedAllPortRules := true
		for _, port := range newToPorts {
			if !libs.ContainsElement(existToPorts, port) {
				includedAllPortRules = false
				break
			}
		}

		includedAllICMPRules := true
		for _, icmp := range newICMPs {
			if !libs.ContainsElement(existICMPs, icmp) {
				includedAllICMPRules = false
				break
			}
		}

		// case 2: policy has toPorts & icmps, which are all included in latest one
		if includedAllPortRules && includedAllICMPRules {
			continue // next existPolicy
		}

		// case 3: policy has toPorts or icmps which are not included in latest one
		if !includedAllPortRules {
			for _, toPort := range existToPorts {
				if !libs.ContainsElement(newToPorts, toPort) {
					newToPorts = append(newToPorts, toPort)
				}
			}
		}

		if !includedAllICMPRules {
			for _, icmp := range existICMPs {
				if !libs.ContainsElement(newICMPs, icmp) {
					newICMPs = append(newICMPs, icmp)
				}
			}
		}

		// annotate the outdated policy
		updateOutdatedPolicy(latestPolicy, &newPolicy)
		updated = true
	}

	// at least one updated
	if updated {
		if newPolicy.Metadata["type"] == PolicyTypeEgress {
			newPolicy.Spec.Egress[0].ToPorts = newToPorts
			newPolicy.Spec.Egress[0].ICMPs = newICMPs
		} else {
			newPolicy.Spec.Ingress[0].ToPorts = newToPorts
			newPolicy.Spec.Ingress[0].ICMPs = newICMPs
		}
		return newPolicy, true
	}

	return newPolicy, false
}

func UpdateMatchLabels(newPolicy types.KnoxNetworkPolicy, existingPolicies []types.KnoxNetworkPolicy) (types.KnoxNetworkPolicy, bool) {
	// case 1: if there is no latest policy, policy is new one
	latestPolicies := GetLatestMatchLabelsPolicy(existingPolicies, newPolicy)
	if len(latestPolicies) == 0 {
		return newPolicy, true
	}

	newICMPs := []types.SpecICMP{}
	newToPorts := []types.SpecPort{}
	newTargetLabelsCount := 0
	if newPolicy.Metadata["type"] == PolicyTypeEgress {
		newToPorts = newPolicy.Spec.Egress[0].ToPorts
		newICMPs = newPolicy.Spec.Egress[0].ICMPs
		newTargetLabelsCount = len(newPolicy.Spec.Egress[0].MatchLabels)
	} else {
		newToPorts = newPolicy.Spec.Ingress[0].ToPorts
		newICMPs = newPolicy.Spec.Ingress[0].ICMPs
		newTargetLabelsCount = len(newPolicy.Spec.Ingress[0].MatchLabels)
	}

	updated := false

	for _, latestPolicy := range latestPolicies {
		existToPorts := []types.SpecPort{}
		existICMPs := []types.SpecICMP{}
		existTargetLabelsCount := 0

		if newPolicy.Metadata["type"] == PolicyTypeEgress {
			existToPorts = latestPolicy.Spec.Egress[0].ToPorts
			existICMPs = latestPolicy.Spec.Egress[0].ICMPs
			existTargetLabelsCount = len(latestPolicy.Spec.Egress[0].MatchLabels)
		} else {
			existToPorts = latestPolicy.Spec.Ingress[0].ToPorts
			existICMPs = latestPolicy.Spec.Ingress[0].ICMPs
			existTargetLabelsCount = len(latestPolicy.Spec.Ingress[0].MatchLabels)
		}

		includedAllPortRules := true
		for _, rule := range newToPorts {
			if !libs.ContainsElement(existToPorts, rule) {
				includedAllPortRules = false
				break
			}
		}

		includedAllICMPRules := true
		for _, icmp := range newICMPs {
			if !libs.ContainsElement(existICMPs, icmp) {
				includedAllICMPRules = false
				break
			}
		}

		// case 2: policy has toPorts & icmps, which are all included in latest one
		if includedAllPortRules && includedAllICMPRules {
			// case 2-1: policy has the lower selector count? outdated
			if len(newPolicy.Spec.Selector.MatchLabels) < len(latestPolicy.Spec.Selector.MatchLabels) ||
				newTargetLabelsCount < existTargetLabelsCount {
				// case 2-2: policy has the lower target matchLabels count? outdated
				updateOutdatedPolicy(latestPolicy, &newPolicy)
				updated = true
			}

			continue // next existPolicy
		}

		// case 3: policy has toPorts or icmps which are not included in latest one
		if !includedAllPortRules {
			for _, toPort := range existToPorts {
				if !libs.ContainsElement(newToPorts, toPort) {
					newToPorts = append(newToPorts, toPort)
				}
			}
		}

		if !includedAllICMPRules {
			for _, icmp := range existICMPs {
				if !libs.ContainsElement(newICMPs, icmp) {
					newICMPs = append(newICMPs, icmp)
				}
			}
		}

		// annotate the outdated policy
		updateOutdatedPolicy(latestPolicy, &newPolicy)
		updated = true
	}

	// at least one updated occurred
	if updated {
		if newPolicy.Metadata["type"] == PolicyTypeEgress {
			newPolicy.Spec.Egress[0].ToPorts = newToPorts
			newPolicy.Spec.Egress[0].ICMPs = newICMPs
		} else {
			newPolicy.Spec.Ingress[0].ToPorts = newToPorts
			newPolicy.Spec.Ingress[0].ICMPs = newICMPs
		}

		return newPolicy, true
	}

	return newPolicy, false
}

func UpdateEntity(newPolicy types.KnoxNetworkPolicy, existingPolicies []types.KnoxNetworkPolicy) (types.KnoxNetworkPolicy, bool) {
	latestPolicies := GetLatestEntityPolicy(existingPolicies, newPolicy)
	if len(latestPolicies) == 0 {
		return newPolicy, false
	}

	var newPorts []types.SpecPort
	var newICMPs []types.SpecICMP

	newEntities := []string{}

	if newPolicy.Metadata["type"] == PolicyTypeEgress {
		newEntities = newPolicy.Spec.Egress[0].ToEntities
		newPorts = newPolicy.Spec.Egress[0].ToPorts
		newICMPs = newPolicy.Spec.Egress[0].ICMPs
	} else {
		newEntities = newPolicy.Spec.Ingress[0].FromEntities
		newPorts = newPolicy.Spec.Ingress[0].ToPorts
		newICMPs = newPolicy.Spec.Ingress[0].ICMPs
	}

	outdateOldPolicy := false

	for _, latestPolicy := range latestPolicies {
		var existPorts []types.SpecPort
		var existICMPs []types.SpecICMP

		existEntities := []string{}

		if newPolicy.Metadata["type"] == PolicyTypeEgress {
			existEntities = latestPolicy.Spec.Egress[0].ToEntities
			existPorts = newPolicy.Spec.Egress[0].ToPorts
			existICMPs = newPolicy.Spec.Egress[0].ICMPs
		} else {
			existEntities = latestPolicy.Spec.Ingress[0].FromEntities
			existPorts = newPolicy.Spec.Ingress[0].ToPorts
			existICMPs = newPolicy.Spec.Ingress[0].ICMPs
		}

		includedAllPortRules := true
		for _, rule := range newPorts {
			if !libs.ContainsElement(existPorts, rule) {
				includedAllPortRules = false
				break
			}
		}

		includedAllICMPRules := true
		for _, icmp := range newICMPs {
			if !libs.ContainsElement(existICMPs, icmp) {
				includedAllICMPRules = false
				break
			}
		}

		if !includedAllPortRules || !includedAllICMPRules {
			continue
		}

		for _, oldEntity := range existEntities {
			if !libs.ContainsElement(newEntities, oldEntity) {
				newEntities = append(newEntities, oldEntity)
			}
		}

		updateOutdatedPolicy(latestPolicy, &newPolicy)
		outdateOldPolicy = true
	}

	if outdateOldPolicy {
		if newPolicy.Metadata["type"] == PolicyTypeEgress {
			newPolicy.Spec.Egress[0].ToEntities = newEntities
		} else {
			newPolicy.Spec.Ingress[0].FromEntities = newEntities
		}
		return newPolicy, true
	}

	return newPolicy, false
}

func UpdateService(newPolicy types.KnoxNetworkPolicy, existingPolicies []types.KnoxNetworkPolicy) (types.KnoxNetworkPolicy, bool) {
	// case 1: if there is no latest, policy is new one
	latestPolicies := GetLatestEntityPolicy(existingPolicies, newPolicy)
	if len(latestPolicies) == 0 {
		return newPolicy, true
	}

	newServices := []types.SpecService{}
	if newPolicy.Metadata["type"] == PolicyTypeEgress {
		newServices = newPolicy.Spec.Egress[0].ToServices
	} else {
		return newPolicy, true
	}

	updated := false

	for _, latestPolicy := range latestPolicies {
		existServices := []types.SpecService{}
		if newPolicy.Metadata["type"] == PolicyTypeEgress {
			existServices = latestPolicy.Spec.Egress[0].ToServices
		} else {
			continue
		}

		// case 2: policy has toService, which are all includes in latest --> skip
		includeAllService := true
		for _, service := range newServices {
			if !libs.ContainsElement(existServices, service) {
				includeAllService = false
			}
		}

		if includeAllService {
			// case 2-1: policy has the lower selector count? outdated
			if len(newPolicy.Spec.Selector.MatchLabels) < len(latestPolicy.Spec.Selector.MatchLabels) {
				updateOutdatedPolicy(latestPolicy, &newPolicy)
				updated = true
			}

			continue
		}

		// case 3: policy has toHTTPs, latest has toHTTPs or no toHTTPs --> move to new policy
		for _, oldService := range existServices {
			if !libs.ContainsElement(newServices, oldService) {
				newServices = append(newServices, oldService)
			}
		}

		// annotate the outdated fqdn policy
		updateOutdatedPolicy(latestPolicy, &newPolicy)
		updated = true
	}

	// at least one updated
	if updated {
		if newPolicy.Metadata["type"] == PolicyTypeEgress {
			newPolicy.Spec.Egress[0].ToServices = newServices
		}

		return newPolicy, true
	}

	return newPolicy, false
}

// ======================= //
// == Policy Name Check == //
// ======================= //

func existPolicyName(policyNamesMap map[string]bool, name string) bool {
	if _, ok := policyNamesMap[name]; ok {
		return true
	}

	return false
}

func GeneratePolicyName(policyNamesMap map[string]bool, policy types.KnoxNetworkPolicy, clusterName string) types.KnoxNetworkPolicy {
	polType := policy.Metadata["type"]

	hashInt := common.HashInt(polType+policy.Metadata["labels"]+policy.Metadata["namespace"]+policy.Metadata["clustername"]+policy.Metadata["containername"])
	hash := strconv.FormatUint(uint64(hashInt), 10)
	name := "autopol-" + polType + "-" + hash

	policyNamesMap[name] = true

	policy.Metadata["name"] = name
	policy.Metadata["cluster_name"] = clusterName

	return policy
}

func GetToFQDNsFromNewDiscoveredPolicies(policy types.KnoxNetworkPolicy, newPolicies []types.KnoxNetworkPolicy) []types.KnoxNetworkPolicy {
	toFQDNs := []types.KnoxNetworkPolicy{}

	for _, newPolicy := range newPolicies {
		if cmp.Equal(&policy.Spec.Selector, &newPolicy.Spec.Selector) {
			for _, egress := range newPolicy.Spec.Egress {
				if len(egress.ToFQDNs) > 0 && !libs.ContainsElement(toFQDNs, newPolicy) {
					toFQDNs = append(toFQDNs, newPolicy)
				}
			}
		}
	}

	return toFQDNs
}

func GetDomainNameFromMap(ipAddr string, dnsToIPs map[string][]string) string {
	for domain, ips := range dnsToIPs {
		for _, ip := range ips {
			if ipAddr == ip {
				return domain
			}
		}
	}

	return ""
}

func GetFQDNFromDomainName(domainName string, fqdnPolicies []types.KnoxNetworkPolicy) (types.KnoxNetworkPolicy, bool) {
	for _, policy := range fqdnPolicies {
		for _, egress := range policy.Spec.Egress {
			for _, fqdn := range egress.ToFQDNs {
				if libs.ContainsElement(fqdn.MatchNames, domainName) {
					return policy, true
				}
			}
		}
	}

	return types.KnoxNetworkPolicy{}, false
}

func updateExistCIDRtoNewFQDN(existingPolicies []types.KnoxNetworkPolicy, newPolicies []types.KnoxNetworkPolicy, dnsToIPs map[string][]string) {
	for _, existCIDR := range existingPolicies {
		policyType := existCIDR.Metadata["type"]
		rule := existCIDR.Metadata["rule"]

		if policyType == "egress" && strings.Contains(rule, "toCIDRs") {
			for _, toCidr := range existCIDR.Spec.Egress[0].ToCIDRs {
				// get fqdns from same selector
				toFQDNs := GetToFQDNsFromNewDiscoveredPolicies(existCIDR, newPolicies)

				for _, cidr := range toCidr.CIDRs { // we know the number of cidr is 1
					ip := strings.Split(cidr, "/")[0]

					// get domain name from the map
					domainName := GetDomainNameFromMap(ip, dnsToIPs)

					// check domain name in fqdn
					if fqdnPolicy, matched := GetFQDNFromDomainName(domainName, toFQDNs); matched {
						if len(existCIDR.Spec.Egress[0].ToPorts) > 0 {
							// if cidr has toPorts also, check duplication as well
							cidrToPorts := existCIDR.Spec.Egress[0].ToPorts
							fqdnToPorts := fqdnPolicy.Spec.Egress[0].ToPorts
							if fqdnToPorts == nil {
								fqdnToPorts = []types.SpecPort{}
							}

							// move cidr's toPorts -> fqdn's toPorts
							for _, toPort := range cidrToPorts {
								if !libs.ContainsElement(fqdnToPorts, toPort) {
									fqdnToPorts = append(fqdnToPorts, toPort)
								}
							}

							// updated fqdn -> newPolicies
							fqdnPolicy.Spec.Egress[0].ToPorts = fqdnToPorts
							for i, exist := range newPolicies {
								if fqdnPolicy.Metadata["name"] == exist.Metadata["name"] {
									newPolicies[i] = fqdnPolicy
								}
							}
						}

						if len(existCIDR.Spec.Egress[0].ICMPs) > 0 {
							// if cidr has ICMPs also, check duplication as well
							cidrICMPs := existCIDR.Spec.Egress[0].ICMPs
							fqdnICMPs := fqdnPolicy.Spec.Egress[0].ICMPs
							if fqdnICMPs == nil {
								fqdnICMPs = []types.SpecICMP{}
							}

							// move cidr's ICMPs -> fqdn's ICMPs
							for _, icmp := range cidrICMPs {
								if !libs.ContainsElement(fqdnICMPs, icmp) {
									fqdnICMPs = append(fqdnICMPs, icmp)
								}
							}

							// updated fqdn -> newPolicies
							fqdnPolicy.Spec.Egress[0].ICMPs = fqdnICMPs
							for i, exist := range newPolicies {
								if fqdnPolicy.Metadata["name"] == exist.Metadata["name"] {
									newPolicies[i] = fqdnPolicy
								}
							}
						}

						libs.UpdateOutdatedNetworkPolicy(CfgDB, existCIDR.Metadata["name"], fqdnPolicy.Metadata["name"])
					}
				}
			}
		}
	}
}

// ==================== //
// == Exact Matching == //
// ==================== //

func IsExistingPolicySpec(existingPolicies []types.KnoxNetworkPolicy, newPolicy types.KnoxNetworkPolicy) bool {
	for _, exist := range existingPolicies {
		if cmp.Equal(&exist.Spec, &newPolicy.Spec) {
			return true
		}
	}

	return false
}

// ====================================== //
// == Update Duplicated Network Policy == //
// ====================================== //

func UpdateDuplicatedPolicy(existingPolicies []types.KnoxNetworkPolicy, discoveredPolicies []types.KnoxNetworkPolicy, dnsToIPs map[string][]string, clusterName string) ([]types.KnoxNetworkPolicy, []types.KnoxNetworkPolicy) {
	newPolicies := []types.KnoxNetworkPolicy{}
	updatedPolicies := []types.KnoxNetworkPolicy{}

	existIngressPolicies := map[Selector]types.KnoxNetworkPolicy{}
	existEgressPolicies := map[Selector]types.KnoxNetworkPolicy{}

	policyNamesMap := map[string]bool{}
	for _, existPolicy := range existingPolicies {
		policyNamesMap[existPolicy.Metadata["name"]] = true

		lblArr := getLabelArrayFromMap(existPolicy.Spec.Selector.MatchLabels)
		selector := Selector{existPolicy.Kind, strings.Join(lblArr, ",")}
		if existPolicy.Metadata["type"] == PolicyTypeIngress {
			existIngressPolicies[selector] = existPolicy
		} else {
			existEgressPolicies[selector] = existPolicy
		}
	}

	for _, newPolicy := range discoveredPolicies {
		lblArr := getLabelArrayFromMap(newPolicy.Spec.Selector.MatchLabels)
		selector := Selector{newPolicy.Kind, strings.Join(lblArr, ",")}

		if newPolicy.Metadata["type"] == PolicyTypeIngress {
			existPolicy, ok := existIngressPolicies[selector]
			if ok {
				// Ingress policy for this endpoint exists already
				mergedPolicy, updated := mergeIngressPolicies(existPolicy, []types.KnoxNetworkPolicy{newPolicy})
				if updated {
					mergedPolicy.Metadata["status"] = "updated"
					existIngressPolicies[selector] = mergedPolicy
				}
			} else {
				// Ingress policy for this endpoint does not exists previously
				namedPolicy := GeneratePolicyName(policyNamesMap, newPolicy, clusterName)
				newPolicies = append(newPolicies, namedPolicy)
			}
		} else {
			existPolicy, ok := existEgressPolicies[selector]
			if ok {
				// Egress policy for this endpoint exists already
				mergedPolicy, updated := mergeEgressPolicies(existPolicy, []types.KnoxNetworkPolicy{newPolicy})
				if updated {
					mergedPolicy.Metadata["status"] = "updated"
					existEgressPolicies[selector] = mergedPolicy
				}
			} else {
				// Egress policy for this endpoint does not exists previously
				namedPolicy := GeneratePolicyName(policyNamesMap, newPolicy, clusterName)
				newPolicies = append(newPolicies, namedPolicy)
			}
		}
	}

	for _, policy := range existIngressPolicies {
		if policy.Metadata["status"] == "updated" {
			policy.Metadata["status"] = "latest"
			//delete(policy.Metadata, "status")
			updatedPolicies = append(updatedPolicies, policy)
		}
	}
	for _, policy := range existEgressPolicies {
		if policy.Metadata["status"] == "updated" {
			policy.Metadata["status"] = "latest"
			//delete(policy.Metadata, "status")
			updatedPolicies = append(updatedPolicies, policy)
		}
	}

	return newPolicies, updatedPolicies
}
