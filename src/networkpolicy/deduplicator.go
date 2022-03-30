package networkpolicy

import (
	"sort"
	"strings"
	"time"

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

			// check cidr list
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

func GetLastedHTTPPolicy(existingPolicies []types.KnoxNetworkPolicy, policy types.KnoxNetworkPolicy) []types.KnoxNetworkPolicy {
	latestPolicies := []types.KnoxNetworkPolicy{}

	for _, exist := range existingPolicies {
		existPolicyType := exist.Metadata["type"]
		existRule := exist.Metadata["rule"]

		if exist.Metadata["namespace"] == policy.Metadata["namespace"] &&
			existPolicyType == policy.Metadata["type"] &&
			strings.Contains(existRule, "toHTTPs") &&
			exist.Metadata["status"] == "latest" {

			// check selector matchLabels, if not matched, next existing rule
			if !includeSelectorLabels(policy.Spec.Selector.MatchLabels, exist.Spec.Selector.MatchLabels) {
				continue
			}

			// check matchLabels & toPorts
			newMatchLabels := map[string]string{}
			newToPorts := []types.SpecPort{}

			existMatchLabels := map[string]string{}
			existToPorts := []types.SpecPort{}

			if existPolicyType == "egress" {
				newMatchLabels = policy.Spec.Egress[0].MatchLabels
				newToPorts = policy.Spec.Egress[0].ToPorts

				existMatchLabels = exist.Spec.Egress[0].MatchLabels
				existToPorts = exist.Spec.Egress[0].ToPorts
			} else {
				newMatchLabels = policy.Spec.Ingress[0].MatchLabels
				newToPorts = policy.Spec.Ingress[0].ToPorts

				existMatchLabels = exist.Spec.Ingress[0].MatchLabels
				existToPorts = exist.Spec.Ingress[0].ToPorts
			}

			// 1. check matchLabels
			matchLabels := true
			for k, v := range newMatchLabels {

				if existMatchLabels[k] != v {
					matchLabels = false
					break
				}
			}

			// 2. check toPorts
			matchToPorts := true
			for _, toPort := range newToPorts {
				if existToPorts == nil && len(existToPorts) == 0 {
					matchToPorts = false
					break
				}

				if !libs.ContainsElement(existToPorts, toPort) {
					matchToPorts = false
					break
				}
			}

			if matchLabels && matchToPorts {
				latestPolicies = append(latestPolicies, exist)
			}
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
	latestPolicies := GetLastedHTTPPolicy(existingPolicies, newPolicy)
	if len(latestPolicies) == 0 {
		return newPolicy, true
	}

	newHTTP := []types.SpecHTTP{}
	if newPolicy.Metadata["type"] == "egress" {
		newHTTP = newPolicy.Spec.Egress[0].ToHTTPs
	} else {
		newHTTP = newPolicy.Spec.Ingress[0].ToHTTPs
	}

	updated := false

	for _, latestPolicy := range latestPolicies {
		existHTTP := []types.SpecHTTP{}
		if newPolicy.Metadata["type"] == "egress" {
			existHTTP = latestPolicy.Spec.Egress[0].ToHTTPs
		} else {
			existHTTP = latestPolicy.Spec.Ingress[0].ToHTTPs
		}

		// case 2: policy has toHTTPs, which are all includes in latest
		includeAllRules := true
		for _, rule := range newHTTP {
			if !includedHTTPPath(existHTTP, rule) {
				includeAllRules = false
			}
		}

		if includeAllRules {
			// case 2-1: policy has the lower selector count? outdated
			if len(newPolicy.Spec.Selector.MatchLabels) < len(latestPolicy.Spec.Selector.MatchLabels) {
				updateOutdatedPolicy(latestPolicy, &newPolicy)
				updated = true
			}

			continue
		}

		// case 3: if policy has no toHTTPs, append it
		for _, rule := range existHTTP {
			if !includedHTTPPath(newHTTP, rule) {
				newHTTP = append(newHTTP, rule)
			}
		}

		// annotate the outdated policy
		updateOutdatedPolicy(latestPolicy, &newPolicy)
		updated = true
	}

	// at least one updated
	if updated {
		if newPolicy.Metadata["type"] == "egress" {
			newPolicy.Spec.Egress[0].ToHTTPs = newHTTP
		} else {
			newPolicy.Spec.Ingress[0].ToHTTPs = newHTTP
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
		return newPolicy, true
	}

	if len(latestPolicies) == 0 {
		return newPolicy, true
	}

	newToPorts := []types.SpecPort{}
	newICMPs := []types.SpecICMP{}
	if newPolicy.Metadata["type"] == "egress" {
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
		if newPolicy.Metadata["type"] == "egress" {
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
			// case 2-1: policy has the lower selector count? outdated
			if len(newPolicy.Spec.Selector.MatchLabels) < len(latestPolicy.Spec.Selector.MatchLabels) {
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

	// at least one updated
	if updated {
		if newPolicy.Metadata["type"] == "egress" {
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
	if newPolicy.Metadata["type"] == "egress" {
		newToPorts = newPolicy.Spec.Egress[0].ToPorts
		newICMPs = newPolicy.Spec.Egress[0].ICMPs
		newTargetLabelsCount = len(newPolicy.Spec.Egress[0].MatchLabels)
	} else {
		newToPorts = newPolicy.Spec.Ingress[0].ToPorts
		newICMPs = newPolicy.Spec.Egress[0].ICMPs
		newTargetLabelsCount = len(newPolicy.Spec.Ingress[0].MatchLabels)
	}

	updated := false

	for _, latestPolicy := range latestPolicies {
		existToPorts := []types.SpecPort{}
		existICMPs := []types.SpecICMP{}
		existTargetLabelsCount := 0

		if newPolicy.Metadata["type"] == "egress" {
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
		if newPolicy.Metadata["type"] == "egress" {
			newPolicy.Spec.Egress[0].ToPorts = newToPorts
			newPolicy.Spec.Egress[0].ICMPs = newICMPs
		} else {
			newPolicy.Spec.Ingress[0].ICMPs = newICMPs
		}

		return newPolicy, true
	}

	return newPolicy, false
}

func UpdateEntity(newPolicy types.KnoxNetworkPolicy, existingPolicies []types.KnoxNetworkPolicy) (types.KnoxNetworkPolicy, bool) {
	// case 1: if there is no latest, policy is new one
	latestPolicies := GetLatestEntityPolicy(existingPolicies, newPolicy)
	if len(latestPolicies) == 0 {
		return newPolicy, true
	}

	newEntities := []string{}
	if newPolicy.Metadata["type"] == "egress" {
		newEntities = newPolicy.Spec.Egress[0].ToEndtities
	} else {
		newEntities = newPolicy.Spec.Ingress[0].FromEntities
	}

	updated := false

	for _, latestPolicy := range latestPolicies {
		existEntities := []string{}
		if newPolicy.Metadata["type"] == "egress" {
			existEntities = latestPolicy.Spec.Egress[0].ToEndtities
		} else {
			existEntities = latestPolicy.Spec.Ingress[0].FromEntities
		}

		// case 2: policy has toHTTPs, which are all includes in latest --> skip
		includeAllEntities := true
		for _, entity := range newEntities {
			if !libs.ContainsElement(existEntities, entity) {
				includeAllEntities = false
			}
		}

		if includeAllEntities {
			// case 2-1: policy has the lower selector count? outdated
			if len(newPolicy.Spec.Selector.MatchLabels) < len(latestPolicy.Spec.Selector.MatchLabels) {
				updateOutdatedPolicy(latestPolicy, &newPolicy)
				updated = true
			}

			continue
		}

		// case 3: policy has toHTTPs, latest has toHTTPs or no toHTTPs --> move to new policy
		for _, oldEntity := range existEntities {
			if !libs.ContainsElement(newEntities, oldEntity) {
				newEntities = append(newEntities, oldEntity)
			}
		}

		// annotate the outdated fqdn policy
		updateOutdatedPolicy(latestPolicy, &newPolicy)
		updated = true
	}

	// at least one updated
	if updated {
		if newPolicy.Metadata["type"] == "egress" {
			newPolicy.Spec.Egress[0].ToEndtities = newEntities
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
	if newPolicy.Metadata["type"] == "egress" {
		newServices = newPolicy.Spec.Egress[0].ToServices
	} else {
		return newPolicy, true
	}

	updated := false

	for _, latestPolicy := range latestPolicies {
		existServices := []types.SpecService{}
		if newPolicy.Metadata["type"] == "egress" {
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
		if newPolicy.Metadata["type"] == "egress" {
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
	egressPrefix := "autopol-egress-"
	ingressPrefix := "autopol-ingress-"

	polType := policy.Metadata["type"]
	name := "autopol-" + polType + "-" + libs.RandSeq(15)

	for existPolicyName(policyNamesMap, name) {
		if polType == "egress" {
			name = egressPrefix + libs.RandSeq(15)
		} else {
			name = ingressPrefix + libs.RandSeq(15)
		}
	}

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

func UpdateDuplicatedPolicy(existingPolicies []types.KnoxNetworkPolicy, discoveredPolicies []types.KnoxNetworkPolicy, dnsToIPs map[string][]string, clusterName string) []types.KnoxNetworkPolicy {
	newPolicies := []types.KnoxNetworkPolicy{}

	// update policy name map
	policyNamesMap := map[string]bool{}
	for _, exist := range existingPolicies {
		policyNamesMap[exist.Metadata["name"]] = true
	}

	// enumerate discovered network policy
	for _, policy := range discoveredPolicies {
		// step 1: compare the total network policy spec
		if IsExistingPolicySpec(existingPolicies, policy) {
			continue
		}

		// step 2: generate policy name
		namedPolicy := GeneratePolicyName(policyNamesMap, policy, clusterName)

		// step 3-1: update existing HTTP rules: egress or ingress
		if strings.Contains(policy.Metadata["rule"], "toHTTPs") {
			updatedPolicy, updated := UpdateHTTP(namedPolicy, existingPolicies)
			if updated {
				namedPolicy = updatedPolicy
			}
		} else if strings.Contains(policy.Metadata["rule"], "matchLabels") {
			// step 3-2: update existing matchLabels+toPorts rules: egress or ingress
			updatedPolicy, updated := UpdateMatchLabels(policy, existingPolicies)
			if updated {
				namedPolicy = updatedPolicy
			}
		}

		// step 4: update existing CIDR(+toPorts) rules: egress or ingress
		if strings.Contains(policy.Metadata["rule"], "toCIDRs") {
			updatedPolicy, updated := UpdateToPorts(namedPolicy, existingPolicies)
			if updated {
				namedPolicy = updatedPolicy
			}
		}

		// step 5: update existing FQDN+toPorts rules: egress
		if strings.Contains(policy.Metadata["rule"], "toFQDNs") && policy.Metadata["type"] == "egress" {
			updatedPolicy, updated := UpdateToPorts(namedPolicy, existingPolicies)
			if updated {
				namedPolicy = updatedPolicy
			}
		}

		// step 6: update existing Entities rules: egress or ingress
		if strings.Contains(policy.Metadata["rule"], "Entities") {
			updatedPolicy, updated := UpdateEntity(namedPolicy, existingPolicies)
			if updated {
				namedPolicy = updatedPolicy
			}
		}

		// step 7: update existing Entities rules: egress
		if strings.Contains(policy.Metadata["rule"], "toServices") && policy.Metadata["type"] == "egress" {
			updatedPolicy, updated := UpdateService(namedPolicy, existingPolicies)
			if updated {
				namedPolicy = updatedPolicy
			}
		}

		// step 8: update status
		namedPolicy.Metadata["status"] = "latest"

		// step 9: update generated time
		namedPolicy.GeneratedTime = time.Now().Unix()

		newPolicies = append(newPolicies, namedPolicy)
	}

	// step 8: check if existing cidr matchs new fqdn
	updateExistCIDRtoNewFQDN(existingPolicies, newPolicies, dnsToIPs)

	sort.Slice(newPolicies, func(i, j int) bool {
		return newPolicies[i].Metadata["name"] < newPolicies[j].Metadata["name"]
	})

	return newPolicies
}
