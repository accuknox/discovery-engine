package core

import (
	"strings"

	"github.com/accuknox/knoxAutoPolicy/src/libs"
	types "github.com/accuknox/knoxAutoPolicy/src/types"

	"github.com/google/go-cmp/cmp"
)

// ============================= //
// == Get Latest Policy in DB == //
// ============================= //

// includeSelectorLabels function
func includeSelectorLabels(newSelectorLabels map[string]string, existSelectorLabels map[string]string) bool {
	includeSelector := true

	for k, v := range newSelectorLabels {
		if val, ok := existSelectorLabels[k]; !ok {
			includeSelector = false
			break
		} else {
			if val != v {
				includeSelector = false
				break
			}
		}
	}

	return includeSelector
}

// GetLatestCIDRPolicy function
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

// GetLastedFQDNPolicy function
func GetLastedFQDNPolicy(existingPolicies []types.KnoxNetworkPolicy, policy types.KnoxNetworkPolicy) []types.KnoxNetworkPolicy {
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

// GetLastedHTTPPolicy function
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
			matchLables := true
			for k, v := range newMatchLabels {
				if val, ok := existMatchLabels[k]; !ok {
					matchLables = false
					break
				} else {
					if val != v {
						matchLables = false
						break
					}
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

			if matchLables && matchToPorts {
				latestPolicies = append(latestPolicies, exist)
			}
		}
	}

	return latestPolicies
}

// GetLatestMatchLabelsPolicy function
func GetLatestMatchLabelsPolicy(existingPolicies []types.KnoxNetworkPolicy, policy types.KnoxNetworkPolicy) []types.KnoxNetworkPolicy {
	latestPolicies := []types.KnoxNetworkPolicy{}

	for _, exist := range existingPolicies {
		existPolicyType := exist.Metadata["type"]
		existRule := exist.Metadata["rule"]

		if exist.Metadata["namespace"] == policy.Metadata["namespace"] &&
			exist.Metadata["type"] == policy.Metadata["type"] &&
			strings.Contains(existRule, "matchLabels") &&
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

			matchLables := true

			// check target matchLabels
			for k, v := range newMatchLabels {
				if val, ok := existMatchLabels[k]; !ok {
					matchLables = false
					break
				} else {
					if val != v {
						matchLables = false
						break
					}
				}
			}

			if matchLables {
				latestPolicies = append(latestPolicies, exist)
			}
		}
	}

	return latestPolicies
}

// GetLatestEntityPolicy function
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

// GetLatestServicePolicy function
func GetLatestServicePolicy(existingPolicies []types.KnoxNetworkPolicy, policy types.KnoxNetworkPolicy) []types.KnoxNetworkPolicy {
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

// includedHTTPPath function
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

// UpdateHTTP function
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
				libs.UpdateOutdatedPolicy(latestPolicy.Metadata["name"], newPolicy.Metadata["name"])
				updated = true
			}

			continue
		}

		// annotate the outdated policy
		libs.UpdateOutdatedPolicy(latestPolicy.Metadata["name"], newPolicy.Metadata["name"])
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

// UpdateToPorts function
func UpdateToPorts(newPolicy types.KnoxNetworkPolicy, existingPolicies []types.KnoxNetworkPolicy) (types.KnoxNetworkPolicy, bool) {
	// case 1: if there is no latest, policy is new one
	latestPolicies := []types.KnoxNetworkPolicy{}
	if newPolicy.Metadata["rule"] == "toCIDRs+toPorts" {
		latestPolicies = GetLatestCIDRPolicy(existingPolicies, newPolicy)
	} else if newPolicy.Metadata["rule"] == "toFQDNs+toPorts" {
		latestPolicies = GetLastedFQDNPolicy(existingPolicies, newPolicy)
	} else {
		return newPolicy, true
	}

	if len(latestPolicies) == 0 {
		return newPolicy, true
	}

	newToPorts := []types.SpecPort{}
	if newPolicy.Metadata["type"] == "egress" {
		newToPorts = newPolicy.Spec.Egress[0].ToPorts
	} else {
		newToPorts = newPolicy.Spec.Ingress[0].ToPorts
	}

	updated := false

	for _, latestPolicy := range latestPolicies {
		existToPorts := []types.SpecPort{}
		if newPolicy.Metadata["type"] == "egress" {
			existToPorts = latestPolicy.Spec.Egress[0].ToPorts
		} else {
			existToPorts = latestPolicy.Spec.Ingress[0].ToPorts
		}

		includeAllRules := true
		for _, rule := range newToPorts {
			if !libs.ContainsElement(existToPorts, rule) {
				includeAllRules = false
			}
		}

		// case 2: policy has toPorts, which are all includes in latest one
		if includeAllRules {
			// case 2-1: policy has the lower selector count? outdated
			if len(newPolicy.Spec.Selector.MatchLabels) < len(latestPolicy.Spec.Selector.MatchLabels) {
				libs.UpdateOutdatedPolicy(latestPolicy.Metadata["name"], newPolicy.Metadata["name"])
				updated = true
			}

			continue // next existPolicy
		}

		// case 3: policy has toPorts, latest has toPorts or no toPorts --> move to new policy
		for _, toPort := range existToPorts {
			if !libs.ContainsElement(newToPorts, toPort) {
				newToPorts = append(newToPorts, toPort)
			}
		}

		// annotate the outdated policy
		libs.UpdateOutdatedPolicy(latestPolicy.Metadata["name"], newPolicy.Metadata["name"])
		updated = true
	}

	// at least one updated
	if updated {
		if newPolicy.Metadata["type"] == "egress" {
			newPolicy.Spec.Egress[0].ToPorts = newToPorts
		} else {
			newPolicy.Spec.Ingress[0].ToPorts = newToPorts
		}

		return newPolicy, true
	}

	return newPolicy, false
}

// UpdateMatchLabels function
func UpdateMatchLabels(newPolicy types.KnoxNetworkPolicy, existingPolicies []types.KnoxNetworkPolicy) (types.KnoxNetworkPolicy, bool) {
	// case 1: if there is no latest policy, policy is new one
	latestPolicies := GetLatestMatchLabelsPolicy(existingPolicies, newPolicy)
	if len(latestPolicies) == 0 {
		return newPolicy, true
	}

	newToPorts := []types.SpecPort{}
	newTargetLabelsCount := 0
	if newPolicy.Metadata["type"] == "egress" {
		newToPorts = newPolicy.Spec.Egress[0].ToPorts
		newTargetLabelsCount = len(newPolicy.Spec.Egress[0].MatchLabels)
	} else {
		newToPorts = newPolicy.Spec.Ingress[0].ToPorts
		newTargetLabelsCount = len(newPolicy.Spec.Ingress[0].MatchLabels)
	}

	updated := false

	for _, latestPolicy := range latestPolicies {
		existToPorts := []types.SpecPort{}
		existTargetLabelsCount := 0

		if newPolicy.Metadata["type"] == "egress" {
			existToPorts = latestPolicy.Spec.Egress[0].ToPorts
			existTargetLabelsCount = len(latestPolicy.Spec.Egress[0].MatchLabels)
		} else {
			existToPorts = latestPolicy.Spec.Ingress[0].ToPorts
			existTargetLabelsCount = len(latestPolicy.Spec.Ingress[0].MatchLabels)
		}

		includeAllRules := true
		for _, rule := range newToPorts {
			if !libs.ContainsElement(existToPorts, rule) {
				includeAllRules = false
			}
		}

		// case 2: policy has toPorts, which are all includes in latest one
		if includeAllRules {
			// case 2-1: policy has the lower selector count? outdated
			if len(newPolicy.Spec.Selector.MatchLabels) < len(latestPolicy.Spec.Selector.MatchLabels) ||
				newTargetLabelsCount < existTargetLabelsCount {
				// case 2-2: policy has the lower target matchLabels count? outdated
				libs.UpdateOutdatedPolicy(latestPolicy.Metadata["name"], newPolicy.Metadata["name"])
				updated = true
			}

			continue // next existPolicy
		}

		// case 3: policy has toPorts, latest has toPorts or no toPorts --> move to new policy
		for _, toPort := range existToPorts {
			if !libs.ContainsElement(newToPorts, toPort) {
				newToPorts = append(newToPorts, toPort)
			}
		}

		// annotate the outdated policy
		libs.UpdateOutdatedPolicy(latestPolicy.Metadata["name"], newPolicy.Metadata["name"])
		updated = true
	}

	// at least one updated
	if updated {
		if newPolicy.Metadata["type"] == "egress" {
			newPolicy.Spec.Egress[0].ToPorts = newToPorts
		} else {
			newPolicy.Spec.Ingress[0].ToPorts = newToPorts
		}

		return newPolicy, true
	}

	return newPolicy, false
}

// UpdateEntity function
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
				libs.UpdateOutdatedPolicy(latestPolicy.Metadata["name"], newPolicy.Metadata["name"])
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
		libs.UpdateOutdatedPolicy(latestPolicy.Metadata["name"], newPolicy.Metadata["name"])
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

// UpdateService function
func UpdateService(newPolicy types.KnoxNetworkPolicy, existingPolicies []types.KnoxNetworkPolicy) (types.KnoxNetworkPolicy, bool) {
	// case 1: if there is no latest, policy is new one
	latestPolicies := GetLatestServicePolicy(existingPolicies, newPolicy)
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
				libs.UpdateOutdatedPolicy(latestPolicy.Metadata["name"], newPolicy.Metadata["name"])
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
		libs.UpdateOutdatedPolicy(latestPolicy.Metadata["name"], newPolicy.Metadata["name"])
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

// ==================== //
// == Exact Matching == //
// ==================== //

// IsExistingPolicy function
func IsExistingPolicy(existingPolicies []types.KnoxNetworkPolicy, newPolicy types.KnoxNetworkPolicy) bool {
	for _, exist := range existingPolicies {
		if exist.Metadata["namespace"] == newPolicy.Metadata["namespace"] &&
			cmp.Equal(&exist.Spec, &newPolicy.Spec) {
			return true
		}
	}

	return false
}

// ==================================== //
// == Remove Policy Name Duplication == //
// ==================================== //

// ReplaceDuplcatedName function
func ReplaceDuplcatedName(existingPolicies []types.KnoxNetworkPolicy, policy types.KnoxNetworkPolicy) types.KnoxNetworkPolicy {
	egressPrefix := "autopol-egress-"
	ingressPrefix := "autopol-ingress-"

	existNames := []string{}
	for _, exist := range existingPolicies {
		existNames = append(existNames, exist.Metadata["name"])
	}

	name := policy.Metadata["name"]

	for libs.ContainsElement(existNames, name) {
		if strings.HasPrefix(name, egressPrefix) {
			name = egressPrefix + libs.RandSeq(10)
		} else {
			name = ingressPrefix + libs.RandSeq(10)
		}
	}

	policy.Metadata["name"] = name

	return policy
}

// GetToFQDNsFromNewDiscoveredPolicies function
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

// GetDomainNameFromMap function
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

// GetFQDNFromDomainName function
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

// updateExistCIDRtoNewFQDN function
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

						libs.UpdateOutdatedPolicy(existCIDR.Metadata["name"], fqdnPolicy.Metadata["name"])
					}
				}
			}
		}
	}
}

// ============================== //
// == Trace Old Network Policy == //
// ============================== //

// DeduplicatePolicies function
func DeduplicatePolicies(existingPolicies []types.KnoxNetworkPolicy, discoveredPolicies []types.KnoxNetworkPolicy, dnsToIPs map[string][]string) []types.KnoxNetworkPolicy {
	newPolicies := []types.KnoxNetworkPolicy{}

	for _, policy := range discoveredPolicies {
		// step 1: compare the total network policy spec
		if IsExistingPolicy(existingPolicies, policy) {
			continue
		}

		// step 2: update existing HTTP rules: egress or ingress
		if strings.Contains(policy.Metadata["rule"], "toHTTPs") {
			updated, valid := UpdateHTTP(policy, existingPolicies)
			if !valid {
				continue
			}
			policy = updated
		} else if strings.Contains(policy.Metadata["rule"], "matchLabels") {
			// step 3: update existing matchLabels+toPorts rules: egress or ingress
			updated, valid := UpdateMatchLabels(policy, existingPolicies)
			if !valid {
				continue
			}
			policy = updated
		}

		// step 4: update existing CIDR(+toPorts) rules: egress or ingress
		if strings.Contains(policy.Metadata["rule"], "toCIDRs") {
			updated, valid := UpdateToPorts(policy, existingPolicies)
			if !valid {
				continue
			}
			policy = updated
		}

		// step 5: update existing FQDN+toPorts rules: egress
		if strings.Contains(policy.Metadata["rule"], "toFQDNs") && policy.Metadata["rule"] == "egress" {
			updated, valid := UpdateToPorts(policy, existingPolicies)
			if !valid {
				continue
			}
			policy = updated
		}

		// step 6: update existing Entities rules: egress or ingress
		if strings.Contains(policy.Metadata["rule"], "Entities") {
			updated, valid := UpdateEntity(policy, existingPolicies)
			if !valid {
				continue
			}
			policy = updated
		}

		// step 7: update existing Entities rules: egress
		if strings.Contains(policy.Metadata["rule"], "toServices") && policy.Metadata["rule"] == "egress" {
			updated, valid := UpdateService(policy, existingPolicies)
			if !valid {
				continue
			}
			policy = updated
		}

		// step 8: check policy name confict
		namedPolicy := ReplaceDuplcatedName(existingPolicies, policy)

		newPolicies = append(newPolicies, namedPolicy)
	}

	// step 9: check if existing cidr matchs new fqdn
	updateExistCIDRtoNewFQDN(existingPolicies, newPolicies, dnsToIPs)

	return newPolicies
}
