package core

import (
	"strings"

	"github.com/accuknox/knoxAutoPolicy/src/libs"
	types "github.com/accuknox/knoxAutoPolicy/src/types"
	"github.com/rs/zerolog/log"

	"github.com/google/go-cmp/cmp"
)

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
		existStatus := exist.Metadata["status"]
		existPolicyType := exist.Metadata["type"]
		existRule := exist.Metadata["rule"]

		if existPolicyType == policy.Metadata["type"] &&
			existRule == policy.Metadata["rule"] &&
			existStatus == "latest" {

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
		existStatus := exist.Metadata["status"]
		existPolicyType := exist.Metadata["type"]
		existRule := exist.Metadata["rule"]

		if existPolicyType == policy.Metadata["type"] &&
			existRule == policy.Metadata["rule"] &&
			existStatus == "latest" {

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

// GetLastedHTTP function
func GetLastedHTTP(existingPolicies []types.KnoxNetworkPolicy, policy types.KnoxNetworkPolicy) []types.KnoxNetworkPolicy {
	latestPolicies := []types.KnoxNetworkPolicy{}

	for _, exist := range existingPolicies {
		existStatus := exist.Metadata["status"]
		existPolicyType := exist.Metadata["type"]
		existRule := exist.Metadata["rule"]

		if existPolicyType == policy.Metadata["type"] &&
			strings.Contains(existRule, "toHTTPs") &&
			existStatus == "latest" {

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

			matchLables := true
			matchToPorts := true

			// 1. check matchLabels
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
		existStatus := exist.Metadata["status"]
		existPolicyType := exist.Metadata["type"]
		existRule := exist.Metadata["rule"]

		if existPolicyType == policy.Metadata["type"] &&
			strings.Contains(existRule, "matchLabels") &&
			existStatus == "latest" {

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

// IncludeToPorts function
func IncludeToPorts(policyToPorts, latestToPorts []types.SpecPort) bool {
	included := true

	for _, toPort := range policyToPorts {
		if !libs.ContainsElement(latestToPorts, toPort) {
			included = false
		}
	}

	return included
}

// UpdateHTTP function
func UpdateHTTP(newPolicy types.KnoxNetworkPolicy, existingPolicies []types.KnoxNetworkPolicy) (types.KnoxNetworkPolicy, bool) {
	// case 1: if there is no latest, policy is new one
	latestPolicies := GetLastedHTTP(existingPolicies, newPolicy)
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

		// case 2: policy has toHTTPs, which are all includes in latest --> skip
		includeAllRules := true
		for _, rule := range newHTTP {
			if !libs.ContainsElement(existHTTP, rule) {
				includeAllRules = false
			}
		}

		if includeAllRules {
			// case 2-1: policy has the lower selector count? outdated
			if len(newPolicy.Spec.Selector.MatchLabels) < len(latestPolicy.Spec.Selector.MatchLabels) {
				err := libs.UpdateOutdatedPolicy(latestPolicy.Metadata["name"], newPolicy.Metadata["name"])
				if err != nil {
					log.Error().Msg(err.Error())
				}
			}

			continue
		}

		// case 3: policy has toHTTPs, latest has toHTTPs or no toHTTPs --> move to new policy
		for _, oldHTTP := range existHTTP {
			if !libs.ContainsElement(newHTTP, oldHTTP) {
				newHTTP = append(newHTTP, oldHTTP)
			}
		}

		// annotate the outdated fqdn policy
		err := libs.UpdateOutdatedPolicy(latestPolicy.Metadata["name"], newPolicy.Metadata["name"])
		if err != nil {
			log.Error().Msg(err.Error())
			return newPolicy, true
		}

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
	} else {
		return newPolicy, false
	}
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
				err := libs.UpdateOutdatedPolicy(latestPolicy.Metadata["name"], newPolicy.Metadata["name"])
				if err != nil {
					log.Error().Msg(err.Error())
				}
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
		err := libs.UpdateOutdatedPolicy(latestPolicy.Metadata["name"], newPolicy.Metadata["name"])
		if err != nil {
			log.Error().Msg(err.Error())
		}

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
	} else {
		return newPolicy, false
	}
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
				err := libs.UpdateOutdatedPolicy(latestPolicy.Metadata["name"], newPolicy.Metadata["name"])
				if err != nil {
					log.Error().Msg(err.Error())
				}
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
		err := libs.UpdateOutdatedPolicy(latestPolicy.Metadata["name"], newPolicy.Metadata["name"])
		if err != nil {
			log.Error().Msg(err.Error())
		}

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
	} else {
		return newPolicy, false
	}
}

// IsExistedPolicy function
func IsExistedPolicy(existingPolicies []types.KnoxNetworkPolicy, inPolicy types.KnoxNetworkPolicy) bool {
	for _, policy := range existingPolicies {
		if cmp.Equal(&policy.Spec, &inPolicy.Spec) {
			return true
		}
	}

	return false
}

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

// DeduplicatePolicies function
func DeduplicatePolicies(existingPolicies []types.KnoxNetworkPolicy, discoveredPolicies []types.KnoxNetworkPolicy, dnsToIPs map[string][]string) []types.KnoxNetworkPolicy {
	newPolicies := []types.KnoxNetworkPolicy{}

	for _, policy := range discoveredPolicies {
		// step 1: compare the total network policy spec
		if IsExistedPolicy(existingPolicies, policy) {
			continue
		}

		// step 2: update existing matchLabels+toPorts rules
		if strings.Contains(policy.Metadata["rule"], "matchLabels") {
			updated, valid := UpdateMatchLabels(policy, existingPolicies)
			if !valid {
				continue
			}
			policy = updated
		}

		// step 3: update existing CIDR+toPorts rules
		if policy.Metadata["rule"] == "toCIDRs+toPorts" && policy.Metadata["type"] == "egress" {
			updated, valid := UpdateToPorts(policy, existingPolicies)
			if !valid {
				continue
			}
			policy = updated
		}

		// step 4: update existing FQDN+toPorts rules
		if policy.Metadata["rule"] == "toFQDNs+toPorts" && policy.Metadata["type"] == "egress" {
			updated, valid := UpdateToPorts(policy, existingPolicies)
			if !valid {
				continue
			}
			policy = updated
		}

		// step 5: update existing HTTP rules
		if strings.Contains(policy.Metadata["rule"], "toHTTPs") {
			updated, valid := UpdateHTTP(policy, existingPolicies)
			if !valid {
				continue
			}
			policy = updated
		}

		// step 6: check policy name confict
		namedPolicy := ReplaceDuplcatedName(existingPolicies, policy)

		newPolicies = append(newPolicies, namedPolicy)
	}

	// step 7: check if existing cidr matchs new fqdn
	updateExistCIDRtoNewFQDN(existingPolicies, newPolicies, dnsToIPs)

	return newPolicies
}
