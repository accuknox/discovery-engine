package core

import (
	"strings"

	"github.com/accuknox/knoxAutoPolicy/src/libs"
	types "github.com/accuknox/knoxAutoPolicy/src/types"
	"github.com/rs/zerolog/log"

	"github.com/google/go-cmp/cmp"
)

// GetLatestCIDRs function
func GetLatestCIDRs(existingPolicies []types.KnoxNetworkPolicy, policy types.KnoxNetworkPolicy) (types.KnoxNetworkPolicy, bool) {
	for _, exist := range existingPolicies {
		existStatus := exist.Metadata["status"]
		existPolicyType := exist.Metadata["type"]
		existRule := exist.Metadata["rule"]

		if cmp.Equal(&exist.Spec.Selector, &policy.Spec.Selector) &&
			existPolicyType == policy.Metadata["type"] &&
			strings.Contains(existRule, "toCIDRs") &&
			existStatus == "latest" {

			// check cidr list
			included := true
			for _, cidr := range policy.Spec.Egress[0].ToCIDRs[0].CIDRs {
				for _, existCidr := range exist.Spec.Egress[0].ToCIDRs[0].CIDRs {
					if cidr != existCidr {
						included = false
					}
				}
			}

			if included {
				return exist, true
			}
		}
	}

	return types.KnoxNetworkPolicy{}, false
}

// GetLastedFQDNs function
func GetLastedFQDNs(existingPolicies []types.KnoxNetworkPolicy, policy types.KnoxNetworkPolicy) (types.KnoxNetworkPolicy, bool) {
	for _, exist := range existingPolicies {
		existStatus := exist.Metadata["status"]
		existPolicyType := exist.Metadata["type"]
		existRule := exist.Metadata["rule"]

		if cmp.Equal(&exist.Spec.Selector, &policy.Spec.Selector) &&
			existPolicyType == policy.Metadata["type"] &&
			strings.Contains(existRule, "toFQDNs") &&
			existStatus == "latest" {

			// check cidr list
			included := true
			for _, dns := range policy.Spec.Egress[0].ToFQDNs[0].MatchNames {
				for _, existDNS := range exist.Spec.Egress[0].ToFQDNs[0].MatchNames {
					if dns != existDNS {
						included = false
					}
				}
			}

			if included {
				return exist, true
			}
		}
	}

	return types.KnoxNetworkPolicy{}, false
}

// GetLastedHTTP function
func GetLastedHTTP(existingPolicies []types.KnoxNetworkPolicy, newPolicy types.KnoxNetworkPolicy) (types.KnoxNetworkPolicy, bool) {
	for _, exist := range existingPolicies {
		existStatus := exist.Metadata["status"]
		existPolicyType := exist.Metadata["type"]
		existRule := exist.Metadata["rule"]

		if cmp.Equal(&exist.Spec.Selector, &newPolicy.Spec.Selector) &&
			existPolicyType == newPolicy.Metadata["type"] &&
			strings.Contains(existRule, "toHTTPs") &&
			existStatus == "latest" {

			// check matchLabels & toPorts
			newMatchLabels := map[string]string{}
			newToPorts := []types.SpecPort{}

			existMatchLabels := map[string]string{}
			existToPorts := []types.SpecPort{}

			if existPolicyType == "egress" {
				newMatchLabels = newPolicy.Spec.Egress[0].MatchLabels
				newToPorts = newPolicy.Spec.Egress[0].ToPorts

				existMatchLabels = exist.Spec.Egress[0].MatchLabels
				existToPorts = exist.Spec.Egress[0].ToPorts
			} else {
				newMatchLabels = newPolicy.Spec.Ingress[0].MatchLabels
				newToPorts = newPolicy.Spec.Ingress[0].ToPorts

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
				if !libs.ContainsElement(existToPorts, toPort) {
					matchToPorts = false
					break
				}
			}

			if matchLables && matchToPorts {
				return exist, true
			}
		}
	}

	return types.KnoxNetworkPolicy{}, false
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

// UpdateCIDR function
func UpdateCIDR(newPolicy types.KnoxNetworkPolicy, existingPolicies []types.KnoxNetworkPolicy) (types.KnoxNetworkPolicy, bool) {
	if newPolicy.Metadata["type"] == "egress" { // egress
		// case 1: if this policy is new one
		latestCidrs, exist := GetLatestCIDRs(existingPolicies, newPolicy)
		if !exist {
			return newPolicy, true
		}

		// case 2: policy has no toPorts, latest has no toPorts --> cannot be happen (exact match)

		// case 3: policy has no toPorts, latest has toPorts --> latest has the higher priority
		if len(newPolicy.Spec.Egress[0].ToPorts) == 0 && len(latestCidrs.Spec.Egress[0].ToPorts) > 0 {
			return newPolicy, false
		}

		// case 4: policy has toPorts, which are includes all in latest --> skip
		newToPorts := newPolicy.Spec.Egress[0].ToPorts
		existingToPorts := latestCidrs.Spec.Egress[0].ToPorts
		if IncludeToPorts(newToPorts, existingToPorts) {
			return newPolicy, false
		}

		// case 5: policy has toPorts, latest has toPorts or no toPorts --> move to new policy
		for _, existingToPort := range existingToPorts {
			if !libs.ContainsElement(newToPorts, existingToPort) {
				newToPorts = append(newToPorts, existingToPort)
			}
		}
		newPolicy.Spec.Egress[0].ToPorts = newToPorts

		// annotate the outdated cidr policy
		err := libs.UpdateOutdatedPolicy(latestCidrs.Metadata["name"], newPolicy.Metadata["name"])
		if err != nil {
			log.Error().Msg(err.Error())
			return newPolicy, true
		}

		return newPolicy, true
	}

	// if ingress cidr don't need to care about it beacuse there is no toPorts
	return newPolicy, true
}

// UpdateFQDN function
func UpdateFQDN(newPolicy types.KnoxNetworkPolicy, existingPolicies []types.KnoxNetworkPolicy) (types.KnoxNetworkPolicy, bool) {
	if newPolicy.Metadata["type"] == "egress" { // egress
		// case 1: policy is new one
		latestFQDNs, exist := GetLastedFQDNs(existingPolicies, newPolicy)
		if !exist {
			return newPolicy, true
		}

		// case 2: policy has no toPorts, latest has no toPorts --> cannot be happen (exact match)

		// case 3: policy has no toPorts, latest has toPorts --> latest has the higher priority
		if len(newPolicy.Spec.Egress[0].ToPorts) == 0 && len(latestFQDNs.Spec.Egress[0].ToPorts) > 0 {
			return newPolicy, false
		}

		// case 4: policy has toPorts, which are includes in latest --> skip
		newToPorts := newPolicy.Spec.Egress[0].ToPorts
		existingToPorts := latestFQDNs.Spec.Egress[0].ToPorts
		if IncludeToPorts(newToPorts, existingToPorts) {
			return newPolicy, false
		}

		// case 5: policy has toPorts, latest has toPorts or no toPorts --> move to this policy
		for _, existingToPort := range existingToPorts {
			if !libs.ContainsElement(newToPorts, existingToPort) {
				newToPorts = append(newToPorts, existingToPort)
			}
		}
		newPolicy.Spec.Egress[0].ToPorts = newToPorts

		// annotate the outdated fqdn policy
		err := libs.UpdateOutdatedPolicy(latestFQDNs.Metadata["name"], newPolicy.Metadata["name"])
		if err != nil {
			log.Error().Msg(err.Error())
			return newPolicy, true
		}

		return newPolicy, true
	}

	// if ingress fqdn don't need to care about,
	return newPolicy, true
}

// UpdateHTTP function
func UpdateHTTP(newPolicy types.KnoxNetworkPolicy, existingPolicies []types.KnoxNetworkPolicy) (types.KnoxNetworkPolicy, bool) {
	// case 1: if there is no latest, policy is new one
	latestHTTP, exist := GetLastedHTTP(existingPolicies, newPolicy)
	if !exist {
		return newPolicy, true
	}

	newHTTP := []types.SpecHTTP{}
	existingHTTP := []types.SpecHTTP{}

	if newPolicy.Metadata["type"] == "egress" {
		newHTTP = newPolicy.Spec.Egress[0].ToHTTPs
		existingHTTP = latestHTTP.Spec.Egress[0].ToHTTPs
	} else {
		newHTTP = newPolicy.Spec.Ingress[0].ToHTTPs
		existingHTTP = latestHTTP.Spec.Ingress[0].ToHTTPs
	}

	// case 2: policy has toHTTPs, which are all includes in latest --> skip
	includeAllRules := true
	for _, rule := range newHTTP {
		if !libs.ContainsElement(existingHTTP, rule) {
			includeAllRules = false
		}
	}

	if includeAllRules {
		return newPolicy, false
	}

	// case 3: policy has toHTTPs, latest has toHTTPs or no toHTTPs --> move to new policy
	for _, oldHTTP := range existingHTTP {
		if !libs.ContainsElement(newHTTP, oldHTTP) {
			newHTTP = append(newHTTP, oldHTTP)
		}
	}

	if newPolicy.Metadata["type"] == "egress" {
		newPolicy.Spec.Egress[0].ToHTTPs = newHTTP
	} else {
		newPolicy.Spec.Ingress[0].ToHTTPs = newHTTP
	}

	// annotate the outdated fqdn policy
	err := libs.UpdateOutdatedPolicy(latestHTTP.Metadata["name"], newPolicy.Metadata["name"])
	if err != nil {
		log.Error().Msg(err.Error())
		return newPolicy, true
	}

	return newPolicy, true
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
	egressPrefix := "autopol-egress"
	ingressPrefix := "autopol-ingress"

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

		// step 2: update existing CIDR rules
		if strings.Contains(policy.Metadata["rule"], "toCIDRs") {
			updated, valid := UpdateCIDR(policy, existingPolicies)
			if !valid {
				continue
			}
			policy = updated
		}

		// step 3: update existing FQDN rules
		if strings.Contains(policy.Metadata["rule"], "toFQDNs") {
			updated, valid := UpdateFQDN(policy, existingPolicies)
			if !valid {
				continue
			}
			policy = updated
		}

		// step 4: update existing HTTP rules
		if strings.Contains(policy.Metadata["rule"], "toHTTPs") {
			updated, valid := UpdateHTTP(policy, existingPolicies)
			if !valid {
				continue
			}
			policy = updated
		}

		// step 5: check policy name confict
		namedPolicy := ReplaceDuplcatedName(existingPolicies, policy)

		newPolicies = append(newPolicies, namedPolicy)
	}

	// step 6: check if existing cidr matchs new fqdn
	updateExistCIDRtoNewFQDN(existingPolicies, newPolicies, dnsToIPs)

	return newPolicies
}
