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

		// case 4: policy has toPorts, which are includes in latest --> skip
		toPorts := newPolicy.Spec.Egress[0].ToPorts
		latestToPorts := newPolicy.Spec.Egress[0].ToPorts
		if IncludeToPorts(toPorts, latestToPorts) {
			return newPolicy, false
		}

		// case 5: policy has toPorts, latest has toPorts or no toPorts --> move to new policy
		for _, toPort := range latestCidrs.Spec.Egress[0].ToPorts {
			if !libs.ContainsElement(toPorts, toPort) {
				toPorts = append(toPorts, toPort)
			}
		}
		newPolicy.Spec.Egress[0].ToPorts = toPorts

		// annotate the outdated cidr policy
		err := libs.UpdateOutdatedPolicy(latestCidrs.Metadata["name"], newPolicy.Metadata["name"])
		if err != nil {
			log.Error().Msg(err.Error())
		}

		return newPolicy, true
	}

	// if ingress cidr don't need to care about it beacuse there is no toPorts
	return newPolicy, true
}

// UpdateFQDN ...
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
		toPorts := newPolicy.Spec.Egress[0].ToPorts
		latestToPorts := newPolicy.Spec.Egress[0].ToPorts
		if IncludeToPorts(toPorts, latestToPorts) {
			return newPolicy, false
		}

		// case 4: policy has toPorts, latest has toPorts or no toPorts --> move to this policy
		for _, toPort := range latestFQDNs.Spec.Egress[0].ToPorts {
			if !libs.ContainsElement(toPorts, toPort) {
				toPorts = append(toPorts, toPort)
			}
		}
		newPolicy.Spec.Egress[0].ToPorts = toPorts

		// annotate the outdated fqdn policy
		libs.UpdateOutdatedPolicy(latestFQDNs.Metadata["name"], newPolicy.Metadata["name"])

		return newPolicy, true
	}

	// if ingress fqdn don't need to care about,
	return newPolicy, true
}

// GetSpecs function
func GetSpecs(existingPolicies []types.KnoxNetworkPolicy, policy types.KnoxNetworkPolicy) []types.KnoxNetworkPolicy {
	policies := []types.KnoxNetworkPolicy{}

	for _, exist := range existingPolicies {
		// check selector
		if cmp.Equal(&exist.Spec.Selector, &policy.Spec.Selector) {
			if exist.Metadata["type"] == "egress" { // egress
				policies = append(policies, exist)
			} else { // ingress
				policies = append(policies, exist)
			}
		}
	}

	return policies
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

// getToFQDNsFromNewDiscoveredPolicies function
func getToFQDNsFromNewDiscoveredPolicies(policy types.KnoxNetworkPolicy, newPolicies []types.KnoxNetworkPolicy) []types.KnoxNetworkPolicy {
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

// getDomainNameFromMap function
func getDomainNameFromMap(inIP string, dnsToIPs map[string][]string) string {
	for domain, ips := range dnsToIPs {
		for _, ip := range ips {
			if inIP == ip {
				return domain
			}
		}
	}

	return ""
}

// existDomainNameInFQDN function
func existDomainNameInFQDN(domainName string, fqdnPolicies []types.KnoxNetworkPolicy) (types.KnoxNetworkPolicy, bool) {
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
				toFQDNs := getToFQDNsFromNewDiscoveredPolicies(existCIDR, newPolicies)

				for _, cidr := range toCidr.CIDRs { // we know the number of cidr is 1
					ip := strings.Split(cidr, "/")[0]
					// get domain name from the map
					domainName := getDomainNameFromMap(ip, dnsToIPs)

					// check domain name in fqdn
					if fqdnPolicy, matched := existDomainNameInFQDN(domainName, toFQDNs); matched {
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

		// step 2: compare the inside CIDR rules
		if strings.Contains(policy.Metadata["rule"], "toCIDRs") {
			updated, valid := UpdateCIDR(policy, existingPolicies)
			if !valid {
				continue
			}
			policy = updated
		}

		// step 3: compare the inside FQDN rules
		if strings.Contains(policy.Metadata["rule"], "toFQDNs") {
			updated, valid := UpdateFQDN(policy, existingPolicies)
			if !valid {
				continue
			}
			policy = updated
		}

		// step 3: check policy name confict
		namedPolicy := ReplaceDuplcatedName(existingPolicies, policy)

		newPolicies = append(newPolicies, namedPolicy)
	}

	// step 4: check existed cidr -> new fqdn
	updateExistCIDRtoNewFQDN(existingPolicies, newPolicies, dnsToIPs)

	return newPolicies
}
