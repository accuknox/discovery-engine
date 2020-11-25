package core

import (
	"strings"

	"github.com/accuknox/knoxAutoPolicy/src/libs"
	types "github.com/accuknox/knoxAutoPolicy/src/types"

	"github.com/google/go-cmp/cmp"
)

// GetExistingCIDRs function
func GetExistingCIDRs(existingPolicies []types.KnoxNetworkPolicy, inPorts []types.SpecPort) []string {
	cidrs := []string{}

	for _, exist := range existingPolicies { // already same selector policies
		for _, egress := range exist.Spec.Egress { // iterate egress
			for _, toCIDR := range egress.ToCIDRs { // iterate cidr
				// if toPorts exist
				if len(inPorts) > 0 && len(toCIDR.Ports) > 0 {
					portIncluded := true

					for _, port := range inPorts {
						if !libs.ContainsElement(toCIDR.Ports, port) {
							portIncluded = false
						}
					}

					if portIncluded {
						for _, cidr := range toCIDR.CIDRs {
							if !libs.ContainsElement(cidrs, cidr) {
								cidrs = append(cidrs, cidr)
							}
						}
					}
				} else if len(inPorts) == 0 && len(toCIDR.Ports) == 0 { // no toPorts exist
					for _, cidr := range toCIDR.CIDRs {
						if !libs.ContainsElement(cidrs, cidr) {
							cidrs = append(cidrs, cidr)
						}
					}
				}
			}
		}
	}

	return cidrs
}

// GetExistingDNS function
func GetExistingDNS(existingPolicies []types.KnoxNetworkPolicy, inPorts []types.SpecPort) []string {
	dnsNames := []string{}

	for _, exist := range existingPolicies { // already same selector policies
		for _, egress := range exist.Spec.Egress { // iterate egress
			for _, toFQDN := range egress.ToFQDNs { // iterate fqdn
				// if toPorts exist
				if len(inPorts) > 0 && len(toFQDN.ToPorts) > 0 {
					portIncluded := true

					for _, port := range inPorts {
						if !libs.ContainsElement(toFQDN.ToPorts, port) {
							portIncluded = false
						}
					}

					if portIncluded {
						for _, dns := range toFQDN.Matchnames {
							if !libs.ContainsElement(dnsNames, dns) {
								dnsNames = append(dnsNames, dns)
							}
						}
					}
				} else if len(inPorts) == 0 && len(toFQDN.ToPorts) == 0 { // no toPorts exist
					for _, dns := range toFQDN.Matchnames {
						if !libs.ContainsElement(dnsNames, dns) {
							dnsNames = append(dnsNames, dns)
						}
					}
				}
			}
		}
	}

	return dnsNames
}

// RefinePolicy function
func RefinePolicy(existingPolicies []types.KnoxNetworkPolicy, policy types.KnoxNetworkPolicy) (types.KnoxNetworkPolicy, bool) {
	for i, egress := range policy.Spec.Egress {
		if len(egress.ToCIDRs) > 0 {
			// ========= //
			// CIDR rule //
			// ========= //

			for j, toCIDR := range egress.ToCIDRs {
				existingCidrs := GetExistingCIDRs(existingPolicies, toCIDR.Ports)

				newCidrs := []string{}
				for _, cidr := range toCIDR.CIDRs {
					if !libs.ContainsElement(existingCidrs, cidr) {
						newCidrs = append(newCidrs, cidr)
					}
				}

				// if there is no new cidrs, its duplication
				if len(newCidrs) == 0 {
					return types.KnoxNetworkPolicy{}, false
				}

				policy.Spec.Egress[i].ToCIDRs[j].CIDRs = newCidrs
			}
		} else if len(egress.ToFQDNs) > 0 {
			// ========= //
			// FQDN rule //
			// ========= //

			for j, toFQDN := range egress.ToFQDNs {
				existingDNSes := GetExistingDNS(existingPolicies, toFQDN.ToPorts)

				newDNS := []string{}
				for _, dns := range toFQDN.Matchnames {
					if !libs.ContainsElement(existingDNSes, dns) {
						newDNS = append(newDNS, dns)
					}
				}

				// if there is no new dns, its duplication
				if len(newDNS) == 0 {
					return types.KnoxNetworkPolicy{}, false
				}

				policy.Spec.Egress[i].ToFQDNs[j].Matchnames = newDNS
			}
		}
	}

	return policy, true
}

// FilteredSpecs function
func FilteredSpecs(existingPolicies []types.KnoxNetworkPolicy, policy types.KnoxNetworkPolicy) []types.KnoxNetworkPolicy {
	policies := []types.KnoxNetworkPolicy{}

	for _, exist := range existingPolicies {
		// check selector
		if cmp.Equal(&exist.Spec.Selector, &policy.Spec.Selector) {
			// check egress/ingress
			if len(policy.Spec.Egress) > 0 && len(exist.Spec.Egress) > 0 { // egress
				policies = append(policies, exist)
			} else if len(policy.Spec.Ingress) > 0 && len(exist.Spec.Ingress) > 0 { // ingress
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
	egressPrefix := "autogen-egress"
	ingressPrefix := "autogen-ingress"

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

// DeduplicatePolicies function
func DeduplicatePolicies(existingPolicies []types.KnoxNetworkPolicy, discoveredPolicies []types.KnoxNetworkPolicy) []types.KnoxNetworkPolicy {
	newPolicies := []types.KnoxNetworkPolicy{}

	for _, policy := range discoveredPolicies {
		// step 1: compare the total network policy spec
		if IsExistedPolicy(existingPolicies, policy) {
			continue
		}

		// step 2: compare the inside rules
		filtered := FilteredSpecs(existingPolicies, policy)
		refined, valid := RefinePolicy(filtered, policy)
		if !valid {
			continue
		}

		// step 3: check policy name confict
		namedPolicy := ReplaceDuplcatedName(existingPolicies, refined)

		newPolicies = append(newPolicies, namedPolicy)
	}

	return newPolicies
}
