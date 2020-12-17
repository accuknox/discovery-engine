package core

import (
	"testing"

	types "github.com/accuknox/knoxAutoPolicy/src/types"
	"github.com/stretchr/testify/assert"
)

func TestGetLatestCIDRs(t *testing.T) {
	exist1 := types.KnoxNetworkPolicy{
		Metadata: map[string]string{
			"status": "latest",
			"type":   "egress",
			"rule":   "toCIDRs",
		},

		Spec: types.Spec{
			Selector: types.Selector{
				MatchLabels: map[string]string{
					"app": "test1",
				},
			},

			Egress: []types.Egress{
				types.Egress{
					ToCIDRs: []types.SpecCIDR{
						types.SpecCIDR{
							CIDRs: []string{"10.0.0.1/32"},
						},
					},
				},
			},
		},
	}

	exist2 := types.KnoxNetworkPolicy{
		Metadata: map[string]string{
			"status": "latest",
			"type":   "egress",
			"rule":   "toCIDRs",
		},

		Spec: types.Spec{
			Selector: types.Selector{
				MatchLabels: map[string]string{
					"app": "test2",
				},
			},

			Egress: []types.Egress{
				types.Egress{
					ToCIDRs: []types.SpecCIDR{
						types.SpecCIDR{
							CIDRs: []string{"10.0.0.1/32"},
						},
					},
				},
			},
		},
	}

	cidrPolicy := types.KnoxNetworkPolicy{
		Metadata: map[string]string{
			"status": "latest",
			"type":   "egress",
			"rule":   "toCIDRs",
		},

		Spec: types.Spec{
			Selector: types.Selector{
				MatchLabels: map[string]string{
					"app": "test1",
				},
			},

			Egress: []types.Egress{
				types.Egress{
					ToCIDRs: []types.SpecCIDR{
						types.SpecCIDR{
							CIDRs: []string{"10.0.0.1/32"},
						},
					},
				},
			},
		},
	}

	existings := []types.KnoxNetworkPolicy{exist1, exist2}

	result := GetLatestCIDRPolicy(existings, cidrPolicy)
	assert.Equal(t, result, exist1, "they should be equal")
}

func TestGetLastedFQDNs(t *testing.T) {
	exist1 := types.KnoxNetworkPolicy{
		Metadata: map[string]string{
			"status": "latest",
			"type":   "egress",
			"rule":   "toFQDNs",
		},

		Spec: types.Spec{
			Selector: types.Selector{
				MatchLabels: map[string]string{
					"app": "test1",
				},
			},

			Egress: []types.Egress{
				types.Egress{
					ToFQDNs: []types.SpecFQDN{
						types.SpecFQDN{
							MatchNames: []string{"test.com"},
						},
					},
				},
			},
		},
	}

	exist2 := types.KnoxNetworkPolicy{
		Metadata: map[string]string{
			"status": "latest",
			"type":   "egress",
			"rule":   "toFQDNs",
		},

		Spec: types.Spec{
			Selector: types.Selector{
				MatchLabels: map[string]string{
					"app": "test2",
				},
			},

			Egress: []types.Egress{
				types.Egress{
					ToFQDNs: []types.SpecFQDN{
						types.SpecFQDN{
							MatchNames: []string{"test.com"},
						},
					},
				},
			},
		},
	}

	fqdnPolicy := types.KnoxNetworkPolicy{
		Metadata: map[string]string{
			"status": "latest",
			"type":   "egress",
			"rule":   "toFQDNs",
		},

		Spec: types.Spec{
			Selector: types.Selector{
				MatchLabels: map[string]string{
					"app": "test1",
				},
			},

			Egress: []types.Egress{
				types.Egress{
					ToFQDNs: []types.SpecFQDN{
						types.SpecFQDN{
							MatchNames: []string{"test.com"},
						},
					},
				},
			},
		},
	}

	existings := []types.KnoxNetworkPolicy{exist1, exist2}

	result := GetLastedFQDNPolicy(existings, fqdnPolicy)
	assert.Equal(t, result, exist1, "they should be equal")
}

func TestUpdateCIDR(t *testing.T) {
	exist1 := types.KnoxNetworkPolicy{
		Metadata: map[string]string{
			"status": "latest",
			"type":   "egress",
			"rule":   "toCIDRs+toPorts",
		},

		Spec: types.Spec{
			Selector: types.Selector{
				MatchLabels: map[string]string{
					"app": "test1",
				},
			},

			Egress: []types.Egress{
				types.Egress{
					ToCIDRs: []types.SpecCIDR{
						types.SpecCIDR{
							CIDRs: []string{"10.0.0.1/32"},
						},
					},
					ToPorts: []types.SpecPort{
						types.SpecPort{
							Port:     "80",
							Protocol: "tcp",
						},
					},
				},
			},
		},
	}

	cidrPolicy := types.KnoxNetworkPolicy{
		Metadata: map[string]string{
			"status": "latest",
			"type":   "egress",
			"rule":   "toCIDRs+toPorts",
		},

		Spec: types.Spec{
			Selector: types.Selector{
				MatchLabels: map[string]string{
					"app": "test1",
				},
			},

			Egress: []types.Egress{
				types.Egress{
					ToCIDRs: []types.SpecCIDR{
						types.SpecCIDR{
							CIDRs: []string{"10.0.0.1/32"},
						},
					},
					ToPorts: []types.SpecPort{
						types.SpecPort{
							Port:     "443",
							Protocol: "tcp",
						},
					},
				},
			},
		},
	}

	expectedPolicy := types.KnoxNetworkPolicy{
		Metadata: map[string]string{
			"status": "latest",
			"type":   "egress",
			"rule":   "toCIDRs+toPorts",
		},

		Spec: types.Spec{
			Selector: types.Selector{
				MatchLabels: map[string]string{
					"app": "test1",
				},
			},

			Egress: []types.Egress{
				types.Egress{
					ToCIDRs: []types.SpecCIDR{
						types.SpecCIDR{
							CIDRs: []string{"10.0.0.1/32"},
						},
					},
					ToPorts: []types.SpecPort{
						types.SpecPort{
							Port:     "443",
							Protocol: "tcp",
						},
						types.SpecPort{
							Port:     "80",
							Protocol: "tcp",
						},
					},
				},
			},
		},
	}

	existings := []types.KnoxNetworkPolicy{exist1}

	result, valid := UpdateToPorts(cidrPolicy, existings)
	if valid {
		assert.Equal(t, result, expectedPolicy, "they should be equal")
	} else {
		assert.Equal(t, valid, true, "they should be equal")
	}
}

func TestUpdateFQDN(t *testing.T) {
	exist1 := types.KnoxNetworkPolicy{
		Metadata: map[string]string{
			"status": "latest",
			"type":   "egress",
			"rule":   "toFQDNs+toPorts",
		},

		Spec: types.Spec{
			Selector: types.Selector{
				MatchLabels: map[string]string{
					"app": "test1",
				},
			},

			Egress: []types.Egress{
				types.Egress{
					ToFQDNs: []types.SpecFQDN{
						types.SpecFQDN{
							MatchNames: []string{"test.com"},
						},
					},
					ToPorts: []types.SpecPort{
						types.SpecPort{
							Port:     "80",
							Protocol: "tcp",
						},
					},
				},
			},
		},
	}

	fqdnPolicy := types.KnoxNetworkPolicy{
		Metadata: map[string]string{
			"status": "latest",
			"type":   "egress",
			"rule":   "toFQDNs+toPorts",
		},

		Spec: types.Spec{
			Selector: types.Selector{
				MatchLabels: map[string]string{
					"app": "test1",
				},
			},

			Egress: []types.Egress{
				types.Egress{
					ToFQDNs: []types.SpecFQDN{
						types.SpecFQDN{
							MatchNames: []string{"test.com"},
						},
					},
					ToPorts: []types.SpecPort{
						types.SpecPort{
							Port:     "443",
							Protocol: "tcp",
						},
					},
				},
			},
		},
	}

	expectedPolicy := types.KnoxNetworkPolicy{
		Metadata: map[string]string{
			"status": "latest",
			"type":   "egress",
			"rule":   "toFQDNs+toPorts",
		},

		Spec: types.Spec{
			Selector: types.Selector{
				MatchLabels: map[string]string{
					"app": "test1",
				},
			},

			Egress: []types.Egress{
				types.Egress{
					ToFQDNs: []types.SpecFQDN{
						types.SpecFQDN{
							MatchNames: []string{"test.com"},
						},
					},
					ToPorts: []types.SpecPort{
						types.SpecPort{
							Port:     "443",
							Protocol: "tcp",
						},
						types.SpecPort{
							Port:     "80",
							Protocol: "tcp",
						},
					},
				},
			},
		},
	}

	existings := []types.KnoxNetworkPolicy{exist1}

	result, valid := UpdateToPorts(fqdnPolicy, existings)
	if valid {
		assert.Equal(t, result, expectedPolicy, "they should be equal")
	} else {
		assert.Equal(t, valid, true, "they should be equal")
	}
}

func TestIsExistedPolicy(t *testing.T) {
	exist1 := types.KnoxNetworkPolicy{
		Metadata: map[string]string{
			"status": "latest",
			"type":   "egress",
			"rule":   "toFQDNs+toPorts",
		},

		Spec: types.Spec{
			Selector: types.Selector{
				MatchLabels: map[string]string{
					"app": "test1",
				},
			},

			Egress: []types.Egress{
				types.Egress{
					ToFQDNs: []types.SpecFQDN{
						types.SpecFQDN{
							MatchNames: []string{"test.com"},
						},
					},
					ToPorts: []types.SpecPort{
						types.SpecPort{
							Port:     "80",
							Protocol: "tcp",
						},
					},
				},
			},
		},
	}

	newPolicy := types.KnoxNetworkPolicy{
		Metadata: map[string]string{
			"status": "latest",
			"type":   "egress",
			"rule":   "toFQDNs+toPorts",
		},

		Spec: types.Spec{
			Selector: types.Selector{
				MatchLabels: map[string]string{
					"app": "test1",
				},
			},

			Egress: []types.Egress{
				types.Egress{
					ToFQDNs: []types.SpecFQDN{
						types.SpecFQDN{
							MatchNames: []string{"test.com"},
						},
					},
					ToPorts: []types.SpecPort{
						types.SpecPort{
							Port:     "80",
							Protocol: "tcp",
						},
					},
				},
			},
		},
	}

	existings := []types.KnoxNetworkPolicy{exist1}

	exist := IsExistingPolicy(existings, newPolicy)
	assert.Equal(t, exist, true, "they should be equal")
}

func TestReplaceDuplcatedName(t *testing.T) {
	exist1 := types.KnoxNetworkPolicy{
		Metadata: map[string]string{
			"name":   "autopol-egress-test",
			"status": "latest",
			"type":   "egress",
			"rule":   "toFQDNs+toPorts",
		},
	}
	existings := []types.KnoxNetworkPolicy{exist1}

	newPolicy := types.KnoxNetworkPolicy{
		Metadata: map[string]string{
			"name":   "autopol-egress-newpolicy",
			"status": "latest",
			"type":   "egress",
			"rule":   "toFQDNs+toPorts",
		},
	}

	expectedPolicy := types.KnoxNetworkPolicy{
		Metadata: map[string]string{
			"name":   "autopol-egress-newpolicy",
			"status": "latest",
			"type":   "egress",
			"rule":   "toFQDNs+toPorts",
		},
	}

	result := ReplaceDuplcatedName(existings, newPolicy)
	assert.Equal(t, expectedPolicy, result, "they should be equal")
}

func TestGetDomainNameFromMap(t *testing.T) {
	ipAddr := "1.2.3.4"

	DNSToIPs := map[string][]string{
		"test.com": []string{"1.2.3.4"},
	}

	result := GetDomainNameFromMap(ipAddr, DNSToIPs)
	assert.Equal(t, result, "test.com", "they should be equal")
}

func TestGetFQDNFromDomainName(t *testing.T) {
	domainName := "test.com"

	fqdn := types.KnoxNetworkPolicy{
		Metadata: map[string]string{
			"status": "latest",
			"type":   "egress",
			"rule":   "toFQDNs+toPorts",
		},

		Spec: types.Spec{
			Selector: types.Selector{
				MatchLabels: map[string]string{
					"app": "test1",
				},
			},

			Egress: []types.Egress{
				types.Egress{
					ToFQDNs: []types.SpecFQDN{
						types.SpecFQDN{
							MatchNames: []string{"test.com"},
						},
					},
					ToPorts: []types.SpecPort{
						types.SpecPort{
							Port:     "80",
							Protocol: "tcp",
						},
					},
				},
			},
		},
	}

	fqdns := []types.KnoxNetworkPolicy{fqdn}

	result, matched := GetFQDNFromDomainName(domainName, fqdns)
	if matched {
		assert.Equal(t, result, fqdn, "they should be equal")
	} else {
		assert.Equal(t, matched, true, "they should be equal")
	}
}

func TestDeduplicatePolicies(t *testing.T) {
	exist1 := types.KnoxNetworkPolicy{
		Metadata: map[string]string{
			"status": "latest",
			"type":   "egress",
			"rule":   "toCIDRs",
		},

		Spec: types.Spec{
			Selector: types.Selector{
				MatchLabels: map[string]string{
					"app": "test1",
				},
			},

			Egress: []types.Egress{
				types.Egress{
					ToCIDRs: []types.SpecCIDR{
						types.SpecCIDR{
							CIDRs: []string{"10.0.0.1/32"},
						},
					},
				},
			},
		},
	}

	existings := []types.KnoxNetworkPolicy{exist1}

	cidrPolicy := types.KnoxNetworkPolicy{
		Metadata: map[string]string{
			"status": "latest",
			"type":   "egress",
			"rule":   "toCIDRs+toPorts",
		},

		Spec: types.Spec{
			Selector: types.Selector{
				MatchLabels: map[string]string{
					"app": "test1",
				},
			},

			Egress: []types.Egress{
				types.Egress{
					ToCIDRs: []types.SpecCIDR{
						types.SpecCIDR{
							CIDRs: []string{"10.0.0.1/32"},
						},
					},
					ToPorts: []types.SpecPort{
						types.SpecPort{
							Port:     "80",
							Protocol: "tcp",
						},
					},
				},
			},
		},
	}

	discovered := []types.KnoxNetworkPolicy{cidrPolicy}

	DNSToIPs := map[string][]string{
		"test.com": []string{"1.2.3.4"},
	}

	result := DeduplicatePolicies(existings, discovered, DNSToIPs)
	assert.Equal(t, result, discovered, "they should be equal")
}
