package networkpolicy

import (
	"testing"

	"github.com/accuknox/auto-policy-discovery/src/libs"
	"github.com/accuknox/auto-policy-discovery/src/types"
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
				{
					ToCIDRs: []types.SpecCIDR{
						{
							CIDRs: []string{"10.0.0.1/32"},
						},
					},
				},
			},
		},
	}

	exist2 := types.KnoxNetworkPolicy{}
	libs.DeepCopy(&exist2, &exist1)
	exist2.Metadata["statue"] = "outdated"

	cidrPolicy := types.KnoxNetworkPolicy{}
	libs.DeepCopy(&cidrPolicy, &exist1)

	existings := []types.KnoxNetworkPolicy{exist1, exist2}

	result := GetLatestCIDRPolicy(existings, cidrPolicy)
	assert.Equal(t, result[0], exist1, ShouldBeEqual)
}

func TestGetLatestFQDNs(t *testing.T) {
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
				{
					ToFQDNs: []types.SpecFQDN{
						{
							MatchNames: []string{"test.com"},
						},
					},
				},
			},
		},
	}

	exist2 := types.KnoxNetworkPolicy{}
	libs.DeepCopy(&exist2, &exist1)
	exist2.Metadata["statue"] = "outdated"

	fqdnPolicy := types.KnoxNetworkPolicy{}
	libs.DeepCopy(&fqdnPolicy, &exist1)

	existings := []types.KnoxNetworkPolicy{exist1, exist2}

	result := GetLatestFQDNPolicy(existings, fqdnPolicy)
	assert.Equal(t, result[0], exist1, ShouldBeEqual)
}

func TestGetLastedHTTPPolicy(t *testing.T) {
	exist1 := types.KnoxNetworkPolicy{
		Metadata: map[string]string{
			"status": "latest",
			"type":   "egress",
			"rule":   "matchLabels+toHTTPs+toPorts",
		},

		Spec: types.Spec{
			Selector: types.Selector{
				MatchLabels: map[string]string{
					"app": "test1",
				},
			},

			Egress: []types.Egress{
				{
					ToHTTPs: []types.SpecHTTP{
						{
							Method: "GET",
							Path:   "/",
						},
					},
				},
			},
		},
	}

	exist2 := types.KnoxNetworkPolicy{}
	libs.DeepCopy(&exist2, &exist1)
	exist2.Metadata["statue"] = "outdated"

	httpPolicy := types.KnoxNetworkPolicy{}
	libs.DeepCopy(&httpPolicy, &exist1)

	existings := []types.KnoxNetworkPolicy{exist1, exist2}

	result := GetLatestHTTPPolicy(existings, httpPolicy)
	assert.Equal(t, result[0], exist1, ShouldBeEqual)
}

func TestGetLatestMatchLabelsPolicy(t *testing.T) {
	exist1 := types.KnoxNetworkPolicy{
		Metadata: map[string]string{
			"status": "latest",
			"type":   "egress",
			"rule":   "matchLabels",
		},

		Spec: types.Spec{
			Selector: types.Selector{
				MatchLabels: map[string]string{
					"app": "test1",
				},
			},

			Egress: []types.Egress{
				{
					MatchLabels: map[string]string{
						"app": "destination",
					},
				},
			},
		},
	}

	exist2 := types.KnoxNetworkPolicy{}
	libs.DeepCopy(&exist2, &exist1)
	exist2.Metadata["statue"] = "outdated"

	matchLabelPolicy := types.KnoxNetworkPolicy{}
	libs.DeepCopy(&matchLabelPolicy, &exist1)

	existings := []types.KnoxNetworkPolicy{exist1, exist2}

	result := GetLatestMatchLabelsPolicy(existings, matchLabelPolicy)
	assert.Equal(t, result[0], exist1, ShouldBeEqual)
}

func TestGetLatestEntityPolicy(t *testing.T) {
	exist1 := types.KnoxNetworkPolicy{
		Metadata: map[string]string{
			"status": "latest",
			"type":   "egress",
			"rule":   "toEntities",
		},

		Spec: types.Spec{
			Selector: types.Selector{
				MatchLabels: map[string]string{
					"app": "test1",
				},
			},

			Egress: []types.Egress{
				{
					ToEntities: []string{"testEntity"},
				},
			},
		},
	}

	exist2 := types.KnoxNetworkPolicy{}
	libs.DeepCopy(&exist2, &exist1)
	exist2.Metadata["statue"] = "outdated"

	entityPolicy := types.KnoxNetworkPolicy{}
	libs.DeepCopy(&entityPolicy, &exist1)

	existings := []types.KnoxNetworkPolicy{exist1, exist2}

	result := GetLatestEntityPolicy(existings, entityPolicy)
	assert.Equal(t, result[0], exist1, ShouldBeEqual)
}

func TestGetLatestServicePolicy(t *testing.T) {
	exist1 := types.KnoxNetworkPolicy{
		Metadata: map[string]string{
			"status": "latest",
			"type":   "egress",
			"rule":   "toServices",
		},

		Spec: types.Spec{
			Selector: types.Selector{
				MatchLabels: map[string]string{
					"app": "test1",
				},
			},

			Egress: []types.Egress{
				{
					ToServices: []types.SpecService{
						{
							ServiceName: "testService",
							Namespace:   "testNamespace",
						},
					},
				},
			},
		},
	}

	exist2 := types.KnoxNetworkPolicy{}
	libs.DeepCopy(&exist2, &exist1)
	exist2.Metadata["statue"] = "outdated"

	toServicePolicy := types.KnoxNetworkPolicy{}
	libs.DeepCopy(&toServicePolicy, &exist1)

	existings := []types.KnoxNetworkPolicy{exist1, exist2}

	result := GetLatestEntityPolicy(existings, toServicePolicy)
	assert.Equal(t, result[0], exist1, ShouldBeEqual)
}

// ============================ //
// == Update Outdated Policy == //
// ============================ //

func TestUpdateHTTP(t *testing.T) {
	existPolicy := types.KnoxNetworkPolicy{
		Metadata: map[string]string{
			"status": "latest",
			"type":   "egress",
			"rule":   "matchLabels+toHTTPs+toPorts",
		},

		Spec: types.Spec{
			Selector: types.Selector{
				MatchLabels: map[string]string{
					"app": "test1",
				},
			},

			Egress: []types.Egress{
				{
					ToHTTPs: []types.SpecHTTP{
						{
							Method: "GET",
							Path:   "/",
						},
					},
				},
			},
		},
	}

	newPolicy := types.KnoxNetworkPolicy{}
	libs.DeepCopy(&newPolicy, &existPolicy)
	newPolicy.Spec.Egress[0].ToHTTPs[0] = types.SpecHTTP{
		Method: "GET",
		Path:   "/test",
	}

	expected := types.KnoxNetworkPolicy{}
	libs.DeepCopy(&expected, &newPolicy)
	expected.Spec.Egress[0].ToHTTPs = append(expected.Spec.Egress[0].ToHTTPs,
		types.SpecHTTP{
			Method: "GET",
			Path:   "/",
		},
	)

	existings := []types.KnoxNetworkPolicy{existPolicy}

	result, updated := UpdateHTTP(newPolicy, existings)
	assert.True(t, updated)

	assert.Equal(t, result, expected, ShouldBeEqual)
}

func TestUpdateToPorts(t *testing.T) {
	existPolicy := types.KnoxNetworkPolicy{
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
				{
					ToPorts: []types.SpecPort{
						{
							Port:     "80",
							Protocol: "tcp",
						},
					},
					ToCIDRs: []types.SpecCIDR{
						{
							CIDRs: []string{"10.0.0.1/32"},
						},
					},
				},
			},
		},
	}

	newPolicy := types.KnoxNetworkPolicy{}
	libs.DeepCopy(&newPolicy, &existPolicy)
	newPolicy.Spec.Egress[0].ToPorts[0] = types.SpecPort{
		Port:     "8080",
		Protocol: "tcp",
	}

	expected := types.KnoxNetworkPolicy{}
	libs.DeepCopy(&expected, &newPolicy)
	expected.Spec.Egress[0].ToPorts = append(expected.Spec.Egress[0].ToPorts,
		types.SpecPort{
			Port:     "80",
			Protocol: "tcp",
		},
	)

	existings := []types.KnoxNetworkPolicy{existPolicy}

	result, updated := UpdateToPorts(newPolicy, existings)
	assert.True(t, updated)

	assert.Equal(t, result, expected, ShouldBeEqual)
}

func TestUpdateMatchLabels(t *testing.T) {
	existPolicy := types.KnoxNetworkPolicy{
		Metadata: map[string]string{
			"status": "latest",
			"type":   "egress",
			"rule":   "matchLabels+toPorts",
		},

		Spec: types.Spec{
			Selector: types.Selector{
				MatchLabels: map[string]string{
					"app": "test1",
				},
			},

			Egress: []types.Egress{
				{
					ToPorts: []types.SpecPort{
						{
							Port:     "80",
							Protocol: "tcp",
						},
					},
					MatchLabels: map[string]string{
						"app": "destination",
					},
				},
			},
		},
	}

	newPolicy := types.KnoxNetworkPolicy{}
	libs.DeepCopy(&newPolicy, &existPolicy)
	newPolicy.Spec.Egress[0].ToPorts[0] = types.SpecPort{
		Port:     "8080",
		Protocol: "tcp",
	}

	expected := types.KnoxNetworkPolicy{}
	libs.DeepCopy(&expected, &newPolicy)
	expected.Spec.Egress[0].ToPorts = append(expected.Spec.Egress[0].ToPorts,
		types.SpecPort{
			Port:     "80",
			Protocol: "tcp",
		},
	)

	existings := []types.KnoxNetworkPolicy{existPolicy}

	result, updated := UpdateMatchLabels(newPolicy, existings)
	assert.True(t, updated)

	assert.Equal(t, result, expected, ShouldBeEqual)
}

func TestUpdateEntity(t *testing.T) {
	existPolicy := types.KnoxNetworkPolicy{
		Metadata: map[string]string{
			"status": "latest",
			"type":   "egress",
			"rule":   "matchLabels+toPorts",
		},

		Spec: types.Spec{
			Selector: types.Selector{
				MatchLabels: map[string]string{
					"app": "test1",
				},
			},

			Egress: []types.Egress{
				{
					ToEntities: []string{"testEntity"},
				},
			},
		},
	}

	newPolicy := types.KnoxNetworkPolicy{}
	libs.DeepCopy(&newPolicy, &existPolicy)
	newPolicy.Spec.Egress[0].ToEntities[0] = "newEntity"

	expected := types.KnoxNetworkPolicy{}
	libs.DeepCopy(&expected, &newPolicy)
	expected.Spec.Egress[0].ToEntities = append(expected.Spec.Egress[0].ToEntities, "testEntity")

	existings := []types.KnoxNetworkPolicy{existPolicy}

	result, updated := UpdateEntity(newPolicy, existings)
	assert.True(t, updated)

	assert.Equal(t, result, expected, ShouldBeEqual)
}

func TestUpdateService(t *testing.T) {
	existPolicy := types.KnoxNetworkPolicy{
		Metadata: map[string]string{
			"status": "latest",
			"type":   "egress",
			"rule":   "matchLabels+toPorts",
		},

		Spec: types.Spec{
			Selector: types.Selector{
				MatchLabels: map[string]string{
					"app": "test1",
				},
			},

			Egress: []types.Egress{
				{
					ToServices: []types.SpecService{
						{
							ServiceName: "testService",
							Namespace:   "testNamespace",
						},
					},
				},
			},
		},
	}

	newPolicy := types.KnoxNetworkPolicy{}
	libs.DeepCopy(&newPolicy, &existPolicy)
	newPolicy.Spec.Egress[0].ToServices[0] = types.SpecService{
		ServiceName: "newService",
		Namespace:   "newNamespace",
	}

	expected := types.KnoxNetworkPolicy{}
	libs.DeepCopy(&expected, &newPolicy)
	expected.Spec.Egress[0].ToServices = append(expected.Spec.Egress[0].ToServices,
		types.SpecService{
			ServiceName: "testService",
			Namespace:   "testNamespace",
		},
	)

	existings := []types.KnoxNetworkPolicy{existPolicy}

	result, updated := UpdateService(newPolicy, existings)
	assert.True(t, updated)

	assert.Equal(t, result, expected, ShouldBeEqual)
}
