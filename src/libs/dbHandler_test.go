package libs

import (
	"testing"

	"github.com/accuknox/knoxAutoPolicy/src/types"
	"github.com/stretchr/testify/assert"
)

func TestUpdateOutdatedPolicy(t *testing.T) {
	outdated := "policy_a"
	latest := "policy_b"

	err := UpdateOutdatedPolicy(outdated, latest)
	assert.Equal(t, nil, err, "they should be equal")
}

func TestInsertDiscoveredPolicies(t *testing.T) {
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

	err := InsertDiscoveredPolicies(discovered)
	assert.Equal(t, nil, err, "they should be equal")
}
