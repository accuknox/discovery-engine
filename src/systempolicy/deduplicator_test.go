package systempolicy

import (
	"testing"

	"github.com/accuknox/auto-policy-discovery/src/libs"
	"github.com/accuknox/auto-policy-discovery/src/types"
	"github.com/stretchr/testify/assert"
)

// ==================== //
// == Exact Matching == //
// ==================== //

func TestIsExistingPolicy(t *testing.T) {
	exist := types.KnoxSystemPolicy{
		Metadata: map[string]string{
			"name": "test",
		},

		Spec: types.KnoxSystemSpec{
			Selector: types.Selector{
				MatchLabels: map[string]string{
					"app": "test1",
				},
			},
		},
	}

	newOne := types.KnoxSystemPolicy{}
	libs.DeepCopy(&newOne, &exist)

	assert.True(t, IsExistingPolicy([]types.KnoxSystemPolicy{exist}, newOne))
}

// ======================= //
// == Policy Name Check == //
// ======================= //

func TestGeneratePolicyName(t *testing.T) {
	exist := types.KnoxSystemPolicy{
		Metadata: map[string]string{},

		Spec: types.KnoxSystemSpec{
			Selector: types.Selector{
				MatchLabels: map[string]string{
					"app": "test1",
				},
			},
		},
	}

	updated := GeneratePolicyName(map[string]bool{}, exist, "testcluster")

	assert.Equal(t, updated.Metadata["clusterName"], "testcluster")
}
