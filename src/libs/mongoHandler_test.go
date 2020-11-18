package libs

import (
	"testing"
	"time"

	"github.com/accuknox/knoxAutoPolicy/src/types"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/bson"
)

func TestConnectMongoDB(t *testing.T) {
	actualClient, actualDB := ConnectMongoDB()

	require.NotNil(t, actualClient)
	require.NotNil(t, actualDB)
}

func TestInsertDiscoveredPoliciesToMongoDB(t *testing.T) {
	policies := []types.KnoxNetworkPolicy{
		types.KnoxNetworkPolicy{
			Metadata: map[string]string{
				"name": "test_policy",
			},
		},
	}

	err := InsertDiscoveredPoliciesToMongoDB(policies)

	require.NoError(t, err)
}

func TestGetDocsByFilter(t *testing.T) {
	_, actualDB := ConnectMongoDB()
	col := actualDB.Collection("discovered_policy")

	_, err := GetDocsByFilter(col, bson.M{})

	require.NoError(t, err)
}

func TestGetNetworkPolicies(t *testing.T) {
	_, actualDB := ConnectMongoDB()
	col := actualDB.Collection("discovered_policy")

	_, err := GetNetworkPolicies(col)

	require.NoError(t, err)
}

func TestCountPoliciesByName(t *testing.T) {
	policies := []types.KnoxNetworkPolicy{
		types.KnoxNetworkPolicy{
			Metadata: map[string]string{
				"name": "test_policy",
			},
		},
	}

	err := InsertDiscoveredPoliciesToMongoDB(policies)
	require.NoError(t, err)

	_, actualDB := ConnectMongoDB()
	col := actualDB.Collection("discovered_policy")

	count := CountPoliciesByName(col, "test_policy")

	require.Equal(t, 1, count)
}

func TestGetTrafficFlowFromMongo(t *testing.T) {
	_, err := GetTrafficFlowFromMongo(0, time.Now().Unix())

	require.NoError(t, err)
}
