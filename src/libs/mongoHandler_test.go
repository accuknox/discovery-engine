package libs

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/bson"
)

func TestConnectMongoDB(t *testing.T) {
	actualClient, actualDB := ConnectMongoDB()

	require.NotNil(t, actualClient)
	require.NotNil(t, actualDB)
}

func TestGetDocsByFilter(t *testing.T) {
	_, actualDB := ConnectMongoDB()
	col := actualDB.Collection("discovered_policy")

	_, err := GetDocsByFilter(col, bson.M{})

	require.NoError(t, err)
}

func TestGetNetworkPolicies(t *testing.T) {
	_, err := GetNetworkPoliciesFromMongo()

	require.NoError(t, err)
}

func TestGetTrafficFlowFromMongo(t *testing.T) {
	_, err := GetTrafficFlowFromMongo(0, time.Now().Unix())

	require.NoError(t, err)
}
