package libs

import (
	"context"
	"encoding/json"
	"net"
	"strings"
	"time"

	"github.com/accuknox/knoxAutoPolicy/src/types"
	"github.com/google/go-cmp/cmp"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// static values, but it will be deprecated
var (
	ColNetworkFlow      string
	ColDiscoveredPolicy string

	DBHost string
	DBPort string
	DBUser string
	DBPass string
	DBName string
)

// init mongodb
func init() {
	if IsK8sEnv() {
		DBHost = GetEnv("DB_HOST", "database.bastion.svc.cluster.local")
		dbAddr, err := net.LookupIP(DBHost)
		if err == nil {
			DBHost = dbAddr[0].String()
		} else {
			DBHost = GetExternalIPAddr()
		}
	} else {
		DBHost = GetEnv("DB_HOST", "database")
		dbAddr, err := net.LookupIP(DBHost)
		if err == nil {
			DBHost = dbAddr[0].String()
		} else {
			DBHost = GetExternalIPAddr()
		}
	}

	DBPort = GetEnv("DB_PORT", "27017")
	DBUser = GetEnv("DB_USER", "root")
	DBPass = GetEnv("DB_PASS", "password")
	DBName = GetEnv("DB_NAME", "flow_management")

	ColNetworkFlow = GetEnv("COL_NETWORK_FLOW", "network_flow")
	ColDiscoveredPolicy = GetEnv("COL_DISCOVERED_POLICY", "discovered_policy")
}

// ConnectMongoDB function
func ConnectMongoDB() (*mongo.Client, *mongo.Database) {
	credential := options.Credential{
		AuthSource: DBName, Username: DBUser, Password: DBPass,
	}

	clientOptions := options.Client().ApplyURI("mongodb://" + DBHost + ":" + DBPort + "/").SetAuth(credential)

	client, err := mongo.Connect(context.Background(), clientOptions)
	for err != nil {
		client, err = mongo.Connect(context.Background(), clientOptions)
		time.Sleep(time.Microsecond * 500)
	}

	return client, client.Database(DBName)
}

// InsertPoliciesToMongoDB function
func InsertPoliciesToMongoDB(policies []types.KnoxNetworkPolicy) error {
	client, db := ConnectMongoDB()
	defer client.Disconnect(context.Background())

	col := db.Collection(ColDiscoveredPolicy)

	existingPolicies, err := GetNetworkPolicies(col)
	if err != nil {
		return err
	}

	for _, policy := range policies {
		if IsExistedPolicy(existingPolicies, policy) {
			continue
		} else {
			policy = replaceDuplcatedName(col, policy)
			if _, err := col.InsertOne(context.Background(), policy); err != nil {
				return err
			}
		}
	}

	return nil
}

// GetDocsByFilter Function
func GetDocsByFilter(col *mongo.Collection, filter primitive.M) ([]map[string]interface{}, error) {
	matchedDocs := []map[string]interface{}{}

	// find documents by the filter
	options := options.Find().SetSort(bson.D{{"_id", -1}})
	cur, err := col.Find(context.Background(), filter, options)
	if err != nil {
		return matchedDocs, err
	}
	defer cur.Close(context.Background())

	for cur.Next(context.Background()) {
		doc := map[string]interface{}{}
		if err := cur.Decode(&doc); err != nil {
			return matchedDocs, err
		}

		matchedDocs = append(matchedDocs, doc)
	}

	return matchedDocs, nil
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

// GetNetworkPolicies Function
func GetNetworkPolicies(col *mongo.Collection) ([]types.KnoxNetworkPolicy, error) {
	docs, _ := GetDocsByFilter(col, bson.M{})
	if len(docs) == 0 { // if no policy, return error
		return []types.KnoxNetworkPolicy{}, nil
	}

	networkPolicies := []types.KnoxNetworkPolicy{}
	jsonString, _ := json.Marshal(docs)
	json.Unmarshal(jsonString, &networkPolicies)

	return networkPolicies, nil
}

// CountPoliciesByName Function
func CountPoliciesByName(col *mongo.Collection, name string) int {
	// set filter by name or path from metadata of policy
	filter := bson.M{}
	filter["metadata.name"] = name

	// count how many docs that are matched to the filter
	count, _ := col.CountDocuments(context.Background(), filter)

	return int(count)
}

// replaceDuplcatedName function
func replaceDuplcatedName(col *mongo.Collection, policy types.KnoxNetworkPolicy) types.KnoxNetworkPolicy {
	name := policy.Metadata["name"]

	if CountPoliciesByName(col, name) > 0 { // name conflict
		egressPrefix := "autogen-egress"
		ingressPrefix := "autogen-ingress"

		if strings.HasPrefix(name, egressPrefix) {
			newName := egressPrefix + RandSeq(10)
			for CountPoliciesByName(col, newName) > 0 {
				newName = egressPrefix + RandSeq(10)
			}

			policy.Metadata["name"] = newName
		} else {
			newName := ingressPrefix + RandSeq(10)
			for CountPoliciesByName(col, newName) > 0 {
				newName = ingressPrefix + RandSeq(10)
			}

			policy.Metadata["name"] = newName
		}
	}

	return policy
}

// updateTimeFilters function
func updateTimeFilters(filter primitive.M, tsStart, tsEnd int64) {
	// update filter by start and end times
	startTime := ConvertUnixTSToDateTime(tsStart)
	endTime := ConvertUnixTSToDateTime(tsEnd)

	filter["timestamp"] = bson.M{"$gte": startTime, "$lt": endTime}
}

// GetTrafficFlowFromMongo function
func GetTrafficFlowFromMongo(startTime, endTime int64) ([]map[string]interface{}, error) {
	client, db := ConnectMongoDB()
	defer client.Disconnect(context.Background())
	col := db.Collection(ColNetworkFlow)

	filter := bson.M{}
	updateTimeFilters(filter, startTime, endTime)

	docs, err := GetDocsByFilter(col, filter)
	if err != nil {
		return nil, err
	}

	return docs, nil
}
