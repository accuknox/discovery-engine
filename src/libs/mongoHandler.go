package libs

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/accuknox/knoxAutoPolicy/src/types"
	"github.com/rs/zerolog/log"
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
func InsertPoliciesToMongoDB(policies []types.KnoxNetworkPolicy) {
	client, db := ConnectMongoDB()
	defer client.Disconnect(context.Background())

	col := db.Collection(ColDiscoveredPolicy)

	for _, policy := range policies {
		if _, err := col.InsertOne(context.Background(), policy); err != nil {
			log.Logger.Err(err)
			continue
		}
	}
}

// GetDocsByFilter Function
func GetDocsByFilter(col *mongo.Collection, filter primitive.M) ([]map[string]interface{}, error) {
	matchedDocs := []map[string]interface{}{}

	// find documents by the filter
	options := options.Find().SetSort(bson.D{{"timestamp", 1}})
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

// GetNetworkPolicies Function
func GetNetworkPolicies() ([]types.KnoxNetworkPolicy, error) {
	client, db := ConnectMongoDB()
	defer client.Disconnect(context.Background())
	col := db.Collection(ColDiscoveredPolicy)

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

// UpdateTimeFilters function
func UpdateTimeFilters(filter primitive.M, tsStart, tsEnd int64) {
	// update filter by start and end times
	startTime := ConvertUnixTSToDateTime(tsStart)
	endTime := ConvertUnixTSToDateTime(tsEnd)

	filter["timestamp"] = bson.M{"$gte": startTime, "$lt": endTime}
}

// UpdateOutdatedLabel function
func UpdateOutdatedLabel(outdatedPolicy string, latestPolicy string) {
	client, db := ConnectMongoDB()
	defer client.Disconnect(context.Background())
	col := db.Collection(ColDiscoveredPolicy)

	filter := bson.M{}
	filter["metadata.name"] = outdatedPolicy

	matchedDoc := map[string]interface{}{}
	err := col.FindOne(context.Background(), filter).Decode(&matchedDoc)
	if err == nil {
		fields := bson.M{}
		fields["labels"] = map[string]string{"outdated": latestPolicy}
		update := bson.M{"$set": fields}

		_, err = col.UpdateOne(context.Background(), filter, update)
		if err != nil {
			fmt.Println(err)
		}
	}
}

// GetTrafficFlowFromMongo function
func GetTrafficFlowFromMongo(startTime, endTime int64) ([]map[string]interface{}, bool) {
	client, db := ConnectMongoDB()
	defer client.Disconnect(context.Background())
	col := db.Collection(ColNetworkFlow)

	filter := bson.M{}
	UpdateTimeFilters(filter, startTime, endTime)

	docs, err := GetDocsByFilter(col, filter)
	if err != nil {
		log.Info().Msg(err.Error())
		return nil, false
	}

	return docs, true
}
