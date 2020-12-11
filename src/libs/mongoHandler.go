package libs

import (
	"context"
	"encoding/json"
	"time"

	"github.com/accuknox/knoxAutoPolicy/src/types"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

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

// InsertDiscoveredPoliciesToMongoDB function
func InsertDiscoveredPoliciesToMongoDB(policies []types.KnoxNetworkPolicy) error {
	client, db := ConnectMongoDB()
	defer client.Disconnect(context.Background())

	col := db.Collection(TableDiscoveredPolicy)

	for _, policy := range policies {
		if _, err := col.InsertOne(context.Background(), policy); err != nil {
			return err
		}
	}

	return nil
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

// GetNetworkPoliciesFromMongo Function
func GetNetworkPoliciesFromMongo(namespace, status string) ([]types.KnoxNetworkPolicy, error) {
	client, db := ConnectMongoDB()
	defer client.Disconnect(context.Background())
	col := db.Collection(TableDiscoveredPolicy)

	docs, _ := GetDocsByFilter(col, bson.M{
		"namespace": namespace,
		"status":    status,
	})
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

// UpdateOutdatedPolicyFromMongo function
func UpdateOutdatedPolicyFromMongo(outdatedPolicy string, latestPolicy string) error {
	client, db := ConnectMongoDB()
	defer client.Disconnect(context.Background())
	col := db.Collection(TableDiscoveredPolicy)

	filter := bson.M{}
	filter["metadata.name"] = outdatedPolicy

	matchedDoc := map[string]interface{}{}
	err := col.FindOne(context.Background(), filter).Decode(&matchedDoc)
	if err == nil {
		fields := bson.M{}
		fields["outdated"] = latestPolicy
		update := bson.M{"$set": fields}

		_, err = col.UpdateOne(context.Background(), filter, update)
		if err != nil {
			return err
		}
	}

	return nil
}

// GetTrafficFlowFromMongo function
func GetTrafficFlowFromMongo(startTime, endTime int64) ([]map[string]interface{}, error) {
	client, db := ConnectMongoDB()
	defer client.Disconnect(context.Background())
	col := db.Collection(TableNetworkFlow)

	filter := bson.M{}
	UpdateTimeFilters(filter, startTime, endTime)

	docs, err := GetDocsByFilter(col, filter)
	if err != nil {
		return nil, err
	}

	return docs, nil
}
