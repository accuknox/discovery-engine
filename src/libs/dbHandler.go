package libs

import (
	"net"
	"time"

	"github.com/accuknox/knoxAutoPolicy/src/types"
	"github.com/rs/zerolog/log"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// env values
var (
	TableNetworkFlow      string
	TableDiscoveredPolicy string

	DBDriver string
	DBHost   string
	DBPort   string
	DBUser   string
	DBPass   string
	DBName   string
)

// network flow between [ startTime <= time < endTime ]
var lastDocID int64 = 0
var startTime int64 = 0
var endTime int64 = 0

func init() {
	DBDriver = GetEnv("DB_DRIVER", "mysql")
	DBUser = GetEnv("DB_USER", "root")
	DBPass = GetEnv("DB_PASS", "password")
	DBName = GetEnv("DB_NAME", "flow_management")

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
	DBPort = GetEnv("DB_PORT", "3306")

	TableNetworkFlow = GetEnv("COL_NETWORK_FLOW", "network_flow")
	TableDiscoveredPolicy = GetEnv("COL_DISCOVERED_POLICY", "discovered_policy")
}

// updateTimeInterval function
func updateTimeInterval(lastDoc map[string]interface{}) {
	if val, ok := lastDoc["timestamp"].(primitive.DateTime); ok {
		ts := val
		startTime = ts.Time().Unix() + 1
	} else if val, ok := lastDoc["timestamp"].(uint32); ok {
		startTime = int64(val) + 1
	}
}

// GetTrafficFlowFromDB function
func GetTrafficFlowFromDB() ([]map[string]interface{}, bool) {
	results := []map[string]interface{}{}

	endTime = time.Now().Unix()
	if DBDriver == "mysql" {
		docs, err := GetTrafficFlowByIDTime(lastDocID, endTime)
		if err != nil {
			log.Error().Msg(err.Error())
			return nil, false
		}
		results = docs
	} else if DBDriver == "mongodb" {
		docs, err := GetTrafficFlowFromMongo(startTime, endTime)
		if err != nil {
			log.Error().Msg(err.Error())
			return nil, false
		}
		results = docs
	} else {
		return nil, false
	}

	if len(results) == 0 {
		log.Info().Msgf("Traffic flow not exist: from %s ~ to %s",
			time.Unix(startTime, 0).Format(TimeFormSimple),
			time.Unix(endTime, 0).Format(TimeFormSimple))

		return nil, false
	}

	fisrtDoc := results[0]
	lastDoc := results[len(results)-1]

	// id/time filter update
	startTime := int64(fisrtDoc["time"].(uint32))

	if DBDriver == "mysql" {
		endTime = int64(lastDoc["time"].(uint32))
		lastDocID = int64(lastDoc["id"].(uint32))
	} else if DBDriver == "mongodb" {
		ts := lastDoc["timestamp"].(primitive.DateTime)
		endTime = ts.Time().Unix()
		startTime = ts.Time().Unix() + 1
	}

	log.Info().Msgf("The total number of traffic flow: [%d] from %s ~ to %s", len(results),
		time.Unix(startTime, 0).Format(TimeFormSimple),
		time.Unix(endTime, 0).Format(TimeFormSimple))

	return results, true
}

// GetNetworkPolicies Function
func GetNetworkPolicies(namespace, status string) ([]types.KnoxNetworkPolicy, error) {
	results := []types.KnoxNetworkPolicy{}

	if DBDriver == "mysql" {
		docs, err := GetNetworkPoliciesFromMySQL(namespace, status)
		if err != nil {
			return nil, err
		}
		results = docs
	} else if DBDriver == "mongodb" {
		docs, err := GetNetworkPoliciesFromMongo(namespace, status)
		if err != nil {
			return nil, err
		}
		results = docs
	} else {
		return results, nil
	}

	return results, nil
}

// UpdateOutdatedPolicy function
func UpdateOutdatedPolicy(outdatedPolicy string, latestPolicy string) error {
	if DBDriver == "mysql" {
		if err := UpdateOutdatedPolicyFromMySQL(outdatedPolicy, latestPolicy); err != nil {
			return err
		}
	} else if DBDriver == "mongodb" {
		if err := UpdateOutdatedPolicyFromMongo(outdatedPolicy, latestPolicy); err != nil {
			return err
		}
	}

	return nil
}

// InsertDiscoveredPolicies function
func InsertDiscoveredPolicies(policies []types.KnoxNetworkPolicy) error {
	if DBDriver == "mysql" {
		if err := InsertDiscoveredPoliciesToMySQL(policies); err != nil {
			return err
		}
	} else if DBDriver == "mongodb" {
		if err := InsertDiscoveredPoliciesToMongoDB(policies); err != nil {
			return err
		}
	}

	return nil
}
