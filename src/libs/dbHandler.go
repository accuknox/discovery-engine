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
		DBHost = GetEnv("DB_HOST", "database.knox-auto-policy.svc.cluster.local")
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

	TableNetworkFlow = GetEnv("TB_NETWORK_FLOW", "network_flow")
	TableDiscoveredPolicy = GetEnv("TB_DISCOVERED_POLICY", "discovered_policy")
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
func GetTrafficFlowFromDB() []map[string]interface{} {
	results := []map[string]interface{}{}

	endTime = time.Now().Unix()

	if DBDriver == "mysql" {
		docs, err := GetTrafficFlowByIDTime(lastDocID, endTime)
		if err != nil {
			log.Error().Msg(err.Error())
			return results
		}
		results = docs
	} else if DBDriver == "mongodb" {
		docs, err := GetTrafficFlowFromMongo(startTime, endTime)
		if err != nil {
			log.Error().Msg(err.Error())
			return results
		}
		results = docs
	} else {
		return results
	}

	if len(results) == 0 {
		log.Info().Msgf("Traffic flow not exist: from %s ~ to %s",
			time.Unix(startTime, 0).Format(TimeFormSimple),
			time.Unix(endTime, 0).Format(TimeFormSimple))

		return results
	}

	lastDoc := results[len(results)-1]
	// id update for mysql
	if DBDriver == "mysql" {
		lastDocID = int64(lastDoc["id"].(uint32))
	}

	log.Info().Msgf("The total number of traffic flow: [%d] from %s ~ to %s", len(results),
		time.Unix(startTime, 0).Format(TimeFormSimple),
		time.Unix(endTime, 0).Format(TimeFormSimple))

	startTime = endTime + 1
	return results
}

// GetNetworkPolicies Function
func GetNetworkPolicies(namespace, status string) []types.KnoxNetworkPolicy {
	results := []types.KnoxNetworkPolicy{}

	if DBDriver == "mysql" {
		docs, err := GetNetworkPoliciesFromMySQL(namespace, status)
		if err != nil {
			return results
		}
		results = docs
	} else if DBDriver == "mongodb" {
		docs, err := GetNetworkPoliciesFromMongo(namespace, status)
		if err != nil {
			return results
		}
		results = docs
	} else {
		return results
	}

	return results
}

// GetNetworkPoliciesBySelector Function
func GetNetworkPoliciesBySelector(namespace, status string, selector map[string]string) ([]types.KnoxNetworkPolicy, error) {
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

	filtered := []types.KnoxNetworkPolicy{}
	for _, policy := range results {
		matched := true
		for k, v := range selector {
			if val, ok := policy.Spec.Selector.MatchLabels[k]; !ok { // not exist key
				matched = false
				break
			} else {
				if val != v { // not matched value
					matched = false
					break
				}
			}
		}

		if matched {
			filtered = append(filtered, policy)
		}
	}

	return filtered, nil
}

// UpdateOutdatedPolicy function
func UpdateOutdatedPolicy(outdatedPolicy string, latestPolicy string) {
	if DBDriver == "mysql" {
		if err := UpdateOutdatedPolicyFromMySQL(outdatedPolicy, latestPolicy); err != nil {
			log.Error().Msg(err.Error())
		}
	} else if DBDriver == "mongodb" {
		if err := UpdateOutdatedPolicyFromMongo(outdatedPolicy, latestPolicy); err != nil {
			log.Error().Msg(err.Error())
		}
	}
}

// InsertDiscoveredPolicies function
func InsertDiscoveredPolicies(policies []types.KnoxNetworkPolicy) {
	if DBDriver == "mysql" {
		if err := InsertDiscoveredPoliciesToMySQL(policies); err != nil {
			log.Error().Msg(err.Error())
		}
	} else if DBDriver == "mongodb" {
		if err := InsertDiscoveredPoliciesToMongoDB(policies); err != nil {
			log.Error().Msg(err.Error())
		}
	}
}
