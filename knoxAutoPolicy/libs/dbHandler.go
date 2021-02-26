package libs

import (
	"strings"
	"time"

	"github.com/accuknox/knoxAutoPolicy/src/types"
	"github.com/rs/zerolog/log"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// LastFlowID network flow between [ startTime <= time < endTime ]
var LastFlowID int64 = 0
var startTime int64 = 0
var endTime int64 = 0

// updateTimeInterval function
func updateTimeInterval(lastDoc map[string]interface{}) {
	if val, ok := lastDoc["timestamp"].(primitive.DateTime); ok {
		ts := val
		startTime = ts.Time().Unix() + 1
	} else if val, ok := lastDoc["timestamp"].(uint32); ok {
		startTime = int64(val) + 1
	}
}

// GetNetworkFlowFromDB function
func GetNetworkFlowFromDB(cfg types.ConfigDB, timeSelection string) []map[string]interface{} {
	results := []map[string]interface{}{}

	endTime = time.Now().Unix()

	if cfg.DBDriver == "mysql" {
		if timeSelection == "" {
			docs, err := GetTrafficFlowByIDTime(cfg, LastFlowID, endTime)
			if err != nil {
				log.Error().Msg(err.Error())
				return results
			}
			results = docs
		} else {
			// given time selection from ~ to
			times := strings.Split(timeSelection, "|")
			from := ConvertStrToUnixTime(times[0])
			to := ConvertStrToUnixTime(times[1])

			docs, err := GetTrafficFlowByTime(cfg, from, to)
			if err != nil {
				log.Error().Msg(err.Error())
				return results
			}
			results = docs
		}
	} else if cfg.DBDriver == "mongodb" {
		docs, err := GetTrafficFlowFromMongo(cfg, startTime, endTime)
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
	if cfg.DBDriver == "mysql" {
		LastFlowID = int64(lastDoc["id"].(uint32))
	}

	log.Info().Msgf("The total number of traffic flow: [%d] from %s ~ to %s", len(results),
		time.Unix(startTime, 0).Format(TimeFormSimple),
		time.Unix(endTime, 0).Format(TimeFormSimple))

	startTime = endTime + 1
	return results
}

// GetNetworkPolicies Function
func GetNetworkPolicies(cfg types.ConfigDB, namespace, status string) []types.KnoxNetworkPolicy {
	results := []types.KnoxNetworkPolicy{}

	if cfg.DBDriver == "mysql" {
		docs, err := GetNetworkPoliciesFromMySQL(cfg, namespace, status)
		if err != nil {
			return results
		}
		results = docs
	} else if cfg.DBDriver == "mongodb" {
		docs, err := GetNetworkPoliciesFromMongo(cfg, namespace, status)
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
func GetNetworkPoliciesBySelector(cfg types.ConfigDB, namespace, status string, selector map[string]string) ([]types.KnoxNetworkPolicy, error) {
	results := []types.KnoxNetworkPolicy{}

	if cfg.DBDriver == "mysql" {
		docs, err := GetNetworkPoliciesFromMySQL(cfg, namespace, status)
		if err != nil {
			return nil, err
		}
		results = docs
	} else if cfg.DBDriver == "mongodb" {
		docs, err := GetNetworkPoliciesFromMongo(cfg, namespace, status)
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
func UpdateOutdatedPolicy(cfg types.ConfigDB, outdatedPolicy string, latestPolicy string) {
	if cfg.DBDriver == "mysql" {
		if err := UpdateOutdatedPolicyFromMySQL(cfg, outdatedPolicy, latestPolicy); err != nil {
			log.Error().Msg(err.Error())
		}
	} else if cfg.DBDriver == "mongodb" {
		if err := UpdateOutdatedPolicyFromMongo(cfg, outdatedPolicy, latestPolicy); err != nil {
			log.Error().Msg(err.Error())
		}
	}
}

// InsertDiscoveredPolicies function
func InsertDiscoveredPolicies(cfg types.ConfigDB, policies []types.KnoxNetworkPolicy) {
	if cfg.DBDriver == "mysql" {
		if err := InsertDiscoveredPoliciesToMySQL(cfg, policies); err != nil {
			log.Error().Msg(err.Error())
		}
	} else if cfg.DBDriver == "mongodb" {
		if err := InsertDiscoveredPoliciesToMongoDB(cfg, policies); err != nil {
			log.Error().Msg(err.Error())
		}
	}
}

// ClearDBTables function
func ClearDBTables(cfg types.ConfigDB) {
	if cfg.DBDriver == "mysql" {
		if err := ClearDBTablesMySQL(cfg); err != nil {
			log.Error().Msg(err.Error())
		}
	} else if cfg.DBDriver == "mongodb" {

	}
}
