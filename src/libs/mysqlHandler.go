package libs

import (
	"database/sql"
	"encoding/json"
	"time"

	"github.com/accuknox/knoxAutoPolicy/src/types"
	"github.com/rs/zerolog/log"

	_ "github.com/go-sql-driver/mysql"
)

// ConnectMySQL function
func ConnectMySQL() (db *sql.DB) {
	db, err := sql.Open(DBDriver, DBUser+":"+DBPass+"@tcp("+DBHost+":"+DBPort+")/"+DBName)
	for err != nil {
		log.Error().Msg("connection error :" + err.Error())
		time.Sleep(time.Second * 1)
		db, err = sql.Open(DBDriver, DBUser+":"+DBPass+"@tcp("+DBHost+":"+DBPort+")/"+DBName)
	}
	return db
}

// QueryBaseSimple ...
var QueryBaseSimple string = "select id,time,traffic_direction,verdict,policy_match_type,drop_reason,event_type,source,destination,ip,l4,l7 from "

// flowScannerToCiliumFlow scans the trafficflow.
func flowScannerToCiliumFlow(results *sql.Rows) ([]map[string]interface{}, error) {
	trafficFlows := []map[string]interface{}{}
	var err error

	for results.Next() {
		var id, time, verdict, policyMatchType, dropReason, direction uint32
		var srcByte, destByte, eventTypeByte []byte
		var ipByte, l4Byte, l7Byte []byte

		err = results.Scan(
			&id,
			&time,
			&direction,
			&verdict,
			&policyMatchType,
			&dropReason,
			&eventTypeByte,
			&srcByte,
			&destByte,
			&ipByte,
			&l4Byte,
			&l7Byte,
		)

		if err != nil {
			log.Error().Msg("Error while scanning traffic flows :" + err.Error())
			return nil, err
		}

		flow := map[string]interface{}{
			"id":                id,
			"time":              time,
			"traffic_direction": direction,
			"verdict":           verdict,
			"policy_match_type": policyMatchType,
			"drop_reason":       dropReason,
			"event_type":        eventTypeByte,
			"source":            srcByte,
			"destination":       destByte,
			"ip":                ipByte,
			"l4":                l4Byte,
			"l7":                l7Byte,
		}

		trafficFlows = append(trafficFlows, flow)
	}

	return trafficFlows, nil
}

// GetTrafficFlowByTime function
func GetTrafficFlowByTime(startTime, endTime int64) ([]map[string]interface{}, error) {
	db := ConnectMySQL()
	defer db.Close()

	QueryBase := QueryBaseSimple + TableNetworkFlow

	rows, err := db.Query(QueryBase+" WHERE time >= ? and time < ?", int(startTime), int(endTime))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return flowScannerToCiliumFlow(rows)
}

// GetTrafficFlowByIDTime function
func GetTrafficFlowByIDTime(id, endTime int64) ([]map[string]interface{}, error) {
	db := ConnectMySQL()
	defer db.Close()

	QueryBase := QueryBaseSimple + TableNetworkFlow

	rows, err := db.Query(QueryBase+" WHERE id > ? ORDER BY id ASC ", id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return flowScannerToCiliumFlow(rows)
}

// GetTrafficFlow function
func GetTrafficFlow() ([]map[string]interface{}, error) {
	db := ConnectMySQL()
	defer db.Close()

	QueryBase := QueryBaseSimple + TableNetworkFlow

	rows, err := db.Query(QueryBase)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return flowScannerToCiliumFlow(rows)
}

// GetNetworkPoliciesFromMySQL function
func GetNetworkPoliciesFromMySQL(namespace, status string) ([]types.KnoxNetworkPolicy, error) {
	db := ConnectMySQL()
	defer db.Close()

	policies := []types.KnoxNetworkPolicy{}
	var results *sql.Rows
	var err error

	query := "SELECT apiVersion,kind,name,namespace,type,rule,status,outdated,spec,generatedTime FROM " + TableDiscoveredPolicy
	if namespace != "" && status != "" {
		query = query + " WHERE namespace = ? and status = ? "
		results, err = db.Query(query, namespace, status)
	} else if namespace != "" {
		query = query + " WHERE namespace = ? "
		results, err = db.Query(query, namespace)
	} else if status != "" {
		query = query + " WHERE status = ? "
		results, err = db.Query(query, status)
	} else {
		results, err = db.Query(query)
	}

	defer results.Close()

	if err != nil {
		log.Error().Msg(err.Error())
		return nil, err
	}

	for results.Next() {
		policy := types.KnoxNetworkPolicy{}

		var name, namespace, policyType, rule, status string
		specByte := []byte{}
		spec := types.Spec{}

		if err := results.Scan(
			&policy.APIVersion,
			&policy.Kind,
			&name,
			&namespace,
			&policyType,
			&rule,
			&status,
			&policy.Outdated,
			&specByte,
			&policy.GeneratedTime,
		); err != nil {
			return nil, err
		}

		if err := json.Unmarshal(specByte, &spec); err != nil {
			return nil, err
		}

		policy.Metadata = map[string]string{
			"name":      name,
			"namespace": namespace,
			"type":      policyType,
			"rule":      rule,
			"status":    status,
		}
		policy.Spec = spec

		policies = append(policies, policy)
	}

	return policies, nil
}

// UpdateOutdatedPolicyFromMySQL ...
func UpdateOutdatedPolicyFromMySQL(outdatedPolicy string, latestPolicy string) error {
	db := ConnectMySQL()
	defer db.Close()

	var err error

	// set status -> outdated
	stmt1, err := db.Prepare("UPDATE " + TableDiscoveredPolicy + " SET status=? WHERE name=?")
	if err != nil {
		return err
	}
	defer stmt1.Close()

	_, err = stmt1.Exec("outdated", outdatedPolicy)
	if err != nil {
		return err
	}

	// set outdated -> latest' name
	stmt2, err := db.Prepare("UPDATE " + TableDiscoveredPolicy + " SET outdated=? WHERE name=?")
	if err != nil {
		return err
	}
	defer stmt2.Close()

	_, err = stmt2.Exec(latestPolicy, outdatedPolicy)
	if err != nil {
		return err
	}

	return nil
}

// insertDiscoveredPolicy function
func insertDiscoveredPolicy(db *sql.DB, policy types.KnoxNetworkPolicy) error {
	stmt, err := db.Prepare("INSERT INTO " + TableDiscoveredPolicy + "(apiVersion,kind,name,namespace,type,rule,status,outdated,spec,generatedTime) values(?,?,?,?,?,?,?,?,?,?)")
	if err != nil {
		return err
	}
	defer stmt.Close()

	specPointer := &policy.Spec
	spec, err := json.Marshal(specPointer)
	if err != nil {
		return err
	}

	_, err = stmt.Exec(policy.APIVersion,
		policy.Kind,
		policy.Metadata["name"],
		policy.Metadata["namespace"],
		policy.Metadata["type"],
		policy.Metadata["rule"],
		policy.Metadata["status"],
		policy.Outdated,
		spec,
		policy.GeneratedTime)
	if err != nil {
		return err
	}

	return nil
}

// InsertDiscoveredPoliciesToMySQL function
func InsertDiscoveredPoliciesToMySQL(policies []types.KnoxNetworkPolicy) error {
	db := ConnectMySQL()
	defer db.Close()

	for _, policy := range policies {
		if err := insertDiscoveredPolicy(db, policy); err != nil {
			return err
		}
	}

	return nil
}
