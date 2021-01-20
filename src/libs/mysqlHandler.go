package libs

import (
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/accuknox/knoxAutoPolicy/src/types"
	"github.com/rs/zerolog/log"

	_ "github.com/go-sql-driver/mysql"
)

// ConnectMySQL function
func ConnectMySQL(cfg types.ConfigDB) (db *sql.DB) {
	db, err := sql.Open(cfg.DBDriver, cfg.DBUser+":"+cfg.DBPass+"@tcp("+cfg.DBHost+":"+cfg.DBPort+")/"+cfg.DBName)
	for err != nil {
		log.Error().Msg("connection error :" + err.Error())
		time.Sleep(time.Second * 1)
		db, err = sql.Open(cfg.DBDriver, cfg.DBUser+":"+cfg.DBPass+"@tcp("+cfg.DBHost+":"+cfg.DBPort+")/"+cfg.DBName)
	}
	return db
}

// ===================== //
// == Network Traffic == //
// ===================== //

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
func GetTrafficFlowByTime(cfg types.ConfigDB, startTime, endTime int64) ([]map[string]interface{}, error) {
	db := ConnectMySQL(cfg)
	defer db.Close()

	QueryBase := QueryBaseSimple + cfg.TableNetworkFlow

	rows, err := db.Query(QueryBase+" WHERE time >= ? and time < ?", int(startTime), int(endTime))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return flowScannerToCiliumFlow(rows)
}

// GetTrafficFlowByIDTime function
func GetTrafficFlowByIDTime(cfg types.ConfigDB, id, endTime int64) ([]map[string]interface{}, error) {
	db := ConnectMySQL(cfg)
	defer db.Close()

	QueryBase := QueryBaseSimple + cfg.TableNetworkFlow

	rows, err := db.Query(QueryBase+" WHERE id > ? ORDER BY id ASC ", id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return flowScannerToCiliumFlow(rows)
}

// GetTrafficFlow function
func GetTrafficFlow(cfg types.ConfigDB) ([]map[string]interface{}, error) {
	db := ConnectMySQL(cfg)
	defer db.Close()

	QueryBase := QueryBaseSimple + cfg.TableNetworkFlow

	rows, err := db.Query(QueryBase)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return flowScannerToCiliumFlow(rows)
}

// ==================== //
// == Network Policy == //
// ==================== //

// GetNetworkPoliciesFromMySQL function
func GetNetworkPoliciesFromMySQL(cfg types.ConfigDB, namespace, status string) ([]types.KnoxNetworkPolicy, error) {
	db := ConnectMySQL(cfg)
	defer db.Close()

	policies := []types.KnoxNetworkPolicy{}
	var results *sql.Rows
	var err error

	query := "SELECT apiVersion,kind,name,namespace,type,rule,status,outdated,spec,generatedTime FROM " + cfg.TableDiscoveredPolicy
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
func UpdateOutdatedPolicyFromMySQL(cfg types.ConfigDB, outdatedPolicy string, latestPolicy string) error {
	db := ConnectMySQL(cfg)
	defer db.Close()

	var err error

	// set status -> outdated
	stmt1, err := db.Prepare("UPDATE " + cfg.TableDiscoveredPolicy + " SET status=? WHERE name=?")
	if err != nil {
		return err
	}
	defer stmt1.Close()

	_, err = stmt1.Exec("outdated", outdatedPolicy)
	if err != nil {
		return err
	}

	// set outdated -> latest' name
	stmt2, err := db.Prepare("UPDATE " + cfg.TableDiscoveredPolicy + " SET outdated=? WHERE name=?")
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
func insertDiscoveredPolicy(cfg types.ConfigDB, db *sql.DB, policy types.KnoxNetworkPolicy) error {
	stmt, err := db.Prepare("INSERT INTO " + cfg.TableDiscoveredPolicy + "(apiVersion,kind,name,namespace,type,rule,status,outdated,spec,generatedTime) values(?,?,?,?,?,?,?,?,?,?)")
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
func InsertDiscoveredPoliciesToMySQL(cfg types.ConfigDB, policies []types.KnoxNetworkPolicy) error {
	db := ConnectMySQL(cfg)
	defer db.Close()

	for _, policy := range policies {
		if err := insertDiscoveredPolicy(cfg, db, policy); err != nil {
			return err
		}
	}

	return nil
}

// =================== //
// == Configuration == //
// =================== //

// CountConfigByName ...
func CountConfigByName(db *sql.DB, tableName, configName string) int {
	var count int
	db.QueryRow("SELECT COUNT(*) FROM "+tableName+" WHERE config_name=?", configName).Scan(&count)
	return count
}

// AddConfiguration function
func AddConfiguration(cfg types.ConfigDB, newConfig types.Configuration) error {
	db := ConnectMySQL(cfg)
	defer db.Close()

	if CountConfigByName(db, cfg.TableConfiguration, newConfig.ConfigName) > 0 {
		return errors.New("Already exist config name: " + newConfig.ConfigName)
	}

	stmt, err := db.Prepare("INSERT INTO " +
		cfg.TableConfiguration +
		"(config_name," +
		"status," +
		"config_db," +
		"config_cilium_hubble," +
		"operation_mode," +
		"cronjob_time_interval," +
		"one_time_job_time_selection," +
		"network_log_from," +
		"discovered_policy_to," +
		"policy_dir," +
		"discovery_policy_types," +
		"discovery_rule_types," +
		"cidr_bits," +
		"ignoring_flows," +
		"l3_aggregation_level," +
		"l4_aggregation_level," +
		"l7_aggregation_level," +
		"http_url_threshold) " +
		"values(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)")

	if err != nil {
		return err
	}

	defer stmt.Close()

	configDBPtr := &newConfig.ConfigDB
	configDB, err := json.Marshal(configDBPtr)
	if err != nil {
		return err
	}

	configHubblePtr := &newConfig.ConfigCiliumHubble
	configCilium, err := json.Marshal(configHubblePtr)
	if err != nil {
		return err
	}

	ignoringFlowsPtr := &newConfig.IgnoringFlows
	ignoringFlows, err := json.Marshal(ignoringFlowsPtr)
	if err != nil {
		return err
	}

	_, err = stmt.Exec(newConfig.ConfigName,
		newConfig.Status,
		configDB,
		configCilium,
		newConfig.OperationMode,
		newConfig.CronJobTimeInterval,
		newConfig.OneTimeJobTimeSelection,
		newConfig.NetworkLogFrom,
		newConfig.DiscoveredPolicyTo,
		newConfig.PolicyDir,
		newConfig.DiscoveryPolicyTypes,
		newConfig.DiscoveryRuleTypes,
		newConfig.CIDRBits,
		ignoringFlows,
		newConfig.L3AggregationLevel,
		newConfig.L4AggregationLevel,
		newConfig.L7AggregationLevel,
		newConfig.HTTPUrlThreshold,
	)

	if err != nil {
		return err
	}

	return nil
}

// GetConfigurations function
func GetConfigurations(cfg types.ConfigDB, configName string) ([]types.Configuration, error) {
	db := ConnectMySQL(cfg)
	defer db.Close()

	configs := []types.Configuration{}
	var results *sql.Rows
	var err error

	query := "SELECT * FROM " + cfg.TableConfiguration
	if configName != "" {
		query = query + " WHERE config_name = ? "
		results, err = db.Query(query, configName)
	}

	defer results.Close()

	if err != nil {
		log.Error().Msg(err.Error())
		return nil, err
	}

	for results.Next() {
		cfg := types.Configuration{}

		id := 0
		configDBByte := []byte{}
		configDB := types.ConfigDB{}

		hubbleByte := []byte{}
		hubble := types.ConfigCiliumHubble{}

		ignoringFlowByte := []byte{}
		ignoringFlows := []types.IgnoringFlows{}

		if err := results.Scan(
			&id,
			&cfg.ConfigName,
			&cfg.Status,
			&configDBByte,
			&hubbleByte,
			&cfg.OperationMode,
			&cfg.CronJobTimeInterval,
			&cfg.OneTimeJobTimeSelection,
			&cfg.NetworkLogFrom,
			&cfg.DiscoveredPolicyTo,
			&cfg.PolicyDir,
			&cfg.DiscoveryPolicyTypes,
			&cfg.DiscoveryRuleTypes,
			&cfg.CIDRBits,
			&ignoringFlowByte,
			&cfg.L3AggregationLevel,
			&cfg.L4AggregationLevel,
			&cfg.L7AggregationLevel,
			&cfg.HTTPUrlThreshold,
		); err != nil {
			return nil, err
		}

		if err := json.Unmarshal(configDBByte, &configDB); err != nil {
			return nil, err
		}
		cfg.ConfigDB = configDB

		if err := json.Unmarshal(hubbleByte, &hubble); err != nil {
			return nil, err
		}
		cfg.ConfigCiliumHubble = hubble

		if err := json.Unmarshal(ignoringFlowByte, &ignoringFlows); err != nil {
			return nil, err
		}
		cfg.IgnoringFlows = ignoringFlows

		configs = append(configs, cfg)
	}

	return configs, nil
}

// UpdateConfiguration ...
func UpdateConfiguration(cfg types.ConfigDB, configName string, updateConfig types.Configuration) error {
	db := ConnectMySQL(cfg)
	defer db.Close()

	var err error

	stmt, err := db.Prepare("UPDATE " + cfg.TableConfiguration + " SET " +
		"config_name=?," +
		"config_db=?," +
		"config_cilium_hubble=?," +
		"operation_mode=?," +
		"cronjob_time_interval=?," +
		"one_time_job_time_selection=?," +
		"network_log_from=?," +
		"discovered_policy_to=?," +
		"policy_dir=?," +
		"discovery_policy_types=?," +
		"discovery_rule_types=?," +
		"cidr_bits=?," +
		"ignoring_flows=?," +
		"l3_aggregation_level=?," +
		"l4_aggregation_level=?," +
		"l7_aggregation_level=?," +
		"http_url_threshold=? " +
		"WHERE config_name=?")

	if err != nil {
		return err
	}
	defer stmt.Close()

	configDBPtr := &updateConfig.ConfigDB
	configDB, err := json.Marshal(configDBPtr)
	if err != nil {
		return err
	}

	configHubblePtr := &updateConfig.ConfigCiliumHubble
	configCilium, err := json.Marshal(configHubblePtr)
	if err != nil {
		return err
	}

	ignoringFlowsPtr := &updateConfig.IgnoringFlows
	ignoringFlows, err := json.Marshal(ignoringFlowsPtr)
	if err != nil {
		return err
	}

	_, err = stmt.Exec(
		updateConfig.ConfigName,
		configDB,
		configCilium,
		updateConfig.OperationMode,
		updateConfig.CronJobTimeInterval,
		updateConfig.OneTimeJobTimeSelection,
		updateConfig.NetworkLogFrom,
		updateConfig.DiscoveredPolicyTo,
		updateConfig.PolicyDir,
		updateConfig.DiscoveryPolicyTypes,
		updateConfig.DiscoveryRuleTypes,
		updateConfig.CIDRBits,
		ignoringFlows,
		updateConfig.L3AggregationLevel,
		updateConfig.L4AggregationLevel,
		updateConfig.L7AggregationLevel,
		updateConfig.HTTPUrlThreshold,
		configName,
	)

	if err != nil {
		return err
	}

	return nil
}

// DeleteConfiguration ...
func DeleteConfiguration(cfg types.ConfigDB, configName string) error {
	db := ConnectMySQL(cfg)
	defer db.Close()

	stmt, err := db.Prepare("DELETE FROM " + cfg.TableConfiguration + "WHERE config_name=?")
	if err != nil {
		return err
	}
	defer stmt.Close()

	_, err = stmt.Exec(configName)
	if err != nil {
		return err
	}

	return nil
}

// ApplyConfiguration ...
func ApplyConfiguration(cfg types.ConfigDB, oldConfigName, configName string) error {
	db := ConnectMySQL(cfg)
	defer db.Close()

	var err error
	stmt1, err := db.Prepare("UPDATE " + cfg.TableConfiguration + " SET status=? WHERE config_name=?")
	if err != nil {
		return err
	}
	defer stmt1.Close()

	_, err = stmt1.Exec(0, oldConfigName)
	if err != nil {
		return err
	}

	stmt2, err := db.Prepare("UPDATE " + cfg.TableConfiguration + " SET status=? WHERE config_name=?")
	if err != nil {
		return err
	}
	defer stmt2.Close()

	_, err = stmt2.Exec(1, configName)
	if err != nil {
		return err
	}

	return nil
}
