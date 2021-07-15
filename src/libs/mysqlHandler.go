package libs

import (
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/accuknox/knoxAutoPolicy/src/types"

	_ "github.com/go-sql-driver/mysql"
)

// ================ //
// == Connection == //
// ================ //

var MockSql sqlmock.Sqlmock = nil
var MockDB *sql.DB = nil

func NewMock() (*sql.DB, sqlmock.Sqlmock) {
	db, mock, err := sqlmock.New()
	if err != nil {
		log.Error().Msgf("an error '%s' was not expected when opening a stub database connection", err)
	}

	MockSql = mock
	MockDB = db

	return db, mock
}

func waitForDB(db *sql.DB) {
	for {
		err := db.Ping()
		if err != nil {
			log.Error().Msg("Cannot reach the database, Retrying.")
			time.Sleep(time.Second * 1)
		} else {
			break
		}
	}
}

func connectMySQL(cfg types.ConfigDB) (db *sql.DB) {
	if MockDB != nil {
		return MockDB
	}

	db, err := sql.Open(cfg.DBDriver, cfg.DBUser+":"+cfg.DBPass+"@tcp("+cfg.DBHost+":"+cfg.DBPort+")/"+cfg.DBName)
	for err != nil {
		log.Error().Msg("connection error :" + err.Error())
		time.Sleep(time.Second * 1)
		db, err = sql.Open(cfg.DBDriver, cfg.DBUser+":"+cfg.DBPass+"@tcp("+cfg.DBHost+":"+cfg.DBPort+")/"+cfg.DBName)
	}

	db.SetMaxIdleConns(0)

	waitForDB(db)

	return db
}

// ================= //
// == Network Log == //
// ================= //

var networkLogQueryBase string = "SELECT id,time,cluster_name,traffic_direction,verdict,policy_match_type,drop_reason,event_type,source,destination,ip,l4,l7 FROM "

func convertDateTimeToUnix(dateTime string) (int64, error) {
	thetime, err := time.Parse(time.RFC3339, dateTime)
	if err != nil {
		return 0, err
	}
	return thetime.Unix(), nil
}

func convertJSONRawToString(raw json.RawMessage) string {
	j, _ := json.Marshal(&raw)
	return string(j)
}

func ScanNetworkLogs(results *sql.Rows) ([]map[string]interface{}, error) {
	networkLogs := []map[string]interface{}{}
	var err error

	for results.Next() {
		var id, time, policyMatchTypeInt, dropReasonInt uint32
		var policyMatchType, dropReason sql.NullInt32
		var verdict, direction, clusterName string
		var srcByte, destByte, eventTypeByte []byte
		var ipByte, l4Byte, l7Byte []byte

		err = results.Scan(
			&id,
			&time,
			&clusterName,
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

		if policyMatchType.Valid {
			policyMatchTypeInt = uint32(policyMatchType.Int32)
		}

		if dropReason.Valid {
			dropReasonInt = uint32(dropReason.Int32)
		}

		if err != nil {
			log.Error().Msg("Error while scanning network logs :" + err.Error())
			return nil, err
		}

		log := map[string]interface{}{
			"id":                id,
			"time":              time,
			"cluster_name":      clusterName,
			"traffic_direction": direction,
			"verdict":           verdict,
			"policy_match_type": policyMatchTypeInt,
			"drop_reason":       dropReasonInt,
			"event_type":        eventTypeByte,
			"source":            srcByte,
			"destination":       destByte,
			"ip":                ipByte,
			"l4":                l4Byte,
			"l7":                l7Byte,
		}

		networkLogs = append(networkLogs, log)
	}

	return networkLogs, nil
}

func GetNetworkLogByTimeFromMySQL(cfg types.ConfigDB, startTime, endTime int64) ([]map[string]interface{}, error) {
	db := connectMySQL(cfg)
	defer db.Close()

	QueryBase := networkLogQueryBase + cfg.TableNetworkLog

	rows, err := db.Query(QueryBase+" WHERE time >= ? and time <= ?", int(startTime), int(endTime))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return ScanNetworkLogs(rows)
}

func GetNetworkLogByIDTimeFromMySQL(cfg types.ConfigDB, id, endTime int64) ([]map[string]interface{}, error) {
	db := connectMySQL(cfg)
	defer db.Close()

	QueryBase := networkLogQueryBase + cfg.TableNetworkLog

	rows, err := db.Query(QueryBase+" WHERE id > ? ORDER BY id ASC ", id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return ScanNetworkLogs(rows)
}

func InsertNetworkLogToMySQL(cfg types.ConfigDB, nfe []types.NetworkLogEvent) error {
	db := connectMySQL(cfg)
	defer db.Close()

	sqlStr := "INSERT INTO " + cfg.TableNetworkLog + "(time,cluster_name,verdict,drop_reason,ethernet,ip,l4,l7,reply,source,destination,type,node_name,event_type,source_service,destination_service,traffic_direction,policy_match_type,trace_observation_point,summary) VALUES "
	vals := []interface{}{}

	for _, e := range nfe {
		sqlStr += "(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?),"
		unixTime, err := convertDateTimeToUnix(e.Time)
		if err != nil {
			log.Error().Msgf("Error converting date time to timestamp: %s", err.Error())
		}

		vals = append(vals,
			unixTime,
			e.ClusterName,
			e.Verdict,
			e.DropReason,
			convertJSONRawToString(e.Ethernet),
			convertJSONRawToString(e.IP),
			convertJSONRawToString(e.L4),
			convertJSONRawToString(e.L7),
			e.Reply,
			convertJSONRawToString(e.Source),
			convertJSONRawToString(e.Destination),
			e.Type,
			e.NodeName,
			convertJSONRawToString(e.EventType),
			convertJSONRawToString(e.SourceService),
			convertJSONRawToString(e.DestinationService),
			e.TrafficDirection,
			e.PolicyMatchType,
			e.TraceObservationPoint,
			e.Summary)
	}

	//trim the last ','
	sqlStr = strings.TrimSuffix(sqlStr, ",")

	//prepare the statement
	stmt, err := db.Prepare(sqlStr)
	if err != nil {
		return err
	}
	defer stmt.Close()

	//format all vals at once
	_, err = stmt.Exec(vals...)
	if err != nil {
		return err
	}

	return nil
}

// ================ //
// == System Log == //
// ================ //

var systemLogQueryBase string = "select id,timestamp,updatedTime,clusterName,hostName,namespaceName,podName,containerID,containerName,hostPid,ppid,pid,uid,type,source,operation,resource,data,result from "

func ScanSystemLogs(results *sql.Rows) ([]map[string]interface{}, error) {
	systemLogs := []map[string]interface{}{}
	var err error

	for results.Next() {
		var id, timestamp, hostPid, ppid, pid, uid uint32
		var updatedTime, clusterName, hostName, namespace, podName, containerID, containerName, types, source, operation, resource, data, result string

		err = results.Scan(
			&id,
			&timestamp,
			&updatedTime, // skip
			&clusterName,
			&hostName,
			&namespace,
			&podName,
			&containerID,
			&containerName,
			&hostPid,
			&ppid,
			&pid,
			&uid,
			&types,
			&source,
			&operation,
			&resource,
			&data,
			&result,
		)

		if err != nil {
			log.Error().Msg("Error while scanning system logs :" + err.Error())
			return nil, err
		}

		log := map[string]interface{}{
			"id":            id,
			"timestamp":     timestamp,
			"clusterName":   clusterName,
			"hostName":      hostName,
			"namespaceName": namespace,
			"podName":       podName,
			"containerID":   containerID,
			"containerName": containerName,
			"hostPid":       hostPid,
			"ppid":          ppid,
			"pid":           pid,
			"uid":           uid,
			"type":          types,
			"source":        source,
			"operation":     operation,
			"resource":      resource,
			"data":          data,
			"result":        result,
		}

		systemLogs = append(systemLogs, log)
	}

	return systemLogs, nil
}

func GetSystemLogByTimeFromMySQL(cfg types.ConfigDB, startTime, endTime int64) ([]map[string]interface{}, error) {
	db := connectMySQL(cfg)
	defer db.Close()

	QueryBase := systemLogQueryBase + cfg.TableSystemLog

	rows, err := db.Query(QueryBase+" WHERE time >= ? and time <= ?", int(startTime), int(endTime))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return ScanSystemLogs(rows)
}

func GetSystemLogByIDTimeFromMySQL(cfg types.ConfigDB, id, endTime int64) ([]map[string]interface{}, error) {
	db := connectMySQL(cfg)
	defer db.Close()

	QueryBase := systemLogQueryBase + cfg.TableSystemLog

	rows, err := db.Query(QueryBase+" WHERE id > ? and timestamp <= ? ORDER BY id ASC ", id, int(endTime))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return ScanSystemLogs(rows)
}

func InsertSystemLogToMySQL(cfg types.ConfigDB, sle []types.SystemLogEvent) error {
	db := connectMySQL(cfg)
	defer db.Close()

	sqlStr := "INSERT INTO " + cfg.TableSystemLog + "(timestamp,updatedTime,clusterName,hostName,namespaceName,podName,containerID,containerName,hostPid,ppid,pid,uid,type,source,operation,resource,data,result) VALUES "
	vals := []interface{}{}

	for _, e := range sle {
		sqlStr += "(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?),"

		vals = append(vals,
			e.Timestamp,
			e.UpdatedTime,
			e.Clustername,
			e.HostName,
			e.NamespaceName,
			e.PodName,
			e.ContainerID,
			e.ContainerName,
			e.HostPID,
			e.PPID,
			e.PID,
			e.UID,
			e.Type,
			e.Source,
			e.Operation,
			e.Resource,
			e.Data,
			e.Result)
	}

	//trim the last ','
	sqlStr = strings.TrimSuffix(sqlStr, ",")

	//prepare the statement
	stmt, err := db.Prepare(sqlStr)
	if err != nil {
		return err
	}
	defer stmt.Close()

	//format all vals at once
	_, err = stmt.Exec(vals...)
	if err != nil {
		return err
	}

	return nil
}

// ================== //
// == System Alert == //
// ================== //

func GetSystemAlertByTimeFromMySQL(cfg types.ConfigDB, startTime, endTime int64) ([]map[string]interface{}, error) {
	db := connectMySQL(cfg)
	defer db.Close()

	QueryBase := systemLogQueryBase + cfg.TableSystemAlert

	rows, err := db.Query(QueryBase+" WHERE time >= ? and time <= ?", int(startTime), int(endTime))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return ScanSystemLogs(rows)
}

func GetSystemAlertByIDTimeFromMySQL(cfg types.ConfigDB, id, endTime int64) ([]map[string]interface{}, error) {
	db := connectMySQL(cfg)
	defer db.Close()

	QueryBase := systemLogQueryBase + cfg.TableSystemAlert

	rows, err := db.Query(QueryBase+" WHERE id > ? and timestamp <= ? ORDER BY id ASC ", id, int(endTime))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return ScanSystemLogs(rows)
}

func InsertSystemAlertToMySQL(cfg types.ConfigDB, sae []types.SystemAlertEvent) error {
	db := connectMySQL(cfg)
	defer db.Close()

	sqlStr := "INSERT INTO " + cfg.TableSystemAlert + "(timestamp,updatedTime,clusterName,hostName,namespaceName,podName,containerID,containerName,hostpid,ppid,pid,uid,policyName,severity,tags,message,type,source,operation,resource,data,action,result) VALUES "
	vals := []interface{}{}

	for _, e := range sae {
		sqlStr += "(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?),"

		vals = append(vals,
			e.Timestamp,
			e.UpdatedTime,
			e.Clustername,
			e.HostName,
			e.NamespaceName,
			e.PodName,
			e.ContainerID,
			e.ContainerName,
			e.HostPID,
			e.PPID,
			e.PID,
			e.UID,
			e.PolicyName,
			e.Severity,
			e.Tags,
			e.Message,
			e.Type,
			e.Source,
			e.Operation,
			e.Resource,
			e.Data,
			e.Action,
			e.Result)
	}

	//trim the last ','
	sqlStr = strings.TrimSuffix(sqlStr, ",")

	//prepare the statement
	stmt, err := db.Prepare(sqlStr)
	if err != nil {
		return err
	}
	defer stmt.Close()

	//format all vals at once
	_, err = stmt.Exec(vals...)
	if err != nil {
		return err
	}

	return nil
}

// ==================== //
// == Network Policy == //
// ==================== //

func GetNetworkPoliciesFromMySQL(cfg types.ConfigDB, cluster, namespace, status string) ([]types.KnoxNetworkPolicy, error) {
	db := connectMySQL(cfg)
	defer db.Close()

	policies := []types.KnoxNetworkPolicy{}
	var results *sql.Rows
	var err error

	query := "SELECT apiVersion,kind,flow_ids,name,cluster_name,namespace,type,rule,status,outdated,spec,generatedTime FROM " + cfg.TableNetworkPolicy + " WHERE cluster_name = ? and namespace = ? "

	if status != "" {
		query = query + " and status = ? "
		results, err = db.Query(query, cluster, namespace, status)
	} else {
		results, err = db.Query(query, cluster, namespace)
	}

	defer results.Close()

	if err != nil {
		log.Error().Msg(err.Error())
		return nil, err
	}

	for results.Next() {
		policy := types.KnoxNetworkPolicy{}

		var name, clusterName, namespace, policyType, rule, status string
		specByte := []byte{}
		spec := types.Spec{}

		flowIDsByte := []byte{}
		flowIDs := []int{}

		if err := results.Scan(
			&policy.APIVersion,
			&policy.Kind,
			&flowIDsByte,
			&name,
			&clusterName,
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

		if err := json.Unmarshal(flowIDsByte, &flowIDs); err != nil {
			return nil, err
		}

		policy.Metadata = map[string]string{
			"name":         name,
			"cluster_name": clusterName,
			"namespace":    namespace,
			"type":         policyType,
			"rule":         rule,
			"status":       status,
		}

		policy.FlowIDs = flowIDs
		policy.Spec = spec

		policies = append(policies, policy)
	}

	return policies, nil
}

func UpdateOutdatedNetworkPolicyFromMySQL(cfg types.ConfigDB, outdatedPolicy string, latestPolicy string) error {
	db := connectMySQL(cfg)
	defer db.Close()

	var err error

	// set status -> outdated
	stmt1, err := db.Prepare("UPDATE " + cfg.TableNetworkPolicy + " SET status=? WHERE name=?")
	if err != nil {
		return err
	}
	defer stmt1.Close()

	_, err = stmt1.Exec("outdated", outdatedPolicy)
	if err != nil {
		return err
	}

	// set outdated -> latest' name
	stmt2, err := db.Prepare("UPDATE " + cfg.TableNetworkPolicy + " SET outdated=? WHERE name=?")
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

func insertNetworkPolicy(cfg types.ConfigDB, db *sql.DB, policy types.KnoxNetworkPolicy) error {
	stmt, err := db.Prepare("INSERT INTO " + cfg.TableNetworkPolicy + "(apiVersion,kind,flow_ids,name,cluster_name,namespace,type,rule,status,outdated,spec,generatedTime) values(?,?,?,?,?,?,?,?,?,?,?,?)")
	if err != nil {
		return err
	}
	defer stmt.Close()

	flowIDsPointer := &policy.FlowIDs
	flowids, err := json.Marshal(flowIDsPointer)
	if err != nil {
		return err
	}

	specPointer := &policy.Spec
	spec, err := json.Marshal(specPointer)
	if err != nil {
		return err
	}

	_, err = stmt.Exec(policy.APIVersion,
		policy.Kind,
		flowids,
		policy.Metadata["name"],
		policy.Metadata["cluster_name"],
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

func InsertNetworkPoliciesToMySQL(cfg types.ConfigDB, policies []types.KnoxNetworkPolicy) error {
	db := connectMySQL(cfg)
	defer db.Close()

	for _, policy := range policies {
		if err := insertNetworkPolicy(cfg, db, policy); err != nil {
			return err
		}
	}

	return nil
}

// =================== //
// == System Policy == //
// =================== //

func UpdateOutdatedSystemPolicyFromMySQL(cfg types.ConfigDB, outdatedPolicy string, latestPolicy string) error {
	db := connectMySQL(cfg)
	defer db.Close()

	var err error

	// set status -> outdated
	stmt1, err := db.Prepare("UPDATE " + cfg.TableSystemPolicy + " SET status=? WHERE name=?")
	if err != nil {
		return err
	}
	defer stmt1.Close()

	_, err = stmt1.Exec("outdated", outdatedPolicy)
	if err != nil {
		return err
	}

	// set outdated -> latest' name
	stmt2, err := db.Prepare("UPDATE " + cfg.TableNetworkPolicy + " SET outdated=? WHERE name=?")
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

func GetSystemPoliciesFromMySQL(cfg types.ConfigDB, namespace, status string) ([]types.KnoxSystemPolicy, error) {
	db := connectMySQL(cfg)
	defer db.Close()

	policies := []types.KnoxSystemPolicy{}
	var results *sql.Rows
	var err error

	query := "SELECT apiVersion,kind,name,clusterName,namespace,type,status,outdated,spec,generatedTime FROM " +
		cfg.TableSystemPolicy

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
		policy := types.KnoxSystemPolicy{}

		var name, clusterName, namespace, policyType, status string
		specByte := []byte{}
		spec := types.KnoxSystemSpec{}

		if err := results.Scan(
			&policy.APIVersion,
			&policy.Kind,
			&name,
			&clusterName,
			&namespace,
			&policyType,
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
			"name":        name,
			"clusterName": clusterName,
			"namespace":   namespace,
			"type":        policyType,
			"status":      status,
		}

		policy.Spec = spec

		policies = append(policies, policy)
	}

	return policies, nil
}

func insertSystemPolicy(cfg types.ConfigDB, db *sql.DB, policy types.KnoxSystemPolicy) error {
	stmt, err := db.Prepare("INSERT INTO " + cfg.TableSystemPolicy + "(apiVersion,kind,name,clusterName,namespace,type,status,outdated,spec,generatedTime) values(?,?,?,?,?,?,?,?,?,?)")
	if err != nil {
		return err
	}
	defer stmt.Close()

	specPointer := &policy.Spec
	spec, err := json.Marshal(specPointer)
	if err != nil {
		return err
	}

	_, err = stmt.Exec(
		policy.APIVersion,
		policy.Kind,
		policy.Metadata["name"],
		policy.Metadata["clusterName"],
		policy.Metadata["namespace"],
		policy.Metadata["type"],
		policy.Metadata["status"],
		policy.Outdated,
		spec,
		policy.GeneratedTime)
	if err != nil {
		return err
	}

	return nil
}

func InsertSystemPoliciesToMySQL(cfg types.ConfigDB, policies []types.KnoxSystemPolicy) error {
	db := connectMySQL(cfg)
	defer db.Close()

	for _, policy := range policies {
		if err := insertSystemPolicy(cfg, db, policy); err != nil {
			return err
		}
	}

	return nil
}

// =================== //
// == Configuration == //
// =================== //

func CountConfigByName(db *sql.DB, tableName, configName string) int {
	var count int

	if err := db.QueryRow("SELECT COUNT(*) FROM "+tableName+" WHERE config_name=?", configName).Scan(&count); err != nil {
		log.Error().Msg(err.Error())
	}

	return count
}

func AddConfiguration(cfg types.ConfigDB, newConfig types.Configuration) error {
	db := connectMySQL(cfg)
	defer db.Close()

	table := cfg.TableConfiguration
	if table == "" {
		table = "auto_policy_config"
	}

	if CountConfigByName(db, table, newConfig.ConfigName) > 0 {
		return errors.New("Already exist config name: " + newConfig.ConfigName)
	}

	stmt, err := db.Prepare("INSERT INTO " + table +
		"(config_name," +
		"status," +
		"config_db," +
		"config_cilium_hubble," +

		"network_operation_mode," +
		"network_cronjob_time_interval," +
		"network_one_time_job_time_selection," +
		"network_log_from," +
		"network_log_file," +
		"network_policy_to," +
		"network_policy_dir," +
		"network_policy_log_filters," +
		"network_policy_types," +
		"network_policy_rule_types," +
		"network_policy_cidr_bits," +
		"network_policy_l3_level," +
		"network_policy_l4_level," +
		"network_policy_l7_level," +

		"system_operation_mode," +
		"system_cronjob_time_interval," +
		"system_one_time_job_time_selection," +
		"system_log_from," +
		"system_log_file," +
		"system_policy_to," +
		"system_policy_dir," +
		"system_policy_types," +
		"system_policy_log_filters," +
		"system_policy_proc_fromsource," +
		"system_policy_file_fromsource," +

		"cluster_info_from," +
		"cluster_mgmt_url) " +

		"values(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)")

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

	// network log filters
	netLogFiltersPtr := &newConfig.ConfigNetPolicy.NetLogFilters
	netLogFilters, err := json.Marshal(netLogFiltersPtr)
	if err != nil {
		return err
	}

	// system log filters
	sysLogFiltersPtr := &newConfig.ConfigSysPolicy.SystemLogFilters
	sysLogFilters, err := json.Marshal(sysLogFiltersPtr)
	if err != nil {
		return err
	}

	_, err = stmt.Exec(
		newConfig.ConfigName,
		newConfig.Status,
		configDB,
		configCilium,

		newConfig.ConfigNetPolicy.OperationMode,
		newConfig.ConfigNetPolicy.CronJobTimeInterval,
		newConfig.ConfigNetPolicy.OneTimeJobTimeSelection,
		newConfig.ConfigNetPolicy.NetworkLogFrom,
		newConfig.ConfigNetPolicy.NetworkLogFile,
		newConfig.ConfigNetPolicy.NetworkPolicyTo,
		newConfig.ConfigNetPolicy.NetworkPolicyDir,
		netLogFilters,
		newConfig.ConfigNetPolicy.NetPolicyTypes,
		newConfig.ConfigNetPolicy.NetPolicyRuleTypes,
		newConfig.ConfigNetPolicy.NetPolicyCIDRBits,
		newConfig.ConfigNetPolicy.NetPolicyL3Level,
		newConfig.ConfigNetPolicy.NetPolicyL4Level,
		newConfig.ConfigNetPolicy.NetPolicyL7Level,

		newConfig.ConfigSysPolicy.OperationMode,
		newConfig.ConfigSysPolicy.CronJobTimeInterval,
		newConfig.ConfigSysPolicy.OneTimeJobTimeSelection,
		newConfig.ConfigSysPolicy.SystemLogFrom,
		newConfig.ConfigSysPolicy.SystemLogFile,
		newConfig.ConfigSysPolicy.SystemPolicyTo,
		newConfig.ConfigSysPolicy.SystemPolicyDir,
		newConfig.ConfigSysPolicy.SysPolicyTypes,
		sysLogFilters,
		newConfig.ConfigSysPolicy.ProcessFromSource,
		newConfig.ConfigSysPolicy.FileFromSource,

		newConfig.ConfigClusterMgmt.ClusterInfoFrom,
		newConfig.ConfigClusterMgmt.ClusterMgmtURL,
	)

	if err != nil {
		return err
	}

	return nil
}

func GetConfigurations(cfg types.ConfigDB, configName string) ([]types.Configuration, error) {
	db := connectMySQL(cfg)
	defer db.Close()

	configs := []types.Configuration{}
	var results *sql.Rows
	var err error

	table := cfg.TableConfiguration
	if table == "" {
		table = "auto_policy_config"
	}

	query := "SELECT * FROM " + table
	if configName != "" {
		query = query + " WHERE config_name = ? "
	}

	results, err = db.Query(query, configName)
	if err != nil {
		log.Error().Msg(err.Error())
		return nil, err
	}
	defer results.Close()

	for results.Next() {
		cfg := types.Configuration{
			ConfigNetPolicy:   types.ConfigNetworkPolicy{},
			ConfigSysPolicy:   types.ConfigSystemPolicy{},
			ConfigClusterMgmt: types.ConfigClusterMgmt{},
		}

		id := 0
		configDBByte := []byte{}
		configDB := types.ConfigDB{}

		hubbleByte := []byte{}
		hubble := types.ConfigCiliumHubble{}

		netLogFiltersByte := []byte{}
		netLogFilters := []types.NetworkLogFilter{}

		sysLogFiltersByte := []byte{}
		sysLogFilters := []types.SystemLogFilter{}

		if err := results.Scan(
			&id,
			&cfg.ConfigName,
			&cfg.Status,
			&configDBByte,
			&hubbleByte,

			&cfg.ConfigNetPolicy.OperationMode,
			&cfg.ConfigNetPolicy.CronJobTimeInterval,
			&cfg.ConfigNetPolicy.OneTimeJobTimeSelection,
			&cfg.ConfigNetPolicy.NetworkLogFrom,
			&cfg.ConfigNetPolicy.NetworkLogFile,
			&cfg.ConfigNetPolicy.NetworkPolicyTo,
			&cfg.ConfigNetPolicy.NetworkPolicyDir,
			&netLogFiltersByte,
			&cfg.ConfigNetPolicy.NetPolicyTypes,
			&cfg.ConfigNetPolicy.NetPolicyRuleTypes,
			&cfg.ConfigNetPolicy.NetPolicyCIDRBits,
			&cfg.ConfigNetPolicy.NetPolicyL3Level,
			&cfg.ConfigNetPolicy.NetPolicyL4Level,
			&cfg.ConfigNetPolicy.NetPolicyL7Level,

			&cfg.ConfigSysPolicy.OperationMode,
			&cfg.ConfigSysPolicy.CronJobTimeInterval,
			&cfg.ConfigSysPolicy.OneTimeJobTimeSelection,
			&cfg.ConfigSysPolicy.SystemLogFrom,
			&cfg.ConfigSysPolicy.SystemLogFile,
			&cfg.ConfigSysPolicy.SystemPolicyTo,
			&cfg.ConfigSysPolicy.SystemPolicyDir,
			&cfg.ConfigSysPolicy.SysPolicyTypes,
			&sysLogFiltersByte,
			&cfg.ConfigSysPolicy.ProcessFromSource,
			&cfg.ConfigSysPolicy.FileFromSource,

			&cfg.ConfigClusterMgmt.ClusterInfoFrom,
			&cfg.ConfigClusterMgmt.ClusterMgmtURL,
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

		if err := json.Unmarshal(netLogFiltersByte, &netLogFilters); err != nil {
			return nil, err
		}
		cfg.ConfigNetPolicy.NetLogFilters = netLogFilters

		if err := json.Unmarshal(sysLogFiltersByte, &sysLogFilters); err != nil {
			return nil, err
		}
		cfg.ConfigSysPolicy.SystemLogFilters = sysLogFilters

		configs = append(configs, cfg)
	}

	return configs, nil
}

func UpdateConfiguration(cfg types.ConfigDB, configName string, updateConfig types.Configuration) error {
	db := connectMySQL(cfg)
	defer db.Close()

	var err error

	table := cfg.TableConfiguration
	if table == "" {
		table = "auto_policy_config"
	}

	stmt, err := db.Prepare("UPDATE " + table + " SET " +
		"config_db=?," +
		"config_cilium_hubble=?," +

		"network_operation_mode=?," +
		"network_cronjob_time_interval=?," +
		"network_one_time_job_time_selection=?," +
		"network_log_from=?," +
		"network_log_file=?," +
		"network_policy_to=?," +
		"network_policy_dir=?," +
		"network_policy_log_filters=?," +
		"network_policy_types=?," +
		"network_policy_rule_types=?," +
		"network_policy_cidr_bits=?," +
		"network_policy_l3_level=?," +
		"network_policy_l4_level=?," +
		"network_policy_l7_level=?," +

		"system_operation_mode=?," +
		"system_cronjob_time_interval=?," +
		"system_one_time_job_time_selection=?," +
		"system_log_from=?," +
		"system_log_file=?," +
		"system_policy_to=?," +
		"system_policy_dir=?," +
		"system_policy_types=?," +
		"system_policy_log_filters=?," +
		"system_policy_proc_fromsource=?," +
		"system_policy_file_fromsource=?," +

		"cluster_info_from=?," +
		"cluster_mgmt_url=? " +

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

	netLogFiltersPtr := &updateConfig.ConfigNetPolicy.NetLogFilters
	netLogFilters, err := json.Marshal(netLogFiltersPtr)
	if err != nil {
		return err
	}

	sysLogFiltersByte := &updateConfig.ConfigSysPolicy.SystemLogFilters
	sysLogFilters, err := json.Marshal(sysLogFiltersByte)
	if err != nil {
		return err
	}

	_, err = stmt.Exec(
		configDB,
		configCilium,

		updateConfig.ConfigNetPolicy.OperationMode,
		updateConfig.ConfigNetPolicy.CronJobTimeInterval,
		updateConfig.ConfigNetPolicy.OneTimeJobTimeSelection,
		updateConfig.ConfigNetPolicy.NetworkLogFrom,
		updateConfig.ConfigNetPolicy.NetworkLogFile,
		updateConfig.ConfigNetPolicy.NetworkPolicyTo,
		updateConfig.ConfigNetPolicy.NetworkPolicyDir,
		netLogFilters,
		updateConfig.ConfigNetPolicy.NetPolicyTypes,
		updateConfig.ConfigNetPolicy.NetPolicyRuleTypes,
		updateConfig.ConfigNetPolicy.NetPolicyCIDRBits,
		updateConfig.ConfigNetPolicy.NetPolicyL3Level,
		updateConfig.ConfigNetPolicy.NetPolicyL4Level,
		updateConfig.ConfigNetPolicy.NetPolicyL7Level,

		updateConfig.ConfigSysPolicy.OperationMode,
		updateConfig.ConfigSysPolicy.CronJobTimeInterval,
		updateConfig.ConfigSysPolicy.OneTimeJobTimeSelection,
		updateConfig.ConfigSysPolicy.SystemLogFrom,
		updateConfig.ConfigSysPolicy.SystemLogFile,
		updateConfig.ConfigSysPolicy.SystemPolicyTo,
		updateConfig.ConfigSysPolicy.SystemPolicyDir,
		updateConfig.ConfigSysPolicy.SysPolicyTypes,
		sysLogFilters,
		updateConfig.ConfigSysPolicy.ProcessFromSource,
		updateConfig.ConfigSysPolicy.FileFromSource,

		updateConfig.ConfigClusterMgmt.ClusterInfoFrom,
		updateConfig.ConfigClusterMgmt.ClusterMgmtURL,

		configName,
	)

	if err != nil {
		return err
	}

	return nil
}

func DeleteConfiguration(cfg types.ConfigDB, configName string) error {
	db := connectMySQL(cfg)
	defer db.Close()

	table := cfg.TableConfiguration
	if table == "" {
		table = "auto_policy_config"
	}

	stmt, err := db.Prepare("DELETE FROM " + table + " WHERE config_name=?")
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

func ApplyConfiguration(cfg types.ConfigDB, oldConfigName, configName string) error {
	db := connectMySQL(cfg)
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

// =========== //
// == Table == //
// =========== //

func ClearDBTablesMySQL(cfg types.ConfigDB) error {
	db := connectMySQL(cfg)
	defer db.Close()

	query := "DELETE FROM " + cfg.TableNetworkLog
	if _, err := db.Query(query); err != nil {
		return err
	}

	query = "DELETE FROM " + cfg.TableNetworkPolicy
	if _, err := db.Query(query); err != nil {
		return err
	}

	query = "DELETE FROM " + cfg.TableSystemLog
	if _, err := db.Query(query); err != nil {
		return err
	}

	query = "DELETE FROM " + cfg.TableSystemPolicy
	if _, err := db.Query(query); err != nil {
		return err
	}

	return nil
}

func CreateTableConfigurationMySQL(cfg types.ConfigDB) error {
	db := connectMySQL(cfg)
	defer db.Close()

	tableName := cfg.TableConfiguration

	// the number of column --> 29
	query :=
		"CREATE TABLE IF NOT EXISTS `" + tableName + "` ( " +
			"	`id` int NOT NULL AUTO_INCREMENT, " +
			"	`config_name` varchar(50) DEFAULT NULL, " +
			"	`status` int DEFAULT '0', " +
			"	`config_db` JSON DEFAULT NULL, " +
			"	`config_cilium_hubble` JSON DEFAULT NULL, " +

			"	`network_operation_mode` int DEFAULT NULL, " +
			"	`network_cronjob_time_interval` varchar(50) DEFAULT NULL, " +
			"	`network_one_time_job_time_selection` varchar(50) DEFAULT NULL, " +
			"	`network_log_from` varchar(50) DEFAULT NULL, " +
			"	`network_log_file` varchar(50) DEFAULT NULL, " +
			"	`network_policy_to` varchar(50) DEFAULT NULL, " +
			"	`network_policy_dir` varchar(50) DEFAULT NULL, " +
			"	`network_policy_log_filters` JSON DEFAULT NULL, " +
			"	`network_policy_types` int DEFAULT NULL, " +
			"	`network_policy_rule_types` int DEFAULT NULL, " +
			"	`network_policy_cidr_bits` int DEFAULT NULL, " +
			"	`network_policy_l3_level` int DEFAULT NULL, " +
			"	`network_policy_l4_level` int DEFAULT NULL, " +
			"	`network_policy_l7_level` int DEFAULT NULL, " +

			"	`system_operation_mode` int DEFAULT NULL, " +
			"	`system_cronjob_time_interval` varchar(50) DEFAULT NULL, " +
			"	`system_one_time_job_time_selection` varchar(50) DEFAULT NULL, " +
			"	`system_log_from` varchar(50) DEFAULT NULL, " +
			"	`system_log_file` varchar(50) DEFAULT NULL, " +
			"	`system_policy_to` varchar(50) DEFAULT NULL, " +
			"	`system_policy_dir` varchar(50) DEFAULT NULL, " +
			"	`system_policy_types` int DEFAULT NULL, " +
			"	`system_policy_log_filters` JSON DEFAULT NULL, " +
			"	`system_policy_proc_fromsource` tinyint(1) DEFAULT '0', " +
			"	`system_policy_file_fromsource` tinyint(1) DEFAULT '0', " +

			"	`cluster_info_from` varchar(50) DEFAULT NULL, " +
			"	`cluster_mgmt_url` varchar(50) DEFAULT NULL, " +

			"	PRIMARY KEY (`id`) " +
			"  ); "

	if _, err := db.Query(query); err != nil {
		return err
	}

	return nil
}

func CreateTableNetworkLogMySQL(cfg types.ConfigDB) error {
	db := connectMySQL(cfg)
	defer db.Close()

	tableName := cfg.TableNetworkLog

	query :=
		"CREATE TABLE IF NOT EXISTS `" + tableName + "` (" +
			"	`id` int NOT NULL AUTO_INCREMENT," +
			"	`time` int DEFAULT NULL," +
			"	`cluster_name` varchar(100) DEFAULT NULL," +
			"	`verdict` varchar(50) DEFAULT NULL," +
			"	`drop_reason` INT DEFAULT NULL," +
			"	`ethernet` JSON DEFAULT NULL," +
			"	`ip` JSON DEFAULT NULL," +
			"	`l4` JSON DEFAULT NULL," +
			"	`l7` JSON DEFAULT NULL," +
			"	`reply` BOOLEAN," +
			"	`source` JSON DEFAULT NULL," +
			"	`destination` JSON DEFAULT NULL," +
			"	`type` varchar(50) DEFAULT NULL," +
			"	`node_name` varchar(100) DEFAULT NULL," +
			"	`event_type` JSON DEFAULT NULL," +
			"	`source_service` JSON DEFAULT NULL," +
			"	`destination_service` JSON DEFAULT NULL," +
			"	`traffic_direction` varchar(50) DEFAULT NULL," +
			"	`policy_match_type` int DEFAULT NULL," +
			"	`trace_observation_point` varchar(100) DEFAULT NULL," +
			"	`summary` varchar(1000) DEFAULT NULL," +
			"	PRIMARY KEY (`id`)" +
			");"

	if _, err := db.Query(query); err != nil {
		return err
	}

	return nil
}

func CreateTableNetworkPolicyMySQL(cfg types.ConfigDB) error {
	db := connectMySQL(cfg)
	defer db.Close()

	tableName := cfg.TableNetworkPolicy

	query :=
		"CREATE TABLE IF NOT EXISTS `" + tableName + "` (" +
			"	`id` int NOT NULL AUTO_INCREMENT," +
			"	`apiVersion` varchar(20) DEFAULT NULL," +
			"	`kind` varchar(20) DEFAULT NULL," +
			"	`flow_ids` JSON DEFAULT NULL," +
			"	`name` varchar(50) DEFAULT NULL," +
			"	`cluster_name` varchar(50) DEFAULT NULL," +
			"	`namespace` varchar(50) DEFAULT NULL," +
			"	`type` varchar(10) DEFAULT NULL," +
			"	`rule` varchar(30) DEFAULT NULL," +
			"	`status` varchar(10) DEFAULT NULL," +
			"	`outdated` varchar(50) DEFAULT NULL," +
			"	`spec` JSON DEFAULT NULL," +
			"	`generatedTime` int DEFAULT NULL," +
			"	PRIMARY KEY (`id`)" +
			"  );"

	if _, err := db.Query(query); err != nil {
		return err
	}

	return nil
}

func CreateTableSystemLogMySQL(cfg types.ConfigDB) error {
	db := connectMySQL(cfg)
	defer db.Close()

	tableName := cfg.TableSystemLog

	query :=
		"CREATE TABLE IF NOT EXISTS `" + tableName + "` (" +
			"    `id` int NOT NULL AUTO_INCREMENT," +
			"    `timestamp` int NOT NULL," +
			"    `updatedTime` varchar(30) NOT NULL," +
			"    `clusterName` varchar(100) NOT NULL," +
			"    `hostName` varchar(100) NOT NULL," +
			"    `namespaceName` varchar(100) NOT NULL," +
			"    `podName` varchar(200) NOT NULL," +
			"    `containerID` varchar(200) NOT NULL," +
			"    `containerName` varchar(200) NOT NULL," +
			"    `hostPid` int NOT NULL," +
			"    `ppid` int NOT NULL," +
			"    `pid` int NOT NULL," +
			"    `uid` int NOT NULL," +
			"    `type` varchar(20) NOT NULL," +
			"    `source` varchar(4000) NOT NULL," +
			"    `operation` varchar(20) NOT NULL," +
			"    `resource` varchar(4000) NOT NULL," +
			"    `data` varchar(1000) DEFAULT NULL," +
			"    `result` varchar(200) NOT NULL," +
			"    PRIMARY KEY (`id`)" +
			");"

	if _, err := db.Query(query); err != nil {
		return err
	}

	return nil
}

func CreateTableSystemAlertMySQL(cfg types.ConfigDB) error {
	db := connectMySQL(cfg)
	defer db.Close()

	tableName := cfg.TableSystemAlert

	query :=
		"CREATE TABLE IF NOT EXISTS `" + tableName + "` (" +
			"    `id` int NOT NULL AUTO_INCREMENT," +
			"    `timestamp` int NOT NULL," +
			"    `updatedTime` varchar(30) NOT NULL," +
			"    `clusterName` varchar(100) NOT NULL," +
			"    `hostName` varchar(100) NOT NULL," +
			"    `namespaceName` varchar(100) NOT NULL," +
			"    `podName` varchar(200) NOT NULL," +
			"    `containerID` varchar(200) NOT NULL," +
			"    `containerName` varchar(200) NOT NULL," +
			"    `hostPid` int NOT NULL," +
			"    `ppid` int NOT NULL," +
			"    `pid` int NOT NULL," +
			"    `uid` int NOT NULL," +
			"    `policyName` varchar(1000) NOT NULL," +
			"    `severity` varchar(100) NOT NULL," +
			"    `tags` varchar(1000) NOT NULL," +
			"    `message` varchar(1000) NOT NULL," +
			"    `type` varchar(20) NOT NULL," +
			"    `source` varchar(4000) NOT NULL," +
			"    `operation` varchar(20) NOT NULL," +
			"    `resource` varchar(4000) NOT NULL," +
			"    `data` varchar(1000) DEFAULT NULL," +
			"    `action` varchar(20) NOT NULL," +
			"    `result` varchar(200) NOT NULL," +
			"    PRIMARY KEY (`id`)" +
			");"

	if _, err := db.Query(query); err != nil {
		return err
	}

	return nil
}

func CreateTableSystemPolicyMySQL(cfg types.ConfigDB) error {
	db := connectMySQL(cfg)
	defer db.Close()

	tableName := cfg.TableSystemPolicy

	query :=
		"CREATE TABLE IF NOT EXISTS `" + tableName + "` (" +
			"	`id` int NOT NULL AUTO_INCREMENT," +
			"	`apiVersion` varchar(40) DEFAULT NULL," +
			"	`kind` varchar(20) DEFAULT NULL," +
			"	`name` varchar(50) DEFAULT NULL," +
			"	`clusterName` varchar(50) DEFAULT NULL," +
			"	`namespace` varchar(50) DEFAULT NULL," +
			"   `type` varchar(20) NOT NULL," +
			"	`status` varchar(10) DEFAULT NULL," +
			"	`outdated` varchar(50) DEFAULT NULL," +
			"	`spec` JSON DEFAULT NULL," +
			"	`generatedTime` int DEFAULT NULL," +
			"	PRIMARY KEY (`id`)" +
			"  );"

	if _, err := db.Query(query); err != nil {
		return err
	}

	return nil
}
