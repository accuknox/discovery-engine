package libs

import (
	"database/sql"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/accuknox/auto-policy-discovery/src/types"

	_ "github.com/mattn/go-sqlite3"
)

const WorkloadProcessFileSetSQLite_TableName = "workload_process_fileset"
const TableNetworkPolicySQLite_TableName = "network_policy"
const TableSystemPolicySQLite_TableName = "system_policy"
const TableSystemLogsSQLite_TableName = "system_logs"
const TableNetworkLogsSQLite_TableName = "network_logs"

// ================ //
// == Connection == //
// ================ //

var MockSqlite sqlmock.Sqlmock = nil
var MockDBSQLite *sql.DB = nil

func NewMockSQLite() (*sql.DB, sqlmock.Sqlmock) {
	db, mock, err := sqlmock.New()
	if err != nil {
		log.Error().Msgf("an error '%s' was not expected when opening a stub database connection", err)
	}

	MockSqlite = mock
	MockDBSQLite = db

	return db, mock
}

func waitForDBSQLite(db *sql.DB) {
	for {
		err := db.Ping()
		if err != nil {
			time.Sleep(time.Second * 1)
			log.Error().Msgf("db.Ping() failed. Will retry. err=%s", err.Error())
		} else {
			break
		}
	}
}

func connectSQLite(cfg types.ConfigDB) (db *sql.DB) {
	if MockDB != nil {
		return MockDB
	}

	dbconn := cfg.DBUser + ":" + cfg.DBPass + "@tcp(" + cfg.DBHost + ":" + cfg.DBPort + ")/" + cfg.DBName
	db, err := sql.Open(cfg.DBDriver, cfg.SQLiteDBPath)
	for err != nil {
		log.Error().Msgf("sqlite driver:%s, user:%s, host:%s, port:%s, dbname:%s conn-error:%s",
			cfg.DBDriver, cfg.DBUser, cfg.DBHost, cfg.DBPort, cfg.DBName, err.Error())
		time.Sleep(time.Second * 1)
		db, err = sql.Open(cfg.DBDriver, dbconn)
	}

	db.SetMaxIdleConns(0)

	waitForDBSQLite(db)

	return db
}

// ==================== //
// == Network Policy == //
// ==================== //

func GetNetworkPoliciesFromSQLite(cfg types.ConfigDB, cluster, namespace, status string) ([]types.KnoxNetworkPolicy, error) {
	db := connectSQLite(cfg)
	defer db.Close()

	policies := []types.KnoxNetworkPolicy{}
	var results *sql.Rows
	var err error

	query := "SELECT apiVersion,kind,flow_ids,name,cluster_name,namespace,type,rule,status,outdated,spec,generatedTime FROM " + TableNetworkPolicySQLite_TableName
	if cluster != "" && namespace != "" && status != "" {
		query = query + " WHERE cluster_name = ? and namespace = ? and status = ? "
		results, err = db.Query(query, cluster, namespace, status)
	} else if cluster != "" && status != "" {
		query = query + " WHERE cluster_name = ? and status = ? "
		results, err = db.Query(query, cluster, status)
	} else if namespace != "" && status != "" {
		query = query + " WHERE namespace = ? and status = ? "
		results, err = db.Query(query, namespace, status)
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

func UpdateOutdatedNetworkPolicyFromSQLite(cfg types.ConfigDB, outdatedPolicy string, latestPolicy string) error {
	db := connectSQLite(cfg)
	defer db.Close()

	var err error

	// set status -> outdated
	stmt1, err := db.Prepare("UPDATE " + TableNetworkPolicySQLite_TableName + " SET status=? WHERE name=?")
	if err != nil {
		return err
	}
	defer stmt1.Close()

	_, err = stmt1.Exec("outdated", outdatedPolicy)
	if err != nil {
		return err
	}

	// set outdated -> latest' name
	stmt2, err := db.Prepare("UPDATE " + TableNetworkPolicySQLite_TableName + " SET outdated=? WHERE name=?")
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

func insertNetworkPolicySQLite(cfg types.ConfigDB, db *sql.DB, policy types.KnoxNetworkPolicy) error {
	stmt, err := db.Prepare("INSERT INTO " + TableNetworkPolicySQLite_TableName + "(apiVersion,kind,flow_ids,name,cluster_name,namespace,type,rule,status,outdated,spec,generatedTime) values(?,?,?,?,?,?,?,?,?,?,?,?)")
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

func InsertNetworkPoliciesToSQLite(cfg types.ConfigDB, policies []types.KnoxNetworkPolicy) error {
	db := connectSQLite(cfg)
	defer db.Close()

	for _, policy := range policies {
		if err := insertNetworkPolicySQLite(cfg, db, policy); err != nil {
			return err
		}
	}

	return nil
}

// =================== //
// == System Policy == //
// =================== //

func UpdateOutdatedSystemPolicyFromSQLite(cfg types.ConfigDB, outdatedPolicy string, latestPolicy string) error {
	db := connectSQLite(cfg)
	defer db.Close()

	var err error

	// set status -> outdated
	stmt1, err := db.Prepare("UPDATE " + TableSystemPolicySQLite_TableName + " SET status=? WHERE name=?")
	if err != nil {
		return err
	}
	defer stmt1.Close()

	_, err = stmt1.Exec("outdated", outdatedPolicy)
	if err != nil {
		return err
	}

	// set outdated -> latest' name
	stmt2, err := db.Prepare("UPDATE " + TableNetworkPolicySQLite_TableName + " SET outdated=? WHERE name=?")
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

func GetSystemPoliciesFromSQLite(cfg types.ConfigDB, namespace, status string) ([]types.KnoxSystemPolicy, error) {
	db := connectSQLite(cfg)
	defer db.Close()

	policies := []types.KnoxSystemPolicy{}
	var results *sql.Rows
	var err error

	query := "SELECT apiVersion,kind,name,clusterName,namespace,type,status,outdated,spec,generatedTime FROM " + TableSystemPolicySQLite_TableName

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

	if err != nil {
		log.Error().Msg(err.Error())
		return nil, err
	}

	defer results.Close()

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

func insertSystemPolicySQLite(cfg types.ConfigDB, db *sql.DB, policy types.KnoxSystemPolicy) error {
	stmt, err := db.Prepare("INSERT INTO " + TableSystemPolicySQLite_TableName + "(apiVersion,kind,name,clusterName,namespace,type,status,outdated,spec,generatedTime) values(?,?,?,?,?,?,?,?,?,?)")
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

func InsertSystemPoliciesToSQLite(cfg types.ConfigDB, policies []types.KnoxSystemPolicy) error {
	db := connectSQLite(cfg)
	defer db.Close()

	for _, policy := range policies {
		if err := insertSystemPolicySQLite(cfg, db, policy); err != nil {
			return err
		}
	}

	return nil
}

func UpdateSystemPolicyToSQLite(cfg types.ConfigDB, policy types.KnoxSystemPolicy) error {
	db := connectSQLite(cfg)
	defer db.Close()

	// set status -> outdated
	stmt, err := db.Prepare("UPDATE " + TableSystemPolicySQLite_TableName +
		" SET apiVersion=?,kind=?,clusterName=?,namespace=?,type=?,status=?,outdated=?,spec=?,generatedTime=? WHERE name = ?")
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
		policy.Metadata["clusterName"],
		policy.Metadata["namespace"],
		policy.Metadata["type"],
		policy.Metadata["status"],
		policy.Outdated,
		spec,
		policy.GeneratedTime,
		policy.Metadata["name"])
	if err != nil {
		return err
	}

	return nil
}

// =========== //
// == Table == //
// =========== //

func ClearDBTablesSQLite(cfg types.ConfigDB) error {
	db := connectSQLite(cfg)
	defer db.Close()

	query := "DELETE FROM " + TableNetworkPolicySQLite_TableName
	if _, err := db.Query(query); err != nil {
		return err
	}

	query = "DELETE FROM " + TableSystemPolicySQLite_TableName
	if _, err := db.Query(query); err != nil {
		return err
	}

	query = "DELETE FROM " + WorkloadProcessFileSetSQLite_TableName
	if _, err := db.Query(query); err != nil {
		return err
	}

	return nil
}

func CreateTableNetworkPolicySQLite(cfg types.ConfigDB) error {
	db := connectSQLite(cfg)
	defer db.Close()

	tableName := TableNetworkPolicySQLite_TableName

	query :=
		"CREATE TABLE IF NOT EXISTS `" + tableName + "` (" +
			"	`id` INTEGER AUTO_INCREMENT," +
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

	if _, err := db.Exec(query); err != nil {
		return err
	}

	return nil
}

func CreateTableSystemPolicySQLite(cfg types.ConfigDB) error {
	db := connectSQLite(cfg)
	defer db.Close()

	tableName := TableSystemPolicySQLite_TableName

	query :=
		"CREATE TABLE IF NOT EXISTS `" + tableName + "` (" +
			"	`id` INTEGER AUTO_INCREMENT," +
			"	`apiVersion` varchar(40) DEFAULT NULL," +
			"	`kind` varchar(20) DEFAULT NULL," +
			"	`name` varchar(128) DEFAULT NULL," +
			"	`clusterName` varchar(50) DEFAULT NULL," +
			"	`namespace` varchar(50) DEFAULT NULL," +
			"   `type` varchar(20) NOT NULL," +
			"	`status` varchar(10) DEFAULT NULL," +
			"	`outdated` varchar(50) DEFAULT NULL," +
			"	`spec` JSON DEFAULT NULL," +
			"	`generatedTime` int DEFAULT NULL," +
			"	PRIMARY KEY (`id`)" +
			"  );"

	if _, err := db.Exec(query); err != nil {
		return err
	}

	return nil
}

func CreateTableWorkLoadProcessFileSetSQLite(cfg types.ConfigDB) error {
	db := connectSQLite(cfg)
	defer db.Close()

	tableName := WorkloadProcessFileSetSQLite_TableName

	query :=
		"CREATE TABLE IF NOT EXISTS `" + tableName + "` (" +
			"	`id` INTEGER AUTO_INCREMENT," +
			"	`policyName` varchar(128) DEFAULT NULL," +
			"	`clusterName` varchar(50) DEFAULT NULL," +
			"	`namespace` varchar(50) DEFAULT NULL," +
			"   `containerName` varchar(100) NOT NULL," +
			"	`labels` varchar(1000) DEFAULT NULL," +
			"	`fromSource` varchar(256) DEFAULT NULL," +
			"	`settype` varchar(16) DEFAULT NULL," + // settype: "file" or "process"
			"	`fileset` text DEFAULT NULL," +
			"	`createdTime` bigint NOT NULL," +
			"	`updatedTime` bigint NOT NULL," +
			"	PRIMARY KEY (`id`)" +
			"  );"

	_, err := db.Exec(query)
	return err
}

func CreateTableSystemLogsSQLite(cfg types.ConfigDB) error {
	db := connectSQLite(cfg)
	defer db.Close()

	tableName := TableSystemLogsSQLite_TableName

	query :=
		"CREATE TABLE IF NOT EXISTS `" + tableName + "` (" +
			"	`id` integer NOT NULL PRIMARY KEY AUTO_INCREMENT," +
			"	`cluster_name` varchar(50) DEFAULT NULL," +
			"	`host_name` varchar(50) DEFAULT NULL," +
			"	`namespace_name` varchar(50) DEFAULT NULL," +
			"	`pod_name` varchar(50) DEFAULT NULL," +
			"	`container_id` varchar(100) DEFAULT NULL," +
			"	`container_name` varchar(100) DEFAULT NULL," +
			"	`uid` INTEGER," +
			"	`type` varchar(50) DEFAULT NULL," +
			"	`source` varchar(250) DEFAULT NULL," +
			"	`operation` varchar(250) DEFAULT NULL," +
			"	`resource` varchar(250) DEFAULT NULL," +
			"	`labels` varchar(250) DEFAULT NULL," +
			"	`data` varchar(250) DEFAULT NULL," +
			"	`category` varchar(50) DEFAULT NULL," +
			"	`action` varchar(50) DEFAULT NULL," +
			"	`start_time` bigint DEFAULT NULL," +
			"	`updated_time` bigint DEFAULT NULL," +
			"	`result` varchar(100) DEFAULT NULL," +
			"	`total` INTEGER	" +
			"  );"

	_, err := db.Query(query)
	return err
}

func CreateTableNetworkLogsSQLite(cfg types.ConfigDB) error {
	db := connectSQLite(cfg)
	defer db.Close()

	tableName := TableNetworkLogsSQLite_TableName

	query :=
		"CREATE TABLE IF NOT EXISTS `" + tableName + "` (" +
			"	`id` integer NOT NULL PRIMARY KEY AUTO_INCREMENT," +
			"	`verdict` varchar(50) DEFAULT NULL," +
			"	`ip_source` varchar(100) DEFAULT NULL," +
			"	`ip_destination` varchar(100) DEFAULT NULL," +
			"	`ip_version` varchar(50) DEFAULT NULL," +
			"	`ip_encrypted` BOOLEAN," +
			"	`l4_tcp_source_port` INTEGER," +
			"	`l4_tcp_destination_port` INTEGER," +
			"	`l4_udp_source_port` INTEGER," +
			"	`l4_udp_destination_port` INTEGER," +
			"	`l4_icmpv4_type` INTEGER," +
			"	`l4_icmpv4_code` INTEGER," +
			"	`l4_icmpv6_type` INTEGER," +
			"	`l4_icmpv6_code` INTEGER," +
			"	`source_namespace` varchar(100) DEFAULT NULL," +
			"	`source_labels` varchar(250) DEFAULT NULL," +
			"	`source_pod_name` varchar(100) DEFAULT NULL," +
			"	`destination_namespace` varchar(100) DEFAULT NULL," +
			"	`destination_labels` varchar(250) DEFAULT NULL," +
			"	`destination_pod_name` varchar(100) DEFAULT NULL," +
			"	`type` varchar(50) DEFAULT NULL," +
			"	`node_name` varchar(100) DEFAULT NULL," +
			"	`l7_type` varchar(100) DEFAULT NULL," +
			"	`l7_dns_cnames` varchar(100) DEFAULT NULL," +
			"	`l7_dns_observation_source` varchar(150) DEFAULT NULL," +
			"	`l7_http_code` INTEGER," +
			"	`l7_http_method` varchar(100) DEFAULT NULL," +
			"	`l7_http_url` varchar(250) DEFAULT NULL," +
			"	`l7_http_protocol` varchar(50) DEFAULT NULL," +
			"	`l7_http_headers` varchar(250) DEFAULT NULL," +
			"	`event_type_type` INTEGER," +
			"	`event_type_sub_type` INTEGER," +
			"	`source_service_name` varchar(100) DEFAULT NULL," +
			"	`source_service_namespace` varchar(100) DEFAULT NULL," +
			"	`destination_service_name` varchar(100) DEFAULT NULL," +
			"	`destination_service_namespace` varchar(100) DEFAULT NULL," +
			"	`traffic_direction` varchar(100) DEFAULT NULL," +
			"	`trace_observation_point` varchar(100) DEFAULT NULL," +
			"	`drop_reason_desc` INTEGER," +
			"	`is_reply` BOOLEAN," +
			"	`start_time` bigint NOT NULL," +
			"	`updated_time` bigint NOT NULL," +
			"	`total` INTEGER" +
			" 	);"

	_, err := db.Query(query)
	return err
}

func concatWhereClauseSQLite(whereClause *string, field string) {
	if *whereClause == "" {
		*whereClause = " WHERE "
	} else {
		*whereClause = *whereClause + " and "
	}
	*whereClause = *whereClause + field + " = ?"
}

func concatWhereClauseIntRangeSQLite(whereClause *string, field string, start int64, end int64) {
	if *whereClause == "" {
		*whereClause = " WHERE "
	} else {
		*whereClause = *whereClause + " and "
	}
	*whereClause = *whereClause + field + " between " + strconv.Itoa(int(start)) + " and " + strconv.Itoa(int(end))
}

// GetWorkloadProcessFileSetMySQL Handle File Sets in context to a given fromSource
func GetWorkloadProcessFileSetSQLite(cfg types.ConfigDB, wpfs types.WorkloadProcessFileSet) (map[types.WorkloadProcessFileSet][]string, types.PolicyNameMap, error) {
	db := connectSQLite(cfg)
	defer db.Close()

	var results *sql.Rows
	var err error

	query := "SELECT policyName,clusterName,namespace,containerName,labels,fromSource,settype,fileset FROM " + WorkloadProcessFileSetSQLite_TableName

	var whereClause string
	var args []interface{}

	if wpfs.ClusterName != "" {
		concatWhereClauseSQLite(&whereClause, "clusterName")
		args = append(args, wpfs.ClusterName)
	}
	if wpfs.Namespace != "" {
		concatWhereClauseSQLite(&whereClause, "namespace")
		args = append(args, wpfs.Namespace)
	}
	if wpfs.ContainerName != "" {
		concatWhereClauseSQLite(&whereClause, "containerName")
		args = append(args, wpfs.ContainerName)
	}
	if wpfs.Labels != "" {
		concatWhereClauseSQLite(&whereClause, "labels")
		args = append(args, wpfs.Labels)
	}
	if wpfs.FromSource != "" {
		concatWhereClauseSQLite(&whereClause, "fromSource")
		args = append(args, wpfs.FromSource)
	}
	if wpfs.SetType != "" {
		concatWhereClauseSQLite(&whereClause, "settype")
		args = append(args, wpfs.SetType)
	}

	results, err = db.Query(query+whereClause, args...)

	if err != nil {
		log.Error().Msg(err.Error())
		return nil, nil, err
	}

	defer results.Close()

	var loc_wpfs types.WorkloadProcessFileSet
	res := types.ResourceSetMap{}
	pnMap := types.PolicyNameMap{}
	var fscsv string
	var fs []string
	var policyName string

	for results.Next() {
		if err := results.Scan(
			&policyName,
			&loc_wpfs.ClusterName,
			&loc_wpfs.Namespace,
			&loc_wpfs.ContainerName,
			&loc_wpfs.Labels,
			&loc_wpfs.FromSource,
			&loc_wpfs.SetType,
			&fscsv,
		); err != nil {
			return nil, nil, err
		}
		fs = strings.Split(fscsv, ",")
		res[loc_wpfs] = fs
		pnMap[loc_wpfs] = policyName
	}

	return res, pnMap, nil
}

func InsertWorkloadProcessFileSetSQLite(cfg types.ConfigDB, wpfs types.WorkloadProcessFileSet, fs []string) error {
	db := connectSQLite(cfg)
	defer db.Close()
	policyName := "autopol-" + strings.ToLower(wpfs.SetType) + "-" + RandSeq(15)
	time := ConvertStrToUnixTime("now")

	stmt, err := db.Prepare("INSERT INTO " + WorkloadProcessFileSetSQLite_TableName +
		"(policyName,clusterName,namespace,containerName,labels,fromSource,settype,fileset,createdtime,updatedtime) values(?,?,?,?,?,?,?,?,?,?)")
	if err != nil {
		return err
	}
	defer stmt.Close()
	fsset := strings.Join(fs[:], ",")

	_, err = stmt.Exec(
		policyName,
		wpfs.ClusterName,
		wpfs.Namespace,
		wpfs.ContainerName,
		wpfs.Labels,
		wpfs.FromSource,
		wpfs.SetType,
		fsset,
		time,
		time)
	return err
}

// Clears out WPFS DB on full or as per options specified
func ClearWPFSDbSQLite(cfg types.ConfigDB, wpfs types.WorkloadProcessFileSet, duration int64) error {
	db := connectSQLite(cfg)
	defer db.Close()

	var err error

	query := "DELETE FROM " + WorkloadProcessFileSetSQLite_TableName

	var whereClause string
	var args []interface{}
	time := ConvertStrToUnixTime("now")

	if wpfs.ClusterName != "" {
		concatWhereClauseSQLite(&whereClause, "clusterName")
		args = append(args, wpfs.ClusterName)
	}
	if wpfs.Namespace != "" {
		concatWhereClauseSQLite(&whereClause, "namespace")
		args = append(args, wpfs.Namespace)
	}
	if wpfs.ContainerName != "" {
		concatWhereClauseSQLite(&whereClause, "containerName")
		args = append(args, wpfs.ContainerName)
	}
	if wpfs.Labels != "" {
		concatWhereClauseSQLite(&whereClause, "labels")
		args = append(args, wpfs.Labels)
	}
	if wpfs.FromSource != "" {
		concatWhereClauseSQLite(&whereClause, "fromSource")
		args = append(args, wpfs.FromSource)
	}
	if duration != 0 {
		concatWhereClauseIntRangeSQLite(&whereClause, "createdtime", time-duration, time)
	}

	_, err = db.Query(query+whereClause, args...)

	if err != nil {
		log.Error().Msg(err.Error())
		return err
	}
	return err
}

func UpdateWorkloadProcessFileSetSQLite(cfg types.ConfigDB, wpfs types.WorkloadProcessFileSet, fs []string) error {
	db := connectSQLite(cfg)
	defer db.Close()

	var err error
	time := ConvertStrToUnixTime("now")

	// set status -> outdated
	stmt, err := db.Prepare("UPDATE " + WorkloadProcessFileSetSQLite_TableName +
		" SET fileset=?,updatedtime=? WHERE clusterName = ? and containerName = ? and namespace = ? and labels = ? and fromSource = ? and settype = ?")
	if err != nil {
		return err
	}
	defer stmt.Close()
	fsset := strings.Join(fs[:], ",")

	_, err = stmt.Exec(fsset,
		time,
		wpfs.ClusterName,
		wpfs.ContainerName,
		wpfs.Namespace,
		wpfs.Labels,
		wpfs.FromSource,
		wpfs.SetType)

	/*
		a, err := res.RowsAffected()
		if err == nil {
			log.Info().Msgf("UPDATE rows affected:%d", a)
		}
	*/
	return err
}

// InsertKubearmorLogsAlertsSQLite : Insert new kubearmor log/alert into DB
func InsertKubearmorLogsAlertsSQLite(cfg types.ConfigDB, log types.KubeArmorLogAlert) error {
	db := connectSQLite(cfg)
	defer db.Close()

	queryString := `(cluster_name,host_name,namespace_name,pod_name,container_id,container_name,
		uid,type,source,operation,resource,labels,data,category,action,start_time,
		updated_time,result,total) values(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`

	stmt, err := db.Prepare("INSERT INTO " + TableSystemLogs_TableName + queryString)
	if err != nil {
		return err
	}
	defer stmt.Close()

	_, err = stmt.Exec(
		log.ClusterName,
		log.HostName,
		log.NamespaceName,
		log.PodName,
		log.ContainerID,
		log.ContainerName,
		log.UID,
		log.Type,
		log.Source,
		log.Operation,
		log.Resource,
		log.Labels,
		log.Data,
		log.Category,
		log.Action,
		log.Timestamp,
		log.Timestamp,
		log.Result,
		1)
	return err
}

// UpdateKubearmorLogsAlertsSQLite -- Update existing log/alert with time and count
func UpdateKubearmorLogsAlertsSQLite(cfg types.ConfigDB, kubearmorlog types.KubeArmorLogAlert) error {
	db := connectSQLite(cfg)
	defer db.Close()

	var err error
	updateQuery := `cluster_name = ? and host_name = ? and namespace_name = ? and pod_name = ? and container_id = ? and 
					container_name = ? and uid = ? and type = ? and source = ? and operation = ? and resource = ? and 
					labels = ? and data = ? and category = ? and action = ? and result = ? `

	// set status -> outdated
	stmt, err := db.Prepare("UPDATE " + TableSystemLogs_TableName + " SET total=total+1, updated_time=? WHERE " + updateQuery + " ")
	if err != nil {
		return err
	}

	_, err = stmt.Exec(
		kubearmorlog.Timestamp,
		kubearmorlog.ClusterName,
		kubearmorlog.HostName,
		kubearmorlog.NamespaceName,
		kubearmorlog.PodName,
		kubearmorlog.ContainerID,
		kubearmorlog.ContainerName,
		kubearmorlog.UID,
		kubearmorlog.Type,
		kubearmorlog.Source,
		kubearmorlog.Operation,
		kubearmorlog.Resource,
		kubearmorlog.Labels,
		kubearmorlog.Data,
		kubearmorlog.Category,
		kubearmorlog.Action,
		kubearmorlog.Result,
	)

	return err
}

// GetKubearmorLogsAlertsMySQL
func GetSystemLogsSQLite(cfg types.ConfigDB, filterLog types.KubeArmorLogAlert) ([]types.KubeArmorLogAlert, []uint32, error) {
	db := connectSQLite(cfg)
	defer db.Close()

	resLog := []types.KubeArmorLogAlert{}
	resTotal := []uint32{}

	var results *sql.Rows
	var err error

	queryString := `cluster_name,host_name,namespace_name,pod_name,container_id,container_name,
		uid,type,source,operation,resource,labels,data,category,action,start_time,updated_time,result,total`

	query := "SELECT " + queryString + " FROM " + TableSystemLogs_TableName + " "

	var whereClause string
	var args []interface{}

	if filterLog.ClusterName != "" {
		concatWhereClause(&whereClause, "cluster_name")
		args = append(args, filterLog.ClusterName)
	}
	if filterLog.HostName != "" {
		concatWhereClause(&whereClause, "host_name")
		args = append(args, filterLog.HostName)
	}
	if filterLog.NamespaceName != "" {
		concatWhereClause(&whereClause, "namespace_name")
		args = append(args, filterLog.NamespaceName)
	}
	if filterLog.PodName != "" {
		concatWhereClause(&whereClause, "pod_name")
		args = append(args, filterLog.PodName)
	}
	if filterLog.ContainerID != "" {
		concatWhereClause(&whereClause, "container_id")
		args = append(args, filterLog.ContainerID)
	}
	if filterLog.ContainerName != "" {
		concatWhereClause(&whereClause, "container_name")
		args = append(args, filterLog.ContainerName)
	}
	if filterLog.UID != 0 {
		concatWhereClause(&whereClause, "uid")
		args = append(args, filterLog.UID)
	}
	if filterLog.Type != "" {
		concatWhereClause(&whereClause, "type")
		args = append(args, filterLog.Type)
	}
	if filterLog.Source != "" {
		concatWhereClause(&whereClause, "source")
		args = append(args, filterLog.Source)
	}
	if filterLog.Operation != "" {
		concatWhereClause(&whereClause, "operation")
		args = append(args, filterLog.Operation)
	}
	if filterLog.Resource != "" {
		concatWhereClause(&whereClause, "resource")
		args = append(args, filterLog.Resource)
	}
	if filterLog.Labels != "" {
		concatWhereClause(&whereClause, "labels")
		args = append(args, filterLog.Labels)
	}
	if filterLog.Data != "" {
		concatWhereClause(&whereClause, "data")
		args = append(args, filterLog.Data)
	}
	if filterLog.Category != "" {
		concatWhereClause(&whereClause, "category")
		args = append(args, filterLog.Category)
	}
	if filterLog.Action != "" {
		concatWhereClause(&whereClause, "action")
		args = append(args, filterLog.Action)
	}
	if filterLog.Timestamp != 0 {
		concatWhereClause(&whereClause, "start_time")
		args = append(args, filterLog.Timestamp)
	}
	if filterLog.UpdatedTime != 0 {
		concatWhereClause(&whereClause, "updated_time")
		args = append(args, filterLog.UpdatedTime)
	}
	if filterLog.Result != "" {
		concatWhereClause(&whereClause, "result")
		args = append(args, filterLog.Result)
	}

	results, err = db.Query(query+whereClause, args...)

	if err != nil {
		log.Error().Msg(err.Error())
		return nil, nil, err
	}
	defer results.Close()

	for results.Next() {
		var loc_log types.KubeArmorLogAlert
		var loc_total uint32
		if err := results.Scan(
			&loc_log.ClusterName,
			&loc_log.HostName,
			&loc_log.NamespaceName,
			&loc_log.PodName,
			&loc_log.ContainerID,
			&loc_log.ContainerName,
			&loc_log.UID,
			&loc_log.Type,
			&loc_log.Source,
			&loc_log.Operation,
			&loc_log.Resource,
			&loc_log.Labels,
			&loc_log.Data,
			&loc_log.Category,
			&loc_log.Action,
			&loc_log.Timestamp,
			&loc_log.UpdatedTime,
			&loc_log.Result,
			&loc_total,
		); err != nil {
			return nil, nil, err
		}
		resLog = append(resLog, loc_log)
		resTotal = append(resTotal, loc_total)
	}

	return resLog, resTotal, err
}

func InsertCiliumLogsSQLite(cfg types.ConfigDB, log types.CiliumLog) error {
	db := connectSQLite(cfg)
	defer db.Close()

	statement := `verdict, ip_source,ip_destination,ip_version,ip_encrypted,l4_tcp_source_port,l4_tcp_destination_port,
		l4_udp_source_port,l4_udp_destination_port,l4_icmpv4_type,l4_icmpv4_code,l4_icmpv6_type,l4_icmpv6_code,
		source_namespace,source_labels,source_pod_name,destination_namespace,destination_labels,destination_pod_name,
		type,node_name,l7_type,l7_dns_cnames,l7_dns_observation_source,l7_http_code,l7_http_method,l7_http_url,l7_http_protocol,l7_http_headers,
		event_type_type,event_type_sub_type,source_service_name,source_service_namespace,destination_service_name,destination_service_namespace,
		traffic_direction,trace_observation_point,drop_reason_desc,is_reply,start_time,updated_time,total) 
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`

	stmt, err := db.Prepare("INSERT INTO " + TableNetworkLogs_TableName + statement)
	if err != nil {
		return err
	}
	defer stmt.Close()

	_, err = stmt.Exec(
		log.Verdict,
		log.IpSource,
		log.IpDestination,
		log.IpVersion,
		log.IpEncrypted,
		log.L4TCPSourcePort,
		log.L4TCPDestinationPort,
		log.L4UDPSourcePort,
		log.L4UDPDestinationPort,
		log.L4ICMPv4Type,
		log.L4ICMPv4Code,
		log.L4ICMPv6Type,
		log.L4ICMPv6Code,
		log.SourceNamespace,
		log.SourceLabels,
		log.SourcePodName,
		log.DestinationNamespace,
		log.DestinationLabels,
		log.DestinationPodName,
		log.Type,
		log.NodeName,
		log.L7Type,
		log.L7DnsCnames,
		log.L7DnsObservationsource,
		log.L7HttpCode,
		log.L7HttpMethod,
		log.L7HttpUrl,
		log.L7HttpProtocol,
		log.L7HttpHeaders,
		log.EventTypeType,
		log.EventTypeSubType,
		log.SourceServiceName,
		log.SourceServiceNamespace,
		log.DestinationServiceName,
		log.DestinationServiceNamespace,
		log.TrafficDirection,
		log.TraceObservationPoint,
		log.DropReasonDesc,
		log.IsReply,
		log.StartTime,
		log.UpdatedTime,
		1)
	return err
}
