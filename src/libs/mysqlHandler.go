package libs

import (
	"database/sql"
	"encoding/json"
	"strings"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/accuknox/auto-policy-discovery/src/types"

	_ "github.com/go-sql-driver/mysql"
)

const WorkloadProcessFileSet_TableName = "workload_process_fileset"
const TableNetworkPolicy_TableName = "network_policy"
const TableSystemPolicy_TableName = "system_policy"

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
			time.Sleep(time.Second * 1)
			log.Error().Msgf("db.Ping() failed. Will retry. err=%s", err.Error())
		} else {
			break
		}
	}
}

func connectMySQL(cfg types.ConfigDB) (db *sql.DB) {
	if MockDB != nil {
		return MockDB
	}

	dbconn := cfg.DBUser + ":" + cfg.DBPass + "@tcp(" + cfg.DBHost + ":" + cfg.DBPort + ")/" + cfg.DBName
	db, err := sql.Open(cfg.DBDriver, dbconn)
	for err != nil {
		log.Error().Msgf("mysql driver:%s, user:%s, host:%s, port:%s, dbname:%s conn-error:%s",
			cfg.DBDriver, cfg.DBUser, cfg.DBHost, cfg.DBPort, cfg.DBName, err.Error())
		time.Sleep(time.Second * 1)
		db, err = sql.Open(cfg.DBDriver, dbconn)
	}

	db.SetMaxIdleConns(0)

	waitForDB(db)

	return db
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

	query := "SELECT apiVersion,kind,flow_ids,name,cluster_name,namespace,type,rule,status,outdated,spec,generatedTime FROM " + TableNetworkPolicy_TableName
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

func UpdateOutdatedNetworkPolicyFromMySQL(cfg types.ConfigDB, outdatedPolicy string, latestPolicy string) error {
	db := connectMySQL(cfg)
	defer db.Close()

	var err error

	// set status -> outdated
	stmt1, err := db.Prepare("UPDATE " + TableNetworkPolicy_TableName + " SET status=? WHERE name=?")
	if err != nil {
		return err
	}
	defer stmt1.Close()

	_, err = stmt1.Exec("outdated", outdatedPolicy)
	if err != nil {
		return err
	}

	// set outdated -> latest' name
	stmt2, err := db.Prepare("UPDATE " + TableNetworkPolicy_TableName + " SET outdated=? WHERE name=?")
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
	stmt, err := db.Prepare("INSERT INTO " + TableNetworkPolicy_TableName + "(apiVersion,kind,flow_ids,name,cluster_name,namespace,type,rule,status,outdated,spec,generatedTime) values(?,?,?,?,?,?,?,?,?,?,?,?)")
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
	stmt1, err := db.Prepare("UPDATE " + TableSystemPolicy_TableName + " SET status=? WHERE name=?")
	if err != nil {
		return err
	}
	defer stmt1.Close()

	_, err = stmt1.Exec("outdated", outdatedPolicy)
	if err != nil {
		return err
	}

	// set outdated -> latest' name
	stmt2, err := db.Prepare("UPDATE " + TableNetworkPolicy_TableName + " SET outdated=? WHERE name=?")
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

	query := "SELECT apiVersion,kind,name,clusterName,namespace,type,status,outdated,spec,generatedTime FROM " + TableSystemPolicy_TableName

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

func insertSystemPolicy(cfg types.ConfigDB, db *sql.DB, policy types.KnoxSystemPolicy) error {
	stmt, err := db.Prepare("INSERT INTO " + TableSystemPolicy_TableName + "(apiVersion,kind,name,clusterName,namespace,type,status,outdated,spec,generatedTime) values(?,?,?,?,?,?,?,?,?,?)")
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

// =========== //
// == Table == //
// =========== //

func ClearDBTablesMySQL(cfg types.ConfigDB) error {
	db := connectMySQL(cfg)
	defer db.Close()

	query := "DELETE FROM " + TableNetworkPolicy_TableName
	if _, err := db.Query(query); err != nil {
		return err
	}

	query = "DELETE FROM " + TableSystemPolicy_TableName
	if _, err := db.Query(query); err != nil {
		return err
	}

	query = "DELETE FROM " + WorkloadProcessFileSet_TableName
	if _, err := db.Query(query); err != nil {
		return err
	}

	return nil
}

func CreateTableNetworkPolicyMySQL(cfg types.ConfigDB) error {
	db := connectMySQL(cfg)
	defer db.Close()

	tableName := TableNetworkPolicy_TableName

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

func CreateTableSystemPolicyMySQL(cfg types.ConfigDB) error {
	db := connectMySQL(cfg)
	defer db.Close()

	tableName := TableSystemPolicy_TableName

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

func CreateTableWorkLoadProcessFileSetMySQL(cfg types.ConfigDB) error {
	db := connectMySQL(cfg)
	defer db.Close()

	tableName := WorkloadProcessFileSet_TableName

	query :=
		"CREATE TABLE IF NOT EXISTS `" + tableName + "` (" +
			"	`id` int NOT NULL AUTO_INCREMENT," +
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

	_, err := db.Query(query)
	return err
}

func concatWhereClause(whereClause *string, field string) {
	if *whereClause == "" {
		*whereClause = " WHERE "
	} else {
		*whereClause = *whereClause + " and "
	}
	*whereClause = *whereClause + field + " = ?"
}

// GetWorkloadProcessFileSetMySQL Handle File Sets in context to a given fromSource
func GetWorkloadProcessFileSetMySQL(cfg types.ConfigDB, wpfs types.WorkloadProcessFileSet) (map[types.WorkloadProcessFileSet][]string, []string, error) {
	db := connectMySQL(cfg)
	defer db.Close()

	var results *sql.Rows
	var err error

	query := "SELECT policyName,clusterName,namespace,containerName,labels,fromSource,settype,fileset FROM " + WorkloadProcessFileSet_TableName

	var whereClause string
	var args []interface{}

	if wpfs.ClusterName != "" {
		concatWhereClause(&whereClause, "clusterName")
		args = append(args, wpfs.ClusterName)
	}
	if wpfs.Namespace != "" {
		concatWhereClause(&whereClause, "namespace")
		args = append(args, wpfs.Namespace)
	}
	if wpfs.ContainerName != "" {
		concatWhereClause(&whereClause, "containerName")
		args = append(args, wpfs.ContainerName)
	}
	if wpfs.Labels != "" {
		concatWhereClause(&whereClause, "labels")
		args = append(args, wpfs.Labels)
	}
	if wpfs.FromSource != "" {
		concatWhereClause(&whereClause, "fromSource")
		args = append(args, wpfs.FromSource)
	}
	if wpfs.SetType != "" {
		concatWhereClause(&whereClause, "settype")
		args = append(args, wpfs.SetType)
	}

	results, err = db.Query(query+whereClause, args...)

	if err != nil {
		log.Error().Msg(err.Error())
		return nil, nil, err
	}

	defer results.Close()

	var loc_wpfs types.WorkloadProcessFileSet
	res := map[types.WorkloadProcessFileSet][]string{}
	var fscsv string
	var fs []string
	var policyNames []string
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
		policyNames = append(policyNames, policyName)
		fs = strings.Split(fscsv, ",")
		res[loc_wpfs] = fs
	}

	return res, policyNames, nil
}

func InsertWorkloadProcessFileSetMySQL(cfg types.ConfigDB, wpfs types.WorkloadProcessFileSet, fs []string) error {
	db := connectMySQL(cfg)
	defer db.Close()
	policyName := "autopol-" + strings.ToLower(wpfs.SetType) + "-" + RandSeq(15)
	time := ConvertStrToUnixTime("now")

	stmt, err := db.Prepare("INSERT INTO " + WorkloadProcessFileSet_TableName +
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

func UpdateWorkloadProcessFileSetMySQL(cfg types.ConfigDB, wpfs types.WorkloadProcessFileSet, fs []string) error {
	db := connectMySQL(cfg)
	defer db.Close()

	var err error
	time := ConvertStrToUnixTime("now")

	// set status -> outdated
	stmt, err := db.Prepare("UPDATE " + WorkloadProcessFileSet_TableName +
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
