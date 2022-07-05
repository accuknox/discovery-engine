package libs

import (
	"errors"

	"github.com/accuknox/auto-policy-discovery/src/types"
)

// ================= //
// == Network Log == //
// ================= //

// LastFlowID network flow between [ startTime <= time < endTime ]
var LastFlowID int64 = 0

// ==================== //
// == Network Policy == //
// ==================== //

func GetNetworkPolicies(cfg types.ConfigDB, cluster, namespace, status, nwtype, rule string) []types.KnoxNetworkPolicy {
	results := []types.KnoxNetworkPolicy{}

	if cfg.DBDriver == "mysql" {
		docs, err := GetNetworkPoliciesFromMySQL(cfg, cluster, namespace, status, nwtype, rule)
		if err != nil {
			return results
		}
		results = docs
	} else if cfg.DBDriver == "sqlite3" {
		docs, err := GetNetworkPoliciesFromSQLite(cfg, cluster, namespace, status)
		if err != nil {
			return results
		}
		results = docs
	}

	return results
}

func GetNetworkPoliciesBySelector(cfg types.ConfigDB, cluster, namespace, status string, selector map[string]string) ([]types.KnoxNetworkPolicy, error) {
	results := []types.KnoxNetworkPolicy{}

	if cfg.DBDriver == "mysql" {
		docs, err := GetNetworkPoliciesFromMySQL(cfg, cluster, namespace, status, "", "")
		if err != nil {
			return nil, err
		}
		results = docs
	} else if cfg.DBDriver == "sqlite3" {
		docs, err := GetNetworkPoliciesFromSQLite(cfg, cluster, namespace, status)
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
			val := policy.Spec.Selector.MatchLabels[k]
			if val != v {
				matched = false
				break
			}
		}

		if matched {
			filtered = append(filtered, policy)
		}
	}

	return filtered, nil
}

func UpdateOutdatedNetworkPolicy(cfg types.ConfigDB, outdatedPolicy string, latestPolicy string) {
	if cfg.DBDriver == "mysql" {
		if err := UpdateOutdatedNetworkPolicyFromMySQL(cfg, outdatedPolicy, latestPolicy); err != nil {
			log.Error().Msg(err.Error())
		}
	} else if cfg.DBDriver == "sqlite3" {
		if err := UpdateOutdatedNetworkPolicyFromSQLite(cfg, outdatedPolicy, latestPolicy); err != nil {
			log.Error().Msg(err.Error())
		}
	}
}

func UpdateNetworkPolicy(cfg types.ConfigDB, policy types.KnoxNetworkPolicy) {
	if cfg.DBDriver == "mysql" {
		if err := UpdateNetworkPolicyToMySQL(cfg, policy); err != nil {
			log.Error().Msg(err.Error())
		}
	} else if cfg.DBDriver == "sqlite3" {
		if err := UpdateNetworkPolicyToSQLite(cfg, policy); err != nil {
			log.Error().Msg(err.Error())
		}
	}
}

func InsertNetworkPolicies(cfg types.ConfigDB, policies []types.KnoxNetworkPolicy) {
	if cfg.DBDriver == "mysql" {
		if err := InsertNetworkPoliciesToMySQL(cfg, policies); err != nil {
			log.Error().Msg(err.Error())
		}
	} else if cfg.DBDriver == "sqlite3" {
		if err := InsertNetworkPoliciesToSQLite(cfg, policies); err != nil {
			log.Error().Msg(err.Error())
		}
	}

}

// ================ //
// == System Log == //
// ================ //

// LastSyslogID system log between [ startTime <= time < endTime ]
var LastSyslogID int64 = 0

// ================== //
// == System Alert == //
// ================== //

// LastSysAlertID system_alert between [ startTime <= time < endTime ]
var LastSysAlertID int64 = 0

// =================== //
// == System Policy == //
// =================== //

func UpdateOutdatedSystemPolicy(cfg types.ConfigDB, outdatedPolicy string, latestPolicy string) {
	if cfg.DBDriver == "mysql" {
		if err := UpdateOutdatedNetworkPolicyFromMySQL(cfg, outdatedPolicy, latestPolicy); err != nil {
			log.Error().Msg(err.Error())
		}
	} else if cfg.DBDriver == "sqlite3" {
		if err := UpdateOutdatedNetworkPolicyFromSQLite(cfg, outdatedPolicy, latestPolicy); err != nil {
			log.Error().Msg(err.Error())
		}
	}
}

func GetSystemPolicies(cfg types.ConfigDB, namespace, status string) []types.KnoxSystemPolicy {
	results := []types.KnoxSystemPolicy{}

	if cfg.DBDriver == "mysql" {
		docs, err := GetSystemPoliciesFromMySQL(cfg, namespace, status)
		if err != nil {
			return results
		}
		results = docs
	} else if cfg.DBDriver == "sqlite3" {
		docs, err := GetSystemPoliciesFromSQLite(cfg, namespace, status)
		if err != nil {
			return results
		}
		results = docs
	}

	return results
}

func InsertSystemPolicies(cfg types.ConfigDB, policies []types.KnoxSystemPolicy) {
	if cfg.DBDriver == "mysql" {
		if err := InsertSystemPoliciesToMySQL(cfg, policies); err != nil {
			log.Error().Msg(err.Error())
		}
	} else if cfg.DBDriver == "sqlite3" {
		if err := InsertSystemPoliciesToSQLite(cfg, policies); err != nil {
			log.Error().Msg(err.Error())
		}
	}
}

func UpdateSystemPolicy(cfg types.ConfigDB, policy types.KnoxSystemPolicy) {
	if cfg.DBDriver == "mysql" {
		if err := UpdateSystemPolicyToMySQL(cfg, policy); err != nil {
			log.Error().Msg(err.Error())
		}
	} else if cfg.DBDriver == "sqlite3" {
		if err := UpdateSystemPolicyToSQLite(cfg, policy); err != nil {
			log.Error().Msg(err.Error())
		}
	}

}

func GetWorkloadProcessFileSet(cfg types.ConfigDB, wpfs types.WorkloadProcessFileSet) (map[types.WorkloadProcessFileSet][]string, types.PolicyNameMap, error) {
	if cfg.DBDriver == "mysql" {
		res, pnMap, err := GetWorkloadProcessFileSetMySQL(cfg, wpfs)
		if err != nil {
			log.Error().Msg(err.Error())
		}
		return res, pnMap, err
	} else if cfg.DBDriver == "sqlite3" {
		res, pnMap, err := GetWorkloadProcessFileSetSQLite(cfg, wpfs)
		if err != nil {
			log.Error().Msg(err.Error())
		}
		return res, pnMap, err
	}
	return nil, nil, errors.New("no db driver")
}

func InsertWorkloadProcessFileSet(cfg types.ConfigDB, wpfs types.WorkloadProcessFileSet, fs []string) error {
	if cfg.DBDriver == "mysql" {
		return InsertWorkloadProcessFileSetMySQL(cfg, wpfs, fs)
	} else if cfg.DBDriver == "sqlite3" {
		return InsertWorkloadProcessFileSetSQLite(cfg, wpfs, fs)
	}
	return errors.New("no db driver")
}

func ClearWPFSDb(cfg types.ConfigDB, wpfs types.WorkloadProcessFileSet, duration int64) error {
	if cfg.DBDriver == "mysql" {
		return ClearWPFSDbMySQL(cfg, wpfs, duration)
	} else if cfg.DBDriver == "sqlite3" {
		return ClearWPFSDbSQLite(cfg, wpfs, duration)
	}
	return errors.New("no db driver")
}

// =========== //
// == Table == //
// =========== //

func ClearDBTables(cfg types.ConfigDB) {
	if cfg.DBDriver == "mysql" {
		if err := ClearDBTablesMySQL(cfg); err != nil {
			log.Error().Msg(err.Error())
		}
	} else if cfg.DBDriver == "sqlite3" {
		if err := ClearDBTablesSQLite(cfg); err != nil {
			log.Error().Msg(err.Error())
		}
	}
}

func ClearNetworkDBTable(cfg types.ConfigDB) {
	if cfg.DBDriver == "mysql" {
		if err := ClearNetworkDBTableMySQL(cfg); err != nil {
			log.Error().Msg(err.Error())
		}
	}
}

func CreateTablesIfNotExist(cfg types.ConfigDB) {
	if cfg.DBDriver == "mysql" {
		if err := CreateTableNetworkPolicyMySQL(cfg); err != nil {
			log.Error().Msg(err.Error())
		}
		if err := CreateTableSystemPolicyMySQL(cfg); err != nil {
			log.Error().Msg(err.Error())
		}
		if err := CreateTableWorkLoadProcessFileSetMySQL(cfg); err != nil {
			log.Error().Msg(err.Error())
		}
		if err := CreateTableSystemLogsMySQL(cfg); err != nil {
			log.Error().Msg(err.Error())
		}
		if err := CreateTableNetworkLogsMySQL(cfg); err != nil {
			log.Error().Msg(err.Error())
		}
	} else if cfg.DBDriver == "sqlite3" {
		if err := CreateTableNetworkPolicySQLite(cfg); err != nil {
			log.Error().Msg(err.Error())
		}
		if err := CreateTableSystemPolicySQLite(cfg); err != nil {
			log.Error().Msg(err.Error())
		}
		if err := CreateTableWorkLoadProcessFileSetSQLite(cfg); err != nil {
			log.Error().Msg(err.Error())
		}
		if err := CreateTableSystemLogsSQLite(cfg); err != nil {
			log.Error().Msg(err.Error())
		}
		if err := CreateTableNetworkLogsSQLite(cfg); err != nil {
			log.Error().Msg(err.Error())
		}
	}
}

// =================== //
// == Observability == //
// =================== //
func InsertKubearmorLogs(cfg types.ConfigDB, kubearmorLog types.KubeArmorLog) error {
	var err = errors.New("unknown db driver")
	if cfg.DBDriver == "mysql" {
		err = InsertKubearmorLogsMySQL(cfg, kubearmorLog)
	} else if cfg.DBDriver == "sqlite3" {
		err = InsertKubearmorLogsSQLite(cfg, kubearmorLog)
	}
	return err
}

func UpdateKubearmorLogs(cfg types.ConfigDB, kubearmorLog types.KubeArmorLog) error {
	var err = errors.New("unknown db driver")
	if cfg.DBDriver == "mysql" {
		err = UpdateKubearmorLogsMySQL(cfg, kubearmorLog)
	} else if cfg.DBDriver == "sqlite3" {
		err = UpdateKubearmorLogsSQLite(cfg, kubearmorLog)
	}
	return err
}

func GetKubearmorLogs(cfg types.ConfigDB, filterLog types.KubeArmorLog) ([]types.KubeArmorLog, []uint32, error) {
	kubearmorLog := []types.KubeArmorLog{}
	totalCount := []uint32{}
	var err = errors.New("unknown db driver")
	if cfg.DBDriver == "mysql" {
		kubearmorLog, totalCount, err = GetSystemLogsMySQL(cfg, filterLog)
	} else if cfg.DBDriver == "sqlite3" {
		kubearmorLog, totalCount, err = GetSystemLogsSQLite(cfg, filterLog)
	}
	return kubearmorLog, totalCount, err
}

func InsertCiliumLogs(cfg types.ConfigDB, ciliumLog types.CiliumLog) error {
	var err = errors.New("unknown db driver")
	if cfg.DBDriver == "mysql" {
		err = InsertCiliumLogsMySQL(cfg, ciliumLog)
	} else if cfg.DBDriver == "sqlite3" {
		err = InsertCiliumLogsSQLite(cfg, ciliumLog)
	}
	return err
}

func UpdateCiliumLogs(cfg types.ConfigDB, ciliumLog types.CiliumLog) error {
	var err = errors.New("unknown db driver")
	if cfg.DBDriver == "mysql" {
		err = UpdateCiliumLogsMySQL(cfg, ciliumLog)
	} else if cfg.DBDriver == "sqlite3" {
		err = UpdateCiliumLogsSQLite(cfg, ciliumLog)
	}
	return err
}

func GetCiliumLogs(cfg types.ConfigDB, ciliumFilter types.CiliumLog) ([]types.CiliumLog, []uint32, error) {
	ciliumLogs := []types.CiliumLog{}
	ciliumTotalCount := []uint32{}
	var err = errors.New("unknown db driver")
	if cfg.DBDriver == "mysql" {
		ciliumLogs, ciliumTotalCount, err = GetCiliumLogsMySQL(cfg, ciliumFilter)
	} else if cfg.DBDriver == "sqlite3" {
		ciliumLogs, ciliumTotalCount, err = GetCiliumLogsSQLite(cfg, ciliumFilter)
	}
	return ciliumLogs, ciliumTotalCount, err
}
