package plugin

import (
	"github.com/accuknox/knoxAutoPolicy/src/types"
)

// ConvertMySQLKubeArmorLogsToKnoxSystemLogs function
func ConvertMySQLKubeArmorLogsToKnoxSystemLogs(docs []map[string]interface{}) []types.KnoxSystemLog {
	logs := []types.KnoxSystemLog{}

	return logs
}

// ConvertKubeArmorSystemLogsToKnoxSystemLogs function
func ConvertKubeArmorSystemLogsToKnoxSystemLogs(dbDriver string, docs []map[string]interface{}) []types.KnoxSystemLog {
	if dbDriver == "mysql" {
		return ConvertMySQLKubeArmorLogsToKnoxSystemLogs(docs)
	} else if dbDriver == "mongo" {
		// TODO: mongodb
		return []types.KnoxSystemLog{}
	} else {
		return []types.KnoxSystemLog{}
	}
}
