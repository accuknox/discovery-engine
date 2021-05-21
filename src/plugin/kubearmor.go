package plugin

import (
	"encoding/json"

	"github.com/accuknox/knoxAutoPolicy/src/types"
)

// ConvertMySQLKubeArmorLogsToKnoxSystemLogs function
func ConvertMySQLKubeArmorLogsToKnoxSystemLogs(docs []map[string]interface{}) []types.KnoxSystemLog {
	results := []types.KnoxSystemLog{}

	for _, doc := range docs {
		syslog := types.SystemLogEvent{}

		b, err := json.Marshal(doc)
		if err != nil {
			log.Error().Msg(err.Error())
			continue
		}

		if err := json.Unmarshal(b, &syslog); err != nil {
			log.Error().Msg(err.Error())
		}

		knoxSysLog := types.KnoxSystemLog{
			LogID:       syslog.ID,
			ClusterName: syslog.ClusterName,
			HostName:    syslog.HostName,
			Namespace:   syslog.NamespaceName,
			PodName:     syslog.PodName,
			Source:      syslog.Source,
			Operation:   syslog.Operation,
			Resource:    syslog.Resource,
			Data:        syslog.Data,
			Result:      syslog.Result,
		}

		results = append(results, knoxSysLog)
	}

	return results
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
