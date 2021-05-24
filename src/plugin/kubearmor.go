package plugin

import (
	"encoding/json"
	"strings"

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

		sources := strings.Split(syslog.Source, " ")
		source := ""
		if len(sources) >= 1 {
			source = sources[0]
		}

		knoxSysLog := types.KnoxSystemLog{
			ClusterName:  syslog.ClusterName,
			HostName:     syslog.HostName,
			Namespace:    syslog.NamespaceName,
			PodName:      syslog.PodName,
			Source:       source,
			SourceOrigin: syslog.Source,
			Operation:    syslog.Operation,
			Resource:     syslog.Resource,
			Data:         syslog.Data,
			Result:       syslog.Result,
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
