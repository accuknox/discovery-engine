package plugin

import (
	"encoding/json"
	"strings"

	"github.com/accuknox/knoxAutoPolicy/src/types"
)

func ConvertKnoxSystemPolicyToKubeArmorPolicy(knoxPolicies []types.KnoxSystemPolicy) []types.KubeArmorPolicy {
	results := []types.KubeArmorPolicy{}

	for _, policy := range knoxPolicies {
		kubePolicy := types.KubeArmorPolicy{
			APIVersion: "security.kubearmor.com/v1",
			Kind:       "KubeArmorPolicy",
			Metadata:   map[string]string{},
		}

		kubePolicy.Metadata["namespace"] = policy.Metadata["namespace"]
		kubePolicy.Metadata["name"] = policy.Metadata["name"]

		kubePolicy.Spec = policy.Spec

		results = append(results, kubePolicy)
	}

	return results
}

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

		resources := strings.Split(syslog.Resource, " ")
		resource := ""
		if len(resources) >= 1 {
			resource = resources[0]
		}

		readOnly := false
		if syslog.Data != "" && strings.Contains(syslog.Data, "O_RDONLY") {
			readOnly = true
		}

		knoxSysLog := types.KnoxSystemLog{
			ClusterName:    syslog.ClusterName,
			HostName:       syslog.HostName,
			Namespace:      syslog.NamespaceName,
			PodName:        syslog.PodName,
			Source:         source,
			SourceOrigin:   syslog.Source,
			Operation:      syslog.Operation,
			ResourceOrigin: syslog.Resource,
			Resource:       resource,
			Data:           syslog.Data,
			ReadOnly:       readOnly,
			Result:         syslog.Result,
		}

		results = append(results, knoxSysLog)
	}

	return results
}

func ConvertKubeArmorSystemLogsToKnoxSystemLogs(dbDriver string, docs []map[string]interface{}) []types.KnoxSystemLog {
	if dbDriver == "mysql" {
		return ConvertMySQLKubeArmorLogsToKnoxSystemLogs(docs)
	}

	return []types.KnoxSystemLog{}
}
