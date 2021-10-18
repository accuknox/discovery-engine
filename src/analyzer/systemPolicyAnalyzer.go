package analyzer

import (
	"encoding/json"

	apb "github.com/accuknox/knoxAutoPolicy/src/protobuf/v1/analyzer"
	syspolicy "github.com/accuknox/knoxAutoPolicy/src/systempolicy"
	types "github.com/accuknox/knoxAutoPolicy/src/types"
)

func extractSystemPoliciesFromSystemLogs(systemLogs []types.KnoxSystemLog) []*apb.KnoxSystemPolicy {

	pbSystemPolicies := []*apb.KnoxSystemPolicy{}
	systemPolicies := syspolicy.PopulateSystemPoliciesFromSystemLogs(systemLogs)

	for _, sysPolicy := range systemPolicies {
		pbSysPolicy := apb.KnoxSystemPolicy{}
		pbSysPolicyBytes, err := json.Marshal(sysPolicy)
		if err != nil {
			return nil
		} else {
			pbSysPolicy.SystemPolicy = pbSysPolicyBytes
			pbSystemPolicies = append(pbSystemPolicies, &pbSysPolicy)
		}
	}

	return pbSystemPolicies
}

func populateSystemLogs(pbSysLogs []*apb.KnoxSystemLog) []types.KnoxSystemLog {
	sysLogs := []types.KnoxSystemLog{}

	// Populate KnoxSystemLog from Protobuf's SystemLog
	for _, pbSysLog := range pbSysLogs {
		sysLog := types.KnoxSystemLog{}
		sysLog.LogID = int(pbSysLog.LogID)
		sysLog.ClusterName = pbSysLog.ClusterName
		sysLog.HostName = pbSysLog.HostName
		sysLog.Namespace = pbSysLog.Namespace
		sysLog.PodName = pbSysLog.PodName
		sysLog.SourceOrigin = pbSysLog.SourceOrigin
		sysLog.Source = pbSysLog.Source
		sysLog.Operation = pbSysLog.Operation
		sysLog.ResourceOrigin = pbSysLog.ResourceOrigin
		sysLog.Resource = pbSysLog.Resource
		sysLog.Data = pbSysLog.Data
		sysLog.ReadOnly = pbSysLog.ReadOnly
		sysLog.Result = pbSysLog.Result

		sysLogs = append(sysLogs, sysLog)
	}

	return sysLogs
}

func GetSystemPolicies(pbSystemLogs []*apb.KnoxSystemLog) []*apb.KnoxSystemPolicy {

	systemLogs := populateSystemLogs(pbSystemLogs)
	systemPolicies := extractSystemPoliciesFromSystemLogs(systemLogs)

	return systemPolicies
}
