package analyzer

import (
	"encoding/json"
	"fmt"

	apb "github.com/accuknox/knoxAutoPolicy/src/protobuf/v1/analyzer"
	syspolicy "github.com/accuknox/knoxAutoPolicy/src/systempolicy"
	types "github.com/accuknox/knoxAutoPolicy/src/types"
	"github.com/rs/zerolog/log"
)

func extractSystemPoliciesFromSystemLogs(systemLogs []types.KnoxSystemLog) []*apb.KnoxSystemPolicy {

	pbSystemPolicies := []*apb.KnoxSystemPolicy{}
	systemPolicies := syspolicy.PopulateSystemPoliciesFromSystemLogs(systemLogs)

	fmt.Printf("systemPolicies : %v\n", systemPolicies)

	for _, sysPolicy := range systemPolicies {
		pbSysPolicy := apb.KnoxSystemPolicy{}
		pbSysPolicyBytes, err := json.Marshal(sysPolicy)
		if err != nil {
			log.Printf("Failed to marshall : %v\n", err)
		} else {
			pbSysPolicy.SystemPolicy = pbSysPolicyBytes
			pbSystemPolicies = append(pbSystemPolicies, &pbSysPolicy)
		}
	}

	return pbSystemPolicies
}

func populateSystemLogs(pbSysLogs []*apb.KnoxSystemLog) []types.KnoxSystemLog {
	sysLogs := []types.KnoxSystemLog{}

	fmt.Printf("\n ESWAR : populateSystemLogs -- ENTRY --  pbSysLogs: %v\n", pbSysLogs)

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

	fmt.Printf("\n ESWAR : sysLogs : %v\n", sysLogs)
	return sysLogs
}

func GetSystemPolicies(pbSystemLogs []*apb.KnoxSystemLog) []*apb.KnoxSystemPolicy {

	fmt.Printf("\n GetSystemPolicies ENTRY -- : %v\n", pbSystemLogs)
	systemLogs := populateSystemLogs(pbSystemLogs)
	systemPolicies := extractSystemPoliciesFromSystemLogs(systemLogs)

	return systemPolicies
}
