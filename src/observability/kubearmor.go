package observability

import (
	"encoding/json"

	"github.com/accuknox/auto-policy-discovery/src/libs"
	"github.com/accuknox/auto-policy-discovery/src/types"

	pb "github.com/kubearmor/KubeArmor/protobuf"
)

func convertKubearmorPbLogToKubearmorLog(pbLog pb.Log) types.KubeArmorLog {
	return types.KubeArmorLog{
		ClusterName:       pbLog.ClusterName,
		HostName:          pbLog.HostName,
		NamespaceName:     pbLog.NamespaceName,
		PodName:           pbLog.PodName,
		Labels:            pbLog.Labels,
		ContainerID:       pbLog.ContainerID,
		ContainerName:     pbLog.ContainerName,
		ContainerImage:    pbLog.ContainerImage,
		ParentProcessName: pbLog.ParentProcessName,
		ProcessName:       pbLog.ProcessName,
		HostPPID:          pbLog.HostPPID,
		HostPID:           pbLog.HostPID,
		PPID:              pbLog.PPID,
		PID:               pbLog.PID,
		UID:               pbLog.UID,
		Type:              pbLog.Type,
		Source:            pbLog.Source,
		Operation:         pbLog.Operation,
		Resource:          pbLog.Resource,
		Data:              pbLog.Data,
		Result:            pbLog.Result,
		Timestamp:         pbLog.Timestamp,
		UpdatedTime:       pbLog.Timestamp,
	}
}

func ProcessSystemLogs() {

	if len(SystemLogs) > 0 {
		SystemLogsMutex.Lock()
		locSysLogs := SystemLogs
		SystemLogs = []*pb.Log{} //reset
		SystemLogsMutex.Unlock()

		ObsMutex.Lock()
		res := []types.KubeArmorLog{}

		for _, kubearmorLog := range locSysLogs {
			locPbLog := pb.Log{}
			locLog := types.KubeArmorLog{}

			jsonLog, _ := json.Marshal(kubearmorLog)
			if err := json.Unmarshal(jsonLog, &locPbLog); err != nil {
				log.Error().Msg(err.Error())
				return
			}

			locLog = convertKubearmorPbLogToKubearmorLog(locPbLog)

			if locLog.Type == "MatchedPolicy" || locLog.Type == "MatchedHostPolicy" {
				locLog.Category = "Alert"
			} else {
				locLog.Action = "Allow"
				locLog.Category = "Log"
			}

			res = append(res, locLog)
		}
		if err := libs.UpdateOrInsertKubearmorLogs(CfgDB, res); err != nil {
			log.Error().Msg(err.Error())
		}
		ObsMutex.Unlock()
	}
}

func ProcessKubearmorLog(kubearmorLog *pb.Log) {
	SystemLogsMutex.Lock()
	SystemLogs = append(SystemLogs, kubearmorLog)
	SystemLogsMutex.Unlock()
}

func ProcessKubearmorAlert(kubearmorAlert *pb.Log) {
	SystemLogsMutex.Lock()
	SystemLogs = append(SystemLogs, kubearmorAlert)
	SystemLogsMutex.Unlock()
}
