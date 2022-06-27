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
	var isEntryExist bool
	var err error

	if len(SystemLogs) > 0 {

		//SystemLogsMutex.Lock()
		locSysLogs := SystemLogs
		SystemLogs = []*pb.Log{} //reset
		//SystemLogsMutex.Unlock()

		for _, kubearmorLog := range locSysLogs {

			locPbLog := pb.Log{}

			var locLog, resLog types.KubeArmorLog

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

			if isEntryExist, resLog, err = checkIfSystemLogExist(locLog); err != nil {
				log.Error().Msg(err.Error())
				return
			}

			if isEntryExist {
				resLog.Timestamp = locLog.Timestamp
				if err := libs.UpdateKubearmorLogs(CfgDB, resLog); err != nil {
					log.Error().Msg(err.Error())
				}
			} else {
				if err := libs.InsertKubearmorLogs(CfgDB, locLog); err != nil {
					log.Error().Msg(err.Error())
				}
			}
		}
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

func compareSrcDestLogAlert(src types.KubeArmorLog, dest types.KubeArmorLog) bool {
	if src.ClusterName == dest.ClusterName && src.HostName == dest.HostName && src.NamespaceName == dest.NamespaceName &&
		src.PodName == dest.PodName && src.ContainerID == dest.ContainerID && src.ContainerName == dest.ContainerName &&
		src.UID == dest.UID && src.Type == dest.Type && src.Source == dest.Source && src.Operation == dest.Operation &&
		src.Resource == dest.Resource && src.Labels == dest.Labels && src.Data == dest.Data && src.Category == dest.Category &&
		src.Action == dest.Action && src.Result == dest.Result {
		return true
	} else {
		return false
	}
}

func checkIfSystemLogExist(logAlert types.KubeArmorLog) (bool, types.KubeArmorLog, error) {
	locLogAlert := types.KubeArmorLog{}

	locLogAlert.ClusterName = logAlert.ClusterName
	locLogAlert.HostName = logAlert.HostName
	locLogAlert.NamespaceName = logAlert.NamespaceName
	locLogAlert.PodName = logAlert.PodName
	locLogAlert.ContainerID = logAlert.ContainerID
	locLogAlert.ContainerName = logAlert.ContainerName
	locLogAlert.UID = logAlert.UID
	locLogAlert.Type = logAlert.Type
	locLogAlert.Source = logAlert.Source
	locLogAlert.Operation = logAlert.Operation
	locLogAlert.Resource = logAlert.Resource
	locLogAlert.Labels = logAlert.Labels
	locLogAlert.Data = logAlert.Data
	locLogAlert.Category = logAlert.Category
	locLogAlert.Action = logAlert.Action
	locLogAlert.Result = logAlert.Result

	destLogAlert, _, err := libs.GetKubearmorLogs(CfgDB, locLogAlert)
	if err != nil {
		log.Error().Msg(err.Error())
		return false, types.KubeArmorLog{}, err
	}

	for _, locDestLogAlert := range destLogAlert {
		if compareSrcDestLogAlert(logAlert, locDestLogAlert) {
			return true, locLogAlert, nil
		}
	}

	return false, types.KubeArmorLog{}, nil
}
