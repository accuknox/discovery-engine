package observability

import (
	"encoding/json"
	"reflect"
	"time"

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
	var updateLogs, newLogs []types.KubeArmorLog

	if len(SystemLogs) > 0 {

		SystemLogsMutex.Lock()
		locSysLogs := SystemLogs
		SystemLogs = []*pb.Log{} //reset
		//SystemLogsMutex.Unlock()

		destLogAlert, err := getSystemLogs()
		if err != nil {
			log.Error().Msg(err.Error())
			return
		}

		for _, kubearmorLog := range locSysLogs {
			isEntryExist = false
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

			for _, locDestLogAlert := range destLogAlert {
				locLog.Timestamp = 0
				locLog.UpdatedTime = 0
				locDestLogAlert.Timestamp = 0
				locDestLogAlert.UpdatedTime = 0
				if reflect.DeepEqual(locLog, locDestLogAlert) {
					isEntryExist = true
					break
				}
			}

			if isEntryExist {
				updateLogs = append(updateLogs, locLog)
			} else {
				newLogs = append(newLogs, locLog)
				destLogAlert = append(destLogAlert, locLog)
			}
		}

		pushKubearmorLogs(newLogs, updateLogs)
		SystemLogsMutex.Unlock()
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

func getSystemLogs() ([]types.KubeArmorLog, error) {
	logs, _, err := libs.GetKubearmorLogs(CfgDB, types.KubeArmorLog{})
	if err != nil {
		log.Error().Msg(err.Error())
		return nil, err
	}
	return logs, nil
}

func pushKubearmorLogs(newLogs, updateLogs []types.KubeArmorLog) {
	SysObsMutex.Lock()
	for _, newlog := range newLogs {
		if err := libs.InsertKubearmorLogs(CfgDB, newlog); err != nil {
			log.Error().Msg(err.Error())
		}
	}
	time.Sleep(500 * time.Millisecond)
	for _, updatelog := range updateLogs {
		if err := libs.UpdateKubearmorLogs(CfgDB, updatelog); err != nil {
			log.Error().Msg(err.Error())
		}
	}
	SysObsMutex.Unlock()
}
