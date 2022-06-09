package observability

import (
	"encoding/json"

	"github.com/accuknox/auto-policy-discovery/src/libs"
	"github.com/accuknox/auto-policy-discovery/src/types"

	pb "github.com/kubearmor/KubeArmor/protobuf"
)

func convertKubearmorPbLogToKubearmorLog(pbLog pb.Log) types.KubeArmorLogAlert {
	return types.KubeArmorLogAlert{
		ClusterName:       pbLog.ClusterName,
		HostName:          pbLog.HostName,
		NamespaceName:     pbLog.ClusterName,
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

func ProcessKubearmorLog(kubearmorLog *pb.Log) {
	var isEntryExist bool
	var err error

	locPbLog := pb.Log{}

	locAlertLog := types.KubeArmorLogAlert{}
	resAlertLog := types.KubeArmorLogAlert{}

	jsonLog, _ := json.Marshal(kubearmorLog)
	if err := json.Unmarshal(jsonLog, &locPbLog); err != nil {
		log.Error().Msg(err.Error())
		return
	}

	locAlertLog = convertKubearmorPbLogToKubearmorLog(locPbLog)
	locAlertLog.Action = "Allow"
	locAlertLog.Category = "Log"

	if isEntryExist, resAlertLog, err = checkIfSystemLogExist(locAlertLog); err != nil {
		log.Error().Msg(err.Error())
		return
	}

	if isEntryExist {
		resAlertLog.Timestamp = locAlertLog.Timestamp
		if err := libs.UpdateKubearmorLogs(CfgDB, resAlertLog); err != nil {
			log.Error().Msg(err.Error())
		}
	} else {
		if err := libs.InsertKubearmorLogs(CfgDB, locAlertLog); err != nil {
			log.Error().Msg(err.Error())
		}
	}
}

func ProcessKubearmorAlert(kubearmorAlert *pb.Log) {
	var isEntryExist bool
	var err error

	locPbLog := pb.Log{}
	locAlertLog := types.KubeArmorLogAlert{}
	resAlertLog := types.KubeArmorLogAlert{}

	jsonLog, _ := json.Marshal(kubearmorAlert)
	if err = json.Unmarshal(jsonLog, &locPbLog); err != nil {
		log.Error().Msg(err.Error())
		return
	}
	locAlertLog = convertKubearmorPbLogToKubearmorLog(locPbLog)
	locAlertLog.Action = "Alert"

	if isEntryExist {
		resAlertLog.Timestamp = locAlertLog.Timestamp
		if err := libs.UpdateKubearmorLogs(CfgDB, resAlertLog); err != nil {
			log.Error().Msg(err.Error())
		}
	} else {
		if err := libs.InsertKubearmorLogs(CfgDB, locAlertLog); err != nil {
			log.Error().Msg(err.Error())
		}
	}
}

func compareSrcDestLogAlert(src types.KubeArmorLogAlert, dest types.KubeArmorLogAlert) bool {
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

func checkIfSystemLogExist(logAlert types.KubeArmorLogAlert) (bool, types.KubeArmorLogAlert, error) {
	locLogAlert := types.KubeArmorLogAlert{}

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
		return false, types.KubeArmorLogAlert{}, err
	}

	for _, locDestLogAlert := range destLogAlert {
		if compareSrcDestLogAlert(logAlert, locDestLogAlert) {
			return true, locLogAlert, nil
		}
	}

	return false, types.KubeArmorLogAlert{}, nil
}
