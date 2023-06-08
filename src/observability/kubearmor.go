package observability

import (
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/accuknox/auto-policy-discovery/src/common"
	"github.com/accuknox/auto-policy-discovery/src/config"
	"github.com/accuknox/auto-policy-discovery/src/libs"
	opb "github.com/accuknox/auto-policy-discovery/src/protobuf/v1/observability"
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

func groupKubeArmorLogs(logs []types.KubeArmorLog) {
	for index, log := range logs {
		if index == 0 {
			KubeArmorLogMap[log] = 1
			continue
		}
		for k, v := range KubeArmorLogMap {
			if log == k {
				KubeArmorLogMap[log] = v + 1
				break
			} else {
				KubeArmorLogMap[log] = 1
				break
			}
		}
	}
}

func clearKubeArmorLogMap() {
	for log := range KubeArmorLogMap {
		delete(KubeArmorLogMap, log)
	}
}

func ProcessSystemLogs() {

	SystemLogsMutex.Lock()
	locSysLogs := SystemLogs
	SystemLogs = []*pb.Alert{} //reset
	SystemLogsMutex.Unlock()

	if len(locSysLogs) <= 0 {
		return
	}

	ObsMutex.Lock()
	defer ObsMutex.Unlock()

	res := []types.KubeArmorLog{}

	if config.GetCfgObservabilityWriteLogsToDB() {
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
				if locLog.Result == "Passed" {
					locLog.Action = "Audit"
				} else {
					locLog.Action = "Deny"
				}
			} else {
				locLog.Action = "Allow"
				locLog.Category = "Log"
			}

			if locLog.Type == "ContainerLog" && locLog.NamespaceName == types.PolicyDiscoveryContainerNamespace {
				locLog.NamespaceName = types.PolicyDiscoveryContainerNamespace
				locLog.PodName = types.PolicyDiscoveryContainerPodName
			}

			if locLog.Type == "HostLog" || locLog.Type == "MatchedHostPolicy" {
				locLog.ContainerName = locLog.HostName
				locLog.NamespaceName = types.PolicyDiscoveryVMNamespace
				locLog.PodName = types.PolicyDiscoveryVMPodName
			}

			if locLog.Operation != "Network" {
				locLog.Source = strings.Split(locLog.Source, " ")[0]
				locLog.Resource = strings.Split(locLog.Resource, " ")[0]
				locLog.Data = ""
			}

			res = append(res, locLog)
		}

		groupKubeArmorLogs(res)

		if err := libs.UpdateOrInsertKubearmorLogs(CfgDB, KubeArmorLogMap); err != nil {
			log.Error().Msg(err.Error())
		}

		clearKubeArmorLogMap()
	}

	// Convert kubearmor sys logs to SystemSummaryMap
	convertSysLogToSysSummaryMap(locSysLogs)

	// update summary map to DB
	if err := libs.UpsertSystemSummary(CfgDB, SummarizerMap); err != nil {
		log.Error().Msg(err.Error())
	}

	if config.GetCfgPublisherEnable() {
		// Update publisher map with summarizer map
		updatePublisherMap()
	}

	//clearSummarizerMap()
}

func ProcessKubearmorLogs(kubearmorLog *pb.Alert) {
	SystemLogsMutex.Lock()
	SystemLogs = append(SystemLogs, kubearmorLog)
	SystemLogsMutex.Unlock()
}

func aggregateProcFileData(data []types.SysObsProcFileData) []types.SysObsProcFileData {
	if len(data) <= 0 {
		return nil
	}

	var destPaths, aggregatedDir []string
	for _, locData := range data {
		destPaths = append(destPaths, locData.Destination)
	}
	aggregatedSysPath := common.AggregatePaths(destPaths)

	for _, sp := range aggregatedSysPath {
		if sp.IsDir {
			aggregatedDir = append(aggregatedDir, sp.Path)
		}
	}

	res := []types.SysObsProcFileData{}

	for _, locData := range data {
		var destination string

		for _, dir := range aggregatedDir {
			if strings.HasPrefix(locData.Destination, dir) {
				destination = dir
				break
			}
			destination = locData.Destination
		}

		locKey := types.SysObsProcFileMapKey{
			Source:      locData.Source,
			Destination: destination,
			Status:      locData.Status,
		}

		v := ProcFileMap[locKey]

		ProcFileMap[locKey] = types.SysObsProcFileMapValue{
			Count:       v.Count + locData.Count,
			UpdatedTime: locData.UpdatedTime,
		}
	}

	for k, v := range ProcFileMap {
		res = append(res, types.SysObsProcFileData{
			Source:      k.Source,
			Destination: k.Destination,
			Status:      k.Status,
			Count:       v.Count,
			UpdatedTime: v.UpdatedTime,
		})
		delete(ProcFileMap, k)
	}

	return res
}

func GetKubearmorSummaryData(req *opb.Request) ([]types.SysObsProcFileData, []types.SysObsProcFileData, []types.SysObsNwData, types.ObsPodDetail) {
	var err error
	var processData, fileData []types.SysObsProcFileData
	var nwData []types.SysObsNwData
	var podInfo types.ObsPodDetail

	sysSummary, err := libs.GetSystemSummary(CfgDB, types.SystemSummary{
		PodName:       req.PodName,
		NamespaceName: req.NameSpace,
		ContainerName: req.ContainerName,
		ClusterName:   req.ClusterName,
		Labels:        req.Label,
		Deployment:    req.DeployName,
	})
	if err != nil {
		return nil, nil, nil, types.ObsPodDetail{}
	}

	for i, ss := range sysSummary {
		if i == 0 {
			podInfo.PodName = ss.PodName
			podInfo.ClusterName = ss.ClusterName
			podInfo.ContainerName = ss.ContainerName
			podInfo.Labels = ss.Labels
			podInfo.Namespace = ss.NamespaceName
			podInfo.DeployName = ss.Deployment
		}

		t := time.Unix(ss.UpdatedTime, 0)

		if ss.Operation == "Process" {
			//ExtractProcessData
			processData = append(processData, types.SysObsProcFileData{
				Source:      ss.Source,
				Destination: ss.Destination,
				Status:      ss.Action,
				Count:       uint32(ss.Count),
				UpdatedTime: t.Format(time.UnixDate),
			})
		} else if ss.Operation == "File" {
			//ExtractFileData
			fileData = append(fileData, types.SysObsProcFileData{
				Source:      ss.Source,
				Destination: ss.Destination,
				Status:      ss.Action,
				Count:       uint32(ss.Count),
				UpdatedTime: t.Format(time.UnixDate),
			})
		} else if ss.Operation == "Network" {
			//ExtractNwData
			nwData = append(nwData, types.SysObsNwData{
				NetType:     ss.NwType,
				Protocol:    ss.Protocol,
				Command:     ss.Source,
				PodSvcIP:    ss.IP,
				ServerPort:  strconv.Itoa(int(ss.Port)),
				BindPort:    ss.BindPort,
				BindAddress: ss.BindAddress,
				Namespace:   ss.DestNamespace,
				Labels:      ss.DestLabels,
				Count:       uint32(ss.Count),
				UpdatedTime: t.Format(time.UnixDate),
			})
		}
	}

	if req.Aggregate {
		fileData = aggregateProcFileData(fileData)
	}

	return processData, fileData, nwData, podInfo
}
