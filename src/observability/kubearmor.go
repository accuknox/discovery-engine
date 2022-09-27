package observability

import (
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/accuknox/auto-policy-discovery/src/cluster"
	"github.com/accuknox/auto-policy-discovery/src/common"
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

	if len(SystemLogs) <= 0 {
		return
	}
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
			ObsMutex.Unlock()
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

	ObsMutex.Unlock()
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

func extractPodSvcInfoFromIP(ip, clustername string) (string, string, string) {
	podSvcName := ip

	_, services, _, pods, err := cluster.GetAllClusterResources(clustername)
	if err != nil {
		return podSvcName, "", ""
	}

	for _, pod := range pods {
		if pod.PodIP == ip {
			return "pod/" + pod.PodName, strings.Join(sort.StringSlice(pod.Labels), ","), pod.Namespace
		}
	}
	for _, svc := range services {
		if svc.ClusterIP == ip {
			return "svc/" + svc.ServiceName, strings.Join(svc.Labels, ","), svc.Namespace
		}
	}

	return podSvcName, "", ""
}

func fetchSysServerConnDetail(log types.KubeArmorLog) (types.SysObsNwData, error) {
	conn := types.SysObsNwData{}
	err := errors.New("not a valid incoming/outgoing connection")

	// get Syscall
	if strings.Contains(log.Data, "tcp_connect") || strings.Contains(log.Data, "SYS_CONNECT") {
		conn.InOut = "OUT"
		conn.Count++
		conn.UpdatedTime = time.UnixDate
	} else if strings.Contains(log.Data, "tcp_accept") || strings.Contains(log.Data, "SYS_ACCEPT") {
		conn.InOut = "IN"
		conn.Count++
		conn.UpdatedTime = time.UnixDate
	} else {
		return types.SysObsNwData{}, err
	}

	// get AF detail
	if strings.Contains(log.Data, "AF_INET") && strings.Contains(log.Data, "tcp_") {
		resslice := strings.Split(log.Resource, " ")
		for _, locres := range resslice {
			if strings.Contains(locres, "remoteip") {
				conn.PodSvcIP, conn.Labels, conn.Namespace = extractPodSvcInfoFromIP(strings.Split(locres, "=")[1], log.ClusterName)
			}
			if strings.Contains(locres, "port") {
				conn.ServerPort = strings.Split(locres, "=")[1]
			}
			if strings.Contains(locres, "protocol") {
				conn.Protocol = strings.Split(locres, "=")[1]
			}
		}
	} else if strings.Contains(log.Resource, "AF_UNIX") {
		var path string
		resslice := strings.Split(log.Resource, " ")
		for _, locres := range resslice {
			if strings.Contains(locres, "sun_path") {
				path = strings.Split(locres, "=")[1]
				if path != "" {
					conn.PodSvcIP = path
					conn.Protocol = "UNIX"
					break
				}
			}
		}
	} else {
		return types.SysObsNwData{}, err
	}

	if conn.PodSvcIP == "" {
		return types.SysObsNwData{}, err
	}

	conn.Command = strings.Split(log.Source, " ")[0]

	return conn, nil
}

func deDuplicateServerInOutConn(connList []types.SysObsNwData) []types.SysObsNwData {
	occurred := map[types.SysObsNwData]bool{}
	result := []types.SysObsNwData{}
	for index := range connList {
		if !occurred[connList[index]] {
			occurred[connList[index]] = true
			// Append to result slice.
			result = append(result, connList[index])
		}
	}
	return result
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

	// Get DB data
	systemLogs, systemTotal, err := libs.GetKubearmorLogs(CfgDB, types.KubeArmorLog{
		PodName: req.PodName,
	})
	if err != nil {
		return nil, nil, nil, types.ObsPodDetail{}
	}

	for sysindex, locSysLog := range systemLogs {

		if sysindex == 0 {
			podInfo.PodName = locSysLog.PodName
			podInfo.ClusterName = locSysLog.ClusterName
			podInfo.ContainerName = locSysLog.ContainerName
			podInfo.Labels = locSysLog.Labels
			podInfo.Namespace = locSysLog.NamespaceName
		}

		t := time.Unix(locSysLog.UpdatedTime, 0)

		if locSysLog.Operation == "Process" {
			//ExtractProcessData
			processData = append(processData, types.SysObsProcFileData{
				Source:      locSysLog.Source,
				Destination: locSysLog.Resource,
				Status:      locSysLog.Action,
				Count:       systemTotal[sysindex],
				UpdatedTime: t.Format(time.UnixDate),
			})
		} else if locSysLog.Operation == "File" {
			//ExtractFileData
			fileData = append(fileData, types.SysObsProcFileData{
				Source:      locSysLog.Source,
				Destination: locSysLog.Resource,
				Status:      locSysLog.Action,
				Count:       systemTotal[sysindex],
				UpdatedTime: t.Format(time.UnixDate),
			})

		} else if locSysLog.Operation == "Network" {
			//ExtractNwData
			nwobsdata, err := fetchSysServerConnDetail(locSysLog)
			if err == nil {
				nwData = append(nwData, nwobsdata)
			}
		}
	}

	if len(nwData) > 0 {
		nwData = deDuplicateServerInOutConn(nwData)
	}

	if req.Aggregate {
		fileData = aggregateProcFileData(fileData)
	}

	return processData, fileData, nwData, podInfo
}
