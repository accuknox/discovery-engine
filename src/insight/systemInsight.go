package insight

import (
	"errors"
	"time"

	"github.com/accuknox/auto-policy-discovery/src/libs"
	ipb "github.com/accuknox/auto-policy-discovery/src/protobuf/v1/insight"
	sys "github.com/accuknox/auto-policy-discovery/src/systempolicy"
	types "github.com/accuknox/auto-policy-discovery/src/types"
)

func ConvertSysInsDataToInsResponse(sysdata ipb.SystemInsightData) ipb.InsightResponse {
	var locsysinsdata ipb.SystemInsightData
	var insresp ipb.InsightResponse

	locsysinsdata.ContainerName = sysdata.ContainerName
	locsysinsdata.SysResource = sysdata.SysResource

	insresp.ClusterName = sysdata.ClusterName
	insresp.NameSpace = sysdata.Namespace
	insresp.Labels = sysdata.Labels
	insresp.SystemResource = append(insresp.SystemResource, &locsysinsdata)

	return ipb.InsightResponse{
		ClusterName:    insresp.ClusterName,
		NameSpace:      insresp.NameSpace,
		Labels:         insresp.Labels,
		SystemResource: insresp.SystemResource,
	}
}

func convertWPFSToInsightData(wpfsSet types.ResourceSetMap) types.SysInsightResponseData {
	var resData types.SysInsightResponseData

	for wpfs, fsset := range wpfsSet {
		var locFsData types.SystemData
		var locObsData types.SysInsightData

		// Populate Fileset data(fromsource, process paths and file paths)
		locFsData.FromSource = wpfs.FromSource
		if wpfs.SetType == sys.SYS_OP_FILE {
			locFsData.FilePaths = append(locFsData.FilePaths, fsset...)
		}
		if wpfs.SetType == sys.SYS_OP_PROCESS {
			locFsData.ProcessPaths = append(locFsData.ProcessPaths, fsset...)
		}
		if wpfs.SetType == sys.SYS_OP_NETWORK {
			locFsData.NetworkPaths = append(locFsData.NetworkPaths, fsset...)
		}

		if len(resData.SysData) > 0 {
			idx := 0
			for _, locResData := range resData.SysData {
				if locResData.ClusterName == wpfs.ClusterName && locResData.Namespace == wpfs.Namespace &&
					locResData.Labels == wpfs.Labels && locResData.ContainerName == wpfs.ContainerName {
					resData.SysData[idx].SysProcessFileData = append(resData.SysData[idx].SysProcessFileData, locFsData)
					break
				}
				idx++
			}

			if idx == len(resData.SysData) {
				locObsData.ClusterName = wpfs.ClusterName
				locObsData.Namespace = wpfs.Namespace
				locObsData.Labels = wpfs.Labels
				locObsData.ContainerName = wpfs.ContainerName
				locObsData.SysProcessFileData = append(locObsData.SysProcessFileData, locFsData)

				resData.SysData = append(resData.SysData, locObsData)
			}
		} else {
			locObsData.ClusterName = wpfs.ClusterName
			locObsData.Namespace = wpfs.Namespace
			locObsData.Labels = wpfs.Labels
			locObsData.ContainerName = wpfs.ContainerName
			locObsData.SysProcessFileData = append(locObsData.SysProcessFileData, locFsData)

			resData.SysData = append(resData.SysData, locObsData)
		}
	}

	return resData
}

func convertSysInsDataToResponse(resData types.SysInsightResponseData) []ipb.SystemInsightData {
	response := []ipb.SystemInsightData{}

	for _, locResData := range resData.SysData {
		var locInsData ipb.SystemInsightData

		locInsData.ClusterName = locResData.ClusterName
		locInsData.Namespace = locResData.Namespace
		locInsData.Labels = locResData.Labels
		locInsData.ContainerName = locResData.ContainerName

		for _, fsset := range locResData.SysProcessFileData {
			locfsset := ipb.SystemData{}
			locfsset.FromSource = fsset.FromSource
			locfsset.FilePaths = append(locfsset.FilePaths, fsset.FilePaths...)
			locfsset.ProcessPaths = append(locfsset.ProcessPaths, fsset.ProcessPaths...)
			locfsset.NetworkProtocol = append(locfsset.NetworkProtocol, fsset.NetworkPaths...)

			locInsData.SysResource = append(locInsData.SysResource, &locfsset)
		}

		response = append(response, locInsData)
	}

	return response
}

func getSysInsightData(wpfs types.WorkloadProcessFileSet) ([]ipb.SystemInsightData, error) {

	systemData := types.SysInsightResponseData{}

	res, _, _ := libs.GetWorkloadProcessFileSet(sys.CfgDB, wpfs)

	systemData = convertWPFSToInsightData(res)

	// Write Observability data to json file
	//libs.WriteSysObsDataToJsonFile(sysObsResData)

	// Generate json response gRPC
	sysInsightData := convertSysInsDataToResponse(systemData)

	return sysInsightData, nil
}

func ClearSysDb(wpfs types.WorkloadProcessFileSet, durationStr string) error {
	if durationStr == "0" {
		return errors.New("not a valid duration")
	}
	duration, err := time.ParseDuration(durationStr)
	if err != nil {
		return err
	}
	err = libs.ClearWPFSDb(sys.CfgDB, wpfs, int64(duration.Seconds()))
	return err
}

func GetSysInsightData(request types.InsightRequest) ([]ipb.SystemInsightData, error) {

	var wpfs types.WorkloadProcessFileSet

	wpfs.ContainerName = request.ContainerName
	wpfs.ClusterName = request.ClusterName
	wpfs.FromSource = request.FromSource
	wpfs.Namespace = request.Namespace
	wpfs.Labels = request.Labels

	if request.Request == "dbclear" {
		err := ClearSysDb(wpfs, request.Duration)
		return nil, err
	} else if request.Request == "observe" {
		sysData, err := getSysInsightData(wpfs)
		return sysData, err
	}

	return nil, errors.New("not a valid request, use observe/dbclear")
}

func GetSystemInsightData(req types.InsightRequest) (ipb.Response, error) {
	var resp ipb.Response

	sysData, err := GetSysInsightData(req)

	if req.Request != "observe" || sysData == nil || len(sysData) == 0 {
		return resp, err
	}

	locInsightSysResp := ipb.InsightResponse{}
	idx := 0
	for idx < len(sysData) {
		locInsightSysResp.SystemResource = append(locInsightSysResp.SystemResource, &sysData[idx])
		idx++
	}

	resp.Res = append(resp.Res, &locInsightSysResp)
	return resp, err
}
