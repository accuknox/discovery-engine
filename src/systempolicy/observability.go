package systempolicy

import (
	"errors"
	"time"

	"github.com/accuknox/auto-policy-discovery/src/libs"
	opb "github.com/accuknox/auto-policy-discovery/src/protobuf/v1/observability"
	types "github.com/accuknox/auto-policy-discovery/src/types"
)

func convertWPFSToObservabilityData(wpfsSet types.ResourceSetMap) types.SysObsResponseData {
	var resData types.SysObsResponseData

	for wpfs, fsset := range wpfsSet {
		var locFsData types.SysObsProcessFileData
		var locObsData types.SysObservabilityData

		// Populate Fileset data(fromsource, process paths and file paths)
		locFsData.FromSource = wpfs.FromSource
		if wpfs.SetType == SYS_OP_FILE {
			locFsData.FilePaths = append(locFsData.FilePaths, fsset...)
		}
		if wpfs.SetType == SYS_OP_PROCESS {
			locFsData.ProcessPaths = append(locFsData.ProcessPaths, fsset...)
		}
		if wpfs.SetType == SYS_OP_NETWORK {
			locFsData.NetworkPaths = append(locFsData.NetworkPaths, fsset...)
		}

		if len(resData.Data) > 0 {
			idx := 0
			for _, locResData := range resData.Data {
				if locResData.ClusterName == wpfs.ClusterName && locResData.Namespace == wpfs.Namespace &&
					locResData.Labels == wpfs.Labels && locResData.ContainerName == wpfs.ContainerName {
					resData.Data[idx].SysProcessFileData = append(resData.Data[idx].SysProcessFileData, locFsData)
					break
				}
				idx++
			}

			if idx == len(resData.Data) {
				locObsData.ClusterName = wpfs.ClusterName
				locObsData.Namespace = wpfs.Namespace
				locObsData.Labels = wpfs.Labels
				locObsData.ContainerName = wpfs.ContainerName
				locObsData.SysProcessFileData = append(locObsData.SysProcessFileData, locFsData)

				resData.Data = append(resData.Data, locObsData)
			}
		} else {
			locObsData.ClusterName = wpfs.ClusterName
			locObsData.Namespace = wpfs.Namespace
			locObsData.Labels = wpfs.Labels
			locObsData.ContainerName = wpfs.ContainerName
			locObsData.SysProcessFileData = append(locObsData.SysProcessFileData, locFsData)

			resData.Data = append(resData.Data, locObsData)
		}
	}

	return resData
}

func convertSysObsDataToResponse(resData types.SysObsResponseData) opb.Response {
	obsResData := opb.Response{}

	for _, locResData := range resData.Data {
		var locObsResData opb.SysObsResponseData

		locObsResData.ClusterName = locResData.ClusterName
		locObsResData.NameSpace = locResData.Namespace
		locObsResData.Labels = locResData.Labels
		locObsResData.ContainerName = locResData.ContainerName

		for _, fsset := range locResData.SysProcessFileData {
			locfsset := opb.SysProcessFileData{}
			locfsset.FromSource = fsset.FromSource
			locfsset.FilePaths = append(locfsset.FilePaths, fsset.FilePaths...)
			locfsset.ProcessPaths = append(locfsset.ProcessPaths, fsset.ProcessPaths...)
			locfsset.NetworkPaths = append(locfsset.NetworkPaths, fsset.NetworkPaths...)

			locObsResData.Resources = append(locObsResData.Resources, &locfsset)
		}

		obsResData.Data = append(obsResData.Data, &locObsResData)
	}

	return obsResData
}

func GetSystemObsData(wpfs types.WorkloadProcessFileSet) (opb.Response, error) {

	sysObsResData := types.SysObsResponseData{}

	res, _, _ := libs.GetWorkloadProcessFileSet(CfgDB, wpfs)

	sysObsResData = convertWPFSToObservabilityData(res)

	// Write Observability data to json file
	libs.WriteSysObsDataToJsonFile(sysObsResData)

	// Generate json response gRPC
	opbSysObsResponse := convertSysObsDataToResponse(sysObsResData)

	return opbSysObsResponse, nil
}

func ClearSysDb(wpfs types.WorkloadProcessFileSet, durationStr string) error {
	if durationStr == "0" {
		return errors.New("not a valid duration")
	}
	duration, err := time.ParseDuration(durationStr)
	if err != nil {
		return err
	}
	err = libs.ClearWPFSDb(CfgDB, wpfs, int64(duration.Seconds()))
	return err
}
