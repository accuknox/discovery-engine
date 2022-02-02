package systempolicy

import (
	"github.com/accuknox/auto-policy-discovery/src/libs"
	opb "github.com/accuknox/auto-policy-discovery/src/protobuf/v1/observability"
	types "github.com/accuknox/auto-policy-discovery/src/types"
)

func convertWPFSToObservabilityData(wpfsSet map[types.WorkloadProcessFileSet][]string, policyNames []string) types.SysObsResponseData {
	if len(wpfsSet) != len(policyNames) {
		log.Error().Msgf("len(wpfsSet):%d != len(policyNames):%d", len(wpfsSet), len(policyNames))
		return types.SysObsResponseData{}
	}

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

func convertSysObsDataToResponse(resData types.SysObsResponseData) opb.SysObsResponse {
	obsResData := opb.SysObsResponse{}

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

			locObsResData.Resources = append(locObsResData.Resources, &locfsset)
		}

		obsResData.Data = append(obsResData.Data, &locObsResData)
	}

	return obsResData
}

func GetSystemObsData(clusterName string, containerName string, namespace string, labels string) (opb.SysObsResponse, error) {

	sysObsResData := types.SysObsResponseData{}
	wpfs := types.WorkloadProcessFileSet{}

	wpfs.ClusterName = clusterName
	wpfs.ContainerName = containerName
	wpfs.Namespace = namespace
	wpfs.Labels = labels

	res, policyNames, _ := libs.GetWorkloadProcessFileSet(CfgDB, wpfs)

	sysObsResData = convertWPFSToObservabilityData(res, policyNames)

	// Write Observability data to json file
	libs.WriteSysObsDataToJsonFile(sysObsResData)

	// Generate json response gRPC
	opbSysObsResponse := convertSysObsDataToResponse(sysObsResData)

	return opbSysObsResponse, nil
}
