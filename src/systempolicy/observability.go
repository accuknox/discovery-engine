package systempolicy

import (
	"github.com/accuknox/auto-policy-discovery/src/libs"
	opb "github.com/accuknox/auto-policy-discovery/src/protobuf/v1/observability"
	types "github.com/accuknox/auto-policy-discovery/src/types"
)

func convertWPFSToObservabilityData(wpfsSet map[types.WorkloadProcessFileSet][]string, policyNames []string) []types.SysObsProcessFileData {
	if len(wpfsSet) != len(policyNames) {
		log.Error().Msgf("len(wpfsSet):%d != len(policyNames):%d", len(wpfsSet), len(policyNames))
		return nil
	}

	var sysObsProcessFileData []types.SysObsProcessFileData

	for wpfs, fsset := range wpfsSet {
		var locSysObsProcessFileData types.SysObsProcessFileData

		locSysObsProcessFileData.FromSource = wpfs.FromSource
		if wpfs.SetType == SYS_OP_PROCESS {
			locSysObsProcessFileData.ProcessPaths = append(locSysObsProcessFileData.ProcessPaths, fsset...)
		}
		if wpfs.SetType == SYS_OP_FILE {
			locSysObsProcessFileData.FilePaths = append(locSysObsProcessFileData.FilePaths, fsset...)
		}
		sysObsProcessFileData = append(sysObsProcessFileData, locSysObsProcessFileData)
	}

	return sysObsProcessFileData
}

func convertSysObsDataToResponse(obsData types.SysObservabilityData) opb.SysObsResponse {
	obsResData := opb.SysObsResponse{}

	obsResData.ClusterName = obsData.ClusterName
	obsResData.ContainerName = obsData.ContainerName
	obsResData.Namespace = obsData.Namespace
	obsResData.Labels = obsData.Labels

	for _, pfs := range obsData.SysProcessFileData {
		processFileSet := opb.SysProcessFileData{}

		processFileSet.FromSource = pfs.FromSource
		processFileSet.ProcessPaths = append(processFileSet.ProcessPaths, pfs.ProcessPaths...)
		processFileSet.FilePaths = append(processFileSet.FilePaths, pfs.FilePaths...)

		obsResData.ProcessFiles = append(obsResData.ProcessFiles, &processFileSet)
	}

	return obsResData
}

func GetSystemObsData(clusterName string, containerName string, namespace string, labels string) (opb.SysObsResponse, error) {

	sysObsData := types.SysObservabilityData{}

	wpfs := types.WorkloadProcessFileSet{}
	wpfs.ClusterName = clusterName
	wpfs.ContainerName = containerName
	wpfs.Namespace = namespace
	wpfs.Labels = labels

	res, policyNames, _ := libs.GetWorkloadProcessFileSet(CfgDB, wpfs)

	sysObsProcessFileData := convertWPFSToObservabilityData(res, policyNames)

	sysObsData.ClusterName = clusterName
	sysObsData.ContainerName = containerName
	sysObsData.Labels = labels
	sysObsData.Namespace = namespace
	sysObsData.SysProcessFileData = sysObsProcessFileData

	// Write Observability data to json file
	libs.WriteSysObsDataToJsonFile(sysObsData)

	// Generate json response gRPC
	opbSysObsResponse := convertSysObsDataToResponse(sysObsData)

	return opbSysObsResponse, nil
}
