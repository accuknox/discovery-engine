package systempolicy

import (
	"github.com/accuknox/auto-policy-discovery/src/libs"
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

func GetSystemObsData(clusterName string, containerName string, namespace string, labels string) error {

	wpfs := types.WorkloadProcessFileSet{}
	var sysObsData types.SysObservabilityData
	wpfs.ClusterName = clusterName
	wpfs.ContainerName = containerName
	wpfs.Namespace = namespace
	wpfs.Labels = labels

	res, policyNames, err := libs.GetWorkloadProcessFileSet(CfgDB, wpfs)
	if err != nil {
		return err
	}

	sysObsProcessFileData := convertWPFSToObservabilityData(res, policyNames)

	sysObsData.ClusterName = clusterName
	sysObsData.ContainerName = containerName
	sysObsData.Labels = labels
	sysObsData.Namespace = namespace
	sysObsData.SysProcessFileData = sysObsProcessFileData

	libs.WriteSysObsDataToJsonFile(sysObsData)

	return nil
}
