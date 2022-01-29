package systempolicy

import (
	"errors"

	"github.com/accuknox/auto-policy-discovery/src/libs"
	types "github.com/accuknox/auto-policy-discovery/src/types"
)

func convertWPFSToObservabilityData(wpfsSet map[types.WorkloadProcessFileSet][]string, policyNames []string) []types.SysObservabilityData {
	if len(wpfsSet) != len(policyNames) {
		log.Error().Msgf("len(wpfsSet):%d != len(policyNames):%d", len(wpfsSet), len(policyNames))
		return nil
	}

	var (
		wpfsArr []types.SysObservabilityData
		idx     = 0
	)
	for wpfs, fsset := range wpfsSet {
		var locWpfs types.SysObservabilityData
		locWpfs.PolicyName = policyNames[idx]
		locWpfs.ClusterName = wpfs.ClusterName
		locWpfs.ContainerName = wpfs.ContainerName
		locWpfs.Namespace = wpfs.Namespace
		locWpfs.Labels = wpfs.Labels
		locWpfs.FromSource = wpfs.FromSource
		locWpfs.SetType = wpfs.SetType
		locWpfs.Paths = append(locWpfs.Paths, fsset...)

		wpfsArr = append(wpfsArr, locWpfs)
		idx++
	}

	return wpfsArr
}

func GetSystemObsData(clusterName string, containerName string, namespace string) error {

	wpfs := types.WorkloadProcessFileSet{}
	wpfs.ClusterName = clusterName
	wpfs.ContainerName = containerName
	wpfs.Namespace = namespace

	res, policyNames, err := libs.GetWorkloadProcessFileSet(CfgDB, wpfs)
	if err != nil {
		return err
	}

	sysObsData := convertWPFSToObservabilityData(res, policyNames)
	if len(sysObsData) == 0 {
		return errors.New("no data in db")
	}

	libs.WriteSysObsDataToJsonFile(sysObsData)

	return nil
}
