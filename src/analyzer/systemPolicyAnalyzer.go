package analyzer

import (
	apb "github.com/accuknox/knoxAutoPolicy/src/protobuf/v1/analyzer"
	syspolicy "github.com/accuknox/knoxAutoPolicy/src/systempolicy"
	types "github.com/accuknox/knoxAutoPolicy/src/types"
)

func populatePbSysPolicyFromSysPolicy(KnoxSysPolicy types.KnoxSystemPolicy) apb.KnoxSystemPolicy {
	pbSysPolicy := apb.KnoxSystemPolicy{}
	pbProcKnoxMatchPaths := []*apb.KnoxMatchPaths{}
	pbProcKnoxMatchDirectories := []*apb.KnoxMatchDirectories{}
	pbFileKnoxMatchPaths := []*apb.KnoxMatchPaths{}
	pbFileKnoxMatchDirectories := []*apb.KnoxMatchDirectories{}
	pbKnoxMatchProtocols := []*apb.KnoxMatchProtocols{}

	pbSysSpec := &apb.KnoxSystemSpec{}
	pbSelector := &apb.Selector{}
	pbProcessKnoxSys := &apb.KnoxSys{}
	pbFileKnoxSys := &apb.KnoxSys{}

	// Basic values
	pbSysPolicy.APIVersion = KnoxSysPolicy.APIVersion
	pbSysPolicy.Kind = KnoxSysPolicy.Kind
	pbSysPolicy.Metadata = KnoxSysPolicy.Metadata
	pbSysPolicy.Outdated = KnoxSysPolicy.Outdated

	// Spec
	pbSysSpec.Severity = int32(KnoxSysPolicy.Spec.Severity)
	pbSysSpec.Tags = append(pbSysPolicy.SysSpec.Tags, KnoxSysPolicy.Spec.Tags...)
	pbSysSpec.Message = KnoxSysPolicy.Spec.Message

	// Spec Selector
	pbSelector.MatchLabels = KnoxSysPolicy.Spec.Selector.MatchLabels
	pbSysPolicy.SysSpec.SystemSelector = pbSelector

	// KnoxSys Process -- MatchPaths
	for _, procMatchPath := range KnoxSysPolicy.Spec.Process.MatchPaths {
		pbKnoxMatchPath := apb.KnoxMatchPaths{}
		pbKnoxMatchPath.Path = procMatchPath.Path
		pbKnoxMatchPath.ReadOnly = procMatchPath.ReadOnly
		pbKnoxMatchPath.OwnerOnly = procMatchPath.OwnerOnly
		for _, knoxFromSource := range procMatchPath.FromSource {
			pbKnoxFromSrc := apb.KnoxFromSource{}
			pbKnoxFromSrc.Path = knoxFromSource.Path
			pbKnoxFromSrc.Dir = knoxFromSource.Dir
			pbKnoxFromSrc.Recursive = knoxFromSource.Recursive
			pbKnoxMatchPath.FromSource = append(pbKnoxMatchPath.FromSource, &pbKnoxFromSrc)
		}
		pbProcKnoxMatchPaths = append(pbProcKnoxMatchPaths, &pbKnoxMatchPath)
	}

	// KnoxSys Process -- MatchDir
	for _, procMatchDir := range KnoxSysPolicy.Spec.Process.MatchDirectories {
		pbKnoxMatchDir := apb.KnoxMatchDirectories{}
		pbKnoxMatchDir.Dir = procMatchDir.Dir
		pbKnoxMatchDir.ReadOnly = procMatchDir.ReadOnly
		pbKnoxMatchDir.OwnerOnly = procMatchDir.OwnerOnly
		for _, knoxFromSource := range procMatchDir.FromSource {
			pbKnoxFromSrc := apb.KnoxFromSource{}
			pbKnoxFromSrc.Path = knoxFromSource.Path
			pbKnoxFromSrc.Dir = knoxFromSource.Dir
			pbKnoxFromSrc.Recursive = knoxFromSource.Recursive
			pbKnoxMatchDir.FromSource = append(pbKnoxMatchDir.FromSource, &pbKnoxFromSrc)
		}
		pbProcKnoxMatchDirectories = append(pbProcKnoxMatchDirectories, &pbKnoxMatchDir)
	}

	// KnoxSys File -- MatchPaths
	for _, fileMatchPath := range KnoxSysPolicy.Spec.File.MatchPaths {
		pbKnoxMatchPath := apb.KnoxMatchPaths{}
		pbKnoxMatchPath.Path = fileMatchPath.Path
		pbKnoxMatchPath.ReadOnly = fileMatchPath.ReadOnly
		pbKnoxMatchPath.OwnerOnly = fileMatchPath.OwnerOnly
		for _, knoxFromSource := range fileMatchPath.FromSource {
			pbKnoxFromSrc := apb.KnoxFromSource{}
			pbKnoxFromSrc.Path = knoxFromSource.Path
			pbKnoxFromSrc.Dir = knoxFromSource.Dir
			pbKnoxFromSrc.Recursive = knoxFromSource.Recursive
			pbKnoxMatchPath.FromSource = append(pbKnoxMatchPath.FromSource, &pbKnoxFromSrc)
		}
		pbFileKnoxMatchPaths = append(pbFileKnoxMatchPaths, &pbKnoxMatchPath)
	}

	// KnoxSys File -- MatchDir
	for _, fileMatchDir := range KnoxSysPolicy.Spec.File.MatchDirectories {
		pbKnoxMatchDir := apb.KnoxMatchDirectories{}
		pbKnoxMatchDir.Dir = fileMatchDir.Dir
		pbKnoxMatchDir.ReadOnly = fileMatchDir.ReadOnly
		pbKnoxMatchDir.OwnerOnly = fileMatchDir.OwnerOnly
		for _, knoxFromSource := range fileMatchDir.FromSource {
			pbKnoxFromSrc := apb.KnoxFromSource{}
			pbKnoxFromSrc.Path = knoxFromSource.Path
			pbKnoxFromSrc.Dir = knoxFromSource.Dir
			pbKnoxFromSrc.Recursive = knoxFromSource.Recursive
			pbKnoxMatchDir.FromSource = append(pbKnoxMatchDir.FromSource, &pbKnoxFromSrc)
		}
		pbFileKnoxMatchDirectories = append(pbFileKnoxMatchDirectories, &pbKnoxMatchDir)
	}

	// Spec -- Match Protocol
	for _, matchProtocol := range KnoxSysPolicy.Spec.Network {
		pbMatchProtocol := apb.KnoxMatchProtocols{}
		pbMatchProtocol.Protocol = matchProtocol.Protocol
		for _, fromSrc := range matchProtocol.FromSource {
			pbFromSrc := apb.KnoxFromSource{}
			pbFromSrc.Path = fromSrc.Path
			pbFromSrc.Dir = fromSrc.Dir
			pbFromSrc.Recursive = fromSrc.Recursive
			pbMatchProtocol.FromSource = append(pbMatchProtocol.FromSource, &pbFromSrc)
		}
		pbKnoxMatchProtocols = append(pbKnoxMatchProtocols, &pbMatchProtocol)
	}

	pbProcessKnoxSys.MatchPaths = pbProcKnoxMatchPaths
	pbProcessKnoxSys.MatchDirectories = pbProcKnoxMatchDirectories
	pbFileKnoxSys.MatchPaths = pbFileKnoxMatchPaths
	pbFileKnoxSys.MatchDirectories = pbFileKnoxMatchDirectories

	pbSysPolicy.SysSpec = pbSysSpec
	pbSysPolicy.SysSpec.Process = pbProcessKnoxSys
	pbSysPolicy.SysSpec.File = pbFileKnoxSys

	pbSysPolicy.SysSpec.Network = pbKnoxMatchProtocols

	// Spec Action
	pbSysPolicy.SysSpec.Action = KnoxSysPolicy.Spec.Action

	pbSysPolicy.GeneratedTime = KnoxSysPolicy.GeneratedTime

	return pbSysPolicy
}

func extractSystemPoliciesFromSystemLogs(systemLogs []types.KnoxSystemLog) []*apb.KnoxSystemPolicy {

	pbSystemPolicies := []*apb.KnoxSystemPolicy{}
	systemPolicies := syspolicy.PopulateSystemPoliciesFromSystemLogs(systemLogs)

	for _, sysPolicy := range systemPolicies {
		pbSysPolicy := populatePbSysPolicyFromSysPolicy(sysPolicy)
		pbSystemPolicies = append(pbSystemPolicies, &pbSysPolicy)
	}

	return pbSystemPolicies
}

func populateSystemLogs(pbSysLogs []*apb.KnoxSystemLog) []types.KnoxSystemLog {
	sysLogs := []types.KnoxSystemLog{}

	// Populate KnoxSystemLog from Protobuf's SystemLog
	for _, pbSysLog := range pbSysLogs {
		sysLog := types.KnoxSystemLog{}
		sysLog.LogID = int(pbSysLog.LogID)
		sysLog.ClusterName = pbSysLog.ClusterName
		sysLog.HostName = pbSysLog.HostName
		sysLog.Namespace = pbSysLog.Namespace
		sysLog.PodName = pbSysLog.PodName
		sysLog.SourceOrigin = pbSysLog.SourceOrigin
		sysLog.Source = pbSysLog.Source
		sysLog.Operation = pbSysLog.Operation
		sysLog.ResourceOrigin = pbSysLog.ResourceOrigin
		sysLog.Resource = pbSysLog.Resource
		sysLog.Data = pbSysLog.Data
		sysLog.ReadOnly = pbSysLog.ReadOnly
		sysLog.Result = pbSysLog.Result

		sysLogs = append(sysLogs, sysLog)
	}

	return sysLogs
}

func GetSystemPolicies(pbSystemLogs []*apb.KnoxSystemLog) []*apb.KnoxSystemPolicy {

	systemLogs := populateSystemLogs(pbSystemLogs)
	systemPolicies := extractSystemPoliciesFromSystemLogs(systemLogs)

	return systemPolicies
}
