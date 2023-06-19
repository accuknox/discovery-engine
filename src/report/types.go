package report

import "github.com/accuknox/auto-policy-discovery/src/types"

//
//import opb "github.com/accuknox/auto-policy-discovery/src/protobuf/v1/observability"
//
//type Report struct {
//	Clusters []*Clusters
//}
//
//type Clusters struct {
//	ClusterName string
//	Namespaces  []*Namespaces
//}
//
//type Namespaces struct {
//	NamespaceName string
//	Resources     []*Resources
//}
//
//type Resources struct {
//	ResourceType string
//	ResourceName string
//	PodName      map[string]*SummaryData
//}
//
//type SummaryData struct {
//	ProcessData       []*opb.SysProcFileSummaryData
//	FileData          []*opb.SysProcFileSummaryData
//	IngressConnection []*opb.SysNwSummaryData
//	EgressConnection  []*opb.SysNwSummaryData
//	BindNwResp        []*opb.SysNwSummaryData
//}

type ReportData struct {
	Clusters map[string]Clusters
}

type Clusters struct {
	ClusterName string
	Namespaces  map[string]Namespaces
}

type Namespaces struct {
	NamespaceName     string
	ResourceTypesData map[string]ResourceTypeData
}

//
//type Clusters struct {
//	NamespaceName []string
//	Namespace     map[string]ResourceTypeData
//}

type ResourceTypeData struct {
	ResourceType        string
	ResourceSummaryData map[string]ResourceData
}

type ResourceData struct {
	ResourceType string
	ResourceName string
	MetaData     *types.MetaData
	SummaryData  *SummaryData
}

type SummaryData struct {
	ProcessData []types.SysObsProcFileData
	FileData    []types.SysObsProcFileData
	NetworkData []types.SysObsNwData
}
