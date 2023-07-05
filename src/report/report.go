package report

import (
	cfg "github.com/accuknox/auto-policy-discovery/src/config"
	"github.com/accuknox/auto-policy-discovery/src/libs"
	"github.com/accuknox/auto-policy-discovery/src/observability"
	opb "github.com/accuknox/auto-policy-discovery/src/protobuf/v1/observability"
	rpb "github.com/accuknox/auto-policy-discovery/src/protobuf/v1/report"
	"github.com/accuknox/auto-policy-discovery/src/types"
	"strconv"
)

type Config struct {
	CfgDB types.ConfigDB
}

func InitializeConfig() {
	Rcfg = &Config{CfgDB: cfg.GetCfgDB()}
}

var Rcfg *Config

type Options struct {
	options *types.ReportOptions
}

func (o *Options) GetReport() (*rpb.ReportResponse, error) {

	res, err := getSystemReport(o)
	if err != nil {
		return nil, err
	}

	return res, nil
}

func getSystemReport(o *Options) (*rpb.ReportResponse, error) {

	res := &rpb.ReportResponse{}
	res.Clusters = map[string]*rpb.ClusterData{}

	reportData, err := getKubearmorReportData(Rcfg.CfgDB, o.options)
	if err != nil {
		return nil, err
	}

	for ck, cv := range reportData.Clusters {
		res.Clusters[ck] = &rpb.ClusterData{
			ClusterName: ck,
			Namespaces:  map[string]*rpb.NamespaceData{},
		}
		res.Clusters[ck].Namespaces = map[string]*rpb.NamespaceData{}
		for nk, nv := range cv.Namespaces {
			res.Clusters[cv.ClusterName].Namespaces[nk] = &rpb.NamespaceData{
				NamespaceName: nk,
				ResourceTypes: map[string]*rpb.ResourceTypeData{},
			}
			for rtk, rtv := range nv.ResourceTypesData {
				res.Clusters[cv.ClusterName].Namespaces[nv.NamespaceName].ResourceTypes[rtk] = &rpb.ResourceTypeData{
					ResourceType: rtk,
					Resources:    map[string]*rpb.ResourceData{},
				}
				for rsdk, rsdv := range rtv.ResourceSummaryData {
					res.Clusters[cv.ClusterName].Namespaces[nv.NamespaceName].ResourceTypes[rtk].Resources[rsdk] = &rpb.ResourceData{
						ResourceType: rsdv.ResourceType,
						ResourceName: rsdv.ResourceName,
						MetaData: &rpb.MetaData{
							Label:         rsdv.MetaData.Label,
							ContainerName: rsdv.MetaData.ContainerName,
						},
						SummaryData: &rpb.SummaryData{
							ProcessData:       []*opb.SysProcFileSummaryData{},
							FileData:          []*opb.SysProcFileSummaryData{},
							IngressConnection: []*opb.SysNwSummaryData{},
							EgressConnection:  []*opb.SysNwSummaryData{},
							BindConnection:    []*opb.SysNwSummaryData{},
						},
					}

					res.Clusters[cv.ClusterName].Namespaces[nv.NamespaceName].ResourceTypes[rtk].Resources[rsdk].SummaryData = &rpb.SummaryData{}

					for _, sd := range rsdv.SummaryData.ProcessData {
						res.Clusters[cv.ClusterName].Namespaces[nv.NamespaceName].ResourceTypes[rtk].Resources[rsdk].SummaryData.ProcessData = append(res.Clusters[cv.ClusterName].Namespaces[nv.NamespaceName].ResourceTypes[rtk].Resources[rsdk].SummaryData.ProcessData,
							&opb.SysProcFileSummaryData{
								Source:      sd.Source,
								Destination: sd.Destination,
								Status:      sd.Status,
							})
					}

					for _, sd := range rsdv.SummaryData.FileData {
						res.Clusters[cv.ClusterName].Namespaces[nv.NamespaceName].ResourceTypes[rtk].Resources[rsdk].SummaryData.FileData = append(res.Clusters[cv.ClusterName].Namespaces[nv.NamespaceName].ResourceTypes[rtk].Resources[rsdk].SummaryData.FileData,
							&opb.SysProcFileSummaryData{
								Source:      sd.Source,
								Destination: sd.Destination,
								Status:      sd.Status,
							})
					}
					for _, sd := range rsdv.SummaryData.NetworkData {
						if sd.NetType == "ingress" {
							res.Clusters[cv.ClusterName].Namespaces[nv.NamespaceName].ResourceTypes[rtk].Resources[rsdk].SummaryData.IngressConnection = append(res.Clusters[cv.ClusterName].Namespaces[nv.NamespaceName].ResourceTypes[rtk].Resources[rsdk].SummaryData.IngressConnection, &opb.SysNwSummaryData{
								Protocol:  sd.Protocol,
								Command:   sd.Command,
								IP:        sd.PodSvcIP,
								Port:      sd.ServerPort,
								Labels:    sd.Labels,
								Namespace: sd.Namespace,
							})
						} else if sd.NetType == "egress" {
							res.Clusters[cv.ClusterName].Namespaces[nv.NamespaceName].ResourceTypes[rtk].Resources[rsdk].SummaryData.EgressConnection = append(res.Clusters[cv.ClusterName].Namespaces[nv.NamespaceName].ResourceTypes[rtk].Resources[rsdk].SummaryData.EgressConnection, &opb.SysNwSummaryData{
								Protocol:  sd.Protocol,
								Command:   sd.Command,
								IP:        sd.PodSvcIP,
								Port:      sd.ServerPort,
								Labels:    sd.Labels,
								Namespace: sd.Namespace,
							})
						} else if sd.NetType == "bind" {
							res.Clusters[cv.ClusterName].Namespaces[nv.NamespaceName].ResourceTypes[rtk].Resources[rsdk].SummaryData.BindConnection = append(res.Clusters[cv.ClusterName].Namespaces[nv.NamespaceName].ResourceTypes[rtk].Resources[rsdk].SummaryData.
								BindConnection, &opb.SysNwSummaryData{
								Protocol:    sd.Protocol,
								Command:     sd.Command,
								IP:          sd.PodSvcIP,
								BindPort:    sd.BindPort,
								BindAddress: sd.BindAddress,
								Labels:      sd.Labels,
								Namespace:   sd.Namespace,
							})
						}
					}
				}
			}

		}
	}
	return res, nil
}

func getKubearmorReportData(CfgDB types.ConfigDB, reportOptions *types.ReportOptions) (*ReportData, error) {
	var err error
	//var processData, fileData []types.SysObsProcFileData
	//var nwData []types.SysObsNwData
	var reportSummaryData ReportData = ReportData{
		Clusters: map[string]Clusters{},
	}
	var sysSummary []types.SystemSummary
	var procMap map[string]string = map[string]string{}
	var fileMap map[string]string = map[string]string{}

	sysSummary, err = libs.GetSystemSummary(CfgDB, nil, reportOptions)

	if err != nil {
		return nil, err
	}

	for _, ss := range sysSummary {
		if ss.Workload.Type == "" || ss.Workload.Name == "" {
			continue
		}
		_, ok := reportSummaryData.Clusters[ss.ClusterName]
		if !ok {
			reportSummaryData.Clusters[ss.ClusterName] = Clusters{
				ClusterName: ss.ClusterName,
				Namespaces:  map[string]Namespaces{},
			}
		}
		_, ok = reportSummaryData.Clusters[ss.ClusterName].Namespaces[ss.NamespaceName]
		if !ok {
			reportSummaryData.Clusters[ss.ClusterName].Namespaces[ss.NamespaceName] = Namespaces{
				NamespaceName:     ss.NamespaceName,
				ResourceTypesData: map[string]ResourceTypeData{},
			}
		}
		// TODO: Add resource type and resource name in system_summary table and reference it here
		_, ok = reportSummaryData.Clusters[ss.ClusterName].Namespaces[ss.NamespaceName].ResourceTypesData[ss.Workload.Type]
		if !ok {
			reportSummaryData.Clusters[ss.ClusterName].Namespaces[ss.NamespaceName].ResourceTypesData[ss.Workload.Type] = ResourceTypeData{
				ResourceType:        ss.Workload.Type,
				ResourceSummaryData: map[string]ResourceData{},
			}
		}
		_, ok = reportSummaryData.Clusters[ss.ClusterName].Namespaces[ss.NamespaceName].ResourceTypesData[ss.Workload.Type].ResourceSummaryData[ss.Workload.Name]
		if !ok {
			reportSummaryData.Clusters[ss.ClusterName].Namespaces[ss.NamespaceName].ResourceTypesData[ss.Workload.Type].ResourceSummaryData[ss.Workload.Name] = ResourceData{
				ResourceType: ss.Workload.Type,
				ResourceName: ss.Workload.Name,
				MetaData: &types.MetaData{
					Label:         ss.Labels,
					ContainerName: ss.ContainerName,
				},
				SummaryData: &SummaryData{
					ProcessData: []types.SysObsProcFileData{},
					FileData:    []types.SysObsProcFileData{},
					NetworkData: []types.SysObsNwData{},
				},
			}
		}
		unq := ss.ClusterName + "_" + ss.NamespaceName + "_" + ss.Workload.Type + "_" + ss.Workload.Name

		//t := time.Unix(ss.UpdatedTime, 0)

		if ss.Operation == "Process" {

			_, sourceOk := procMap[unq+"_"+"source"]
			_, destOk := procMap[unq+"_"+"dest"]
			_, allowOk := procMap[unq+"_"+"action"]

			if sourceOk && destOk && allowOk {
				continue
			}
			//ExtractProcessData
			reportSummaryData.Clusters[ss.ClusterName].Namespaces[ss.NamespaceName].ResourceTypesData[ss.Workload.Type].ResourceSummaryData[ss.Workload.Name].SummaryData.ProcessData = append(reportSummaryData.Clusters[ss.ClusterName].Namespaces[ss.NamespaceName].ResourceTypesData[ss.Workload.Type].ResourceSummaryData[ss.Workload.Name].SummaryData.ProcessData, types.SysObsProcFileData{
				Source:      ss.Source,
				Destination: ss.Destination,
				Status:      ss.Action,
				//Count:       uint32(ss.Count),
				//: t.Format(time.UnixDate),
			})
			procMap[unq+"_"+"source"] = ss.Source
			procMap[unq+"_"+"dest"] = ss.Destination
			procMap[unq+"_"+"action"] = ss.Action

		} else if ss.Operation == "File" {
			_, sourceOk := fileMap[unq+"_"+"source"]
			_, destOk := fileMap[unq+"_"+"dest"]
			_, allowOk := fileMap[unq+"_"+"action"]

			if sourceOk && destOk && allowOk {
				continue
			}
			//ExtractFileData
			reportSummaryData.Clusters[ss.ClusterName].Namespaces[ss.NamespaceName].ResourceTypesData[ss.Workload.Type].ResourceSummaryData[ss.Workload.Name].SummaryData.FileData = append(reportSummaryData.Clusters[ss.ClusterName].Namespaces[ss.NamespaceName].ResourceTypesData[ss.Workload.Type].ResourceSummaryData[ss.Workload.Name].SummaryData.FileData, types.SysObsProcFileData{
				Source:      ss.Source,
				Destination: ss.Destination,
				Status:      ss.Action,
				//:       uint32(ss.Count),
				//UpdatedTime: t.Format(time.UnixDate),
			})
			fileMap[unq+"_"+"source"] = ss.Source
			fileMap[unq+"_"+"dest"] = ss.Destination
			fileMap[unq+"_"+"action"] = ss.Action
			reportSummaryData.Clusters[ss.ClusterName].Namespaces[ss.NamespaceName].ResourceTypesData[ss.Workload.Type].ResourceSummaryData[ss.Workload.Name].SummaryData.FileData = observability.AggregateProcFileData(reportSummaryData.Clusters[ss.ClusterName].Namespaces[ss.NamespaceName].ResourceTypesData[ss.Workload.Type].ResourceSummaryData[ss.Workload.Name].SummaryData.FileData)

		} else if ss.Operation == "Network" {
			//ExtractNwData
			reportSummaryData.Clusters[ss.ClusterName].Namespaces[ss.NamespaceName].ResourceTypesData[ss.Workload.Type].ResourceSummaryData[ss.Workload.Name].SummaryData.NetworkData = append(reportSummaryData.Clusters[ss.ClusterName].Namespaces[ss.NamespaceName].ResourceTypesData[ss.Workload.Type].ResourceSummaryData[ss.Workload.Name].SummaryData.NetworkData, types.SysObsNwData{
				NetType:     ss.NwType,
				Protocol:    ss.Protocol,
				Command:     ss.Source,
				PodSvcIP:    ss.IP,
				ServerPort:  strconv.Itoa(int(ss.Port)),
				BindPort:    ss.BindPort,
				BindAddress: ss.BindAddress,
				Namespace:   ss.DestNamespace,
				Labels:      ss.DestLabels,
				//Count:       uint32(ss.Count),
				//UpdatedTime: t.Format(time.UnixDate),
			})

		}

	}

	return &reportSummaryData, nil

}
