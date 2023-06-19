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
						MData: &rpb.MetaData{
							Label:         rsdv.MetaData.Label,
							ContainerName: rsdv.MetaData.ContainerName,
						},
						SumData: &rpb.SummaryData{
							ProcessData:       []*opb.SysProcFileSummaryData{},
							FileData:          []*opb.SysProcFileSummaryData{},
							IngressConnection: []*opb.SysNwSummaryData{},
							EgressConnection:  []*opb.SysNwSummaryData{},
							BindConnection:    []*opb.SysNwSummaryData{},
						},
					}

					res.Clusters[cv.ClusterName].Namespaces[nv.NamespaceName].ResourceTypes[rtk].Resources[rsdk].SumData = &rpb.SummaryData{}

					for _, sd := range rsdv.SummaryData.ProcessData {
						res.Clusters[cv.ClusterName].Namespaces[nv.NamespaceName].ResourceTypes[rtk].Resources[rsdk].SumData.ProcessData = append(res.Clusters[cv.ClusterName].Namespaces[nv.NamespaceName].ResourceTypes[rtk].Resources[rsdk].SumData.ProcessData,
							&opb.SysProcFileSummaryData{
								Source:      sd.Source,
								Destination: sd.Destination,
								Status:      sd.Status,
							})
					}

					for _, sd := range rsdv.SummaryData.FileData {
						res.Clusters[cv.ClusterName].Namespaces[nv.NamespaceName].ResourceTypes[rtk].Resources[rsdk].SumData.FileData = append(res.Clusters[cv.ClusterName].Namespaces[nv.NamespaceName].ResourceTypes[rtk].Resources[rsdk].SumData.FileData,
							&opb.SysProcFileSummaryData{
								Source:      sd.Source,
								Destination: sd.Destination,
								Status:      sd.Status,
							})
					}
					for _, sd := range rsdv.SummaryData.NetworkData {
						if sd.NetType == "ingress" {
							res.Clusters[cv.ClusterName].Namespaces[nv.NamespaceName].ResourceTypes[rtk].Resources[rsdk].SumData.IngressConnection = append(res.Clusters[cv.ClusterName].Namespaces[nv.NamespaceName].ResourceTypes[rtk].Resources[rsdk].SumData.IngressConnection, &opb.SysNwSummaryData{
								Protocol:  sd.Protocol,
								Command:   sd.Command,
								IP:        sd.PodSvcIP,
								Port:      sd.ServerPort,
								Labels:    sd.Labels,
								Namespace: sd.Namespace,
							})
						} else if sd.NetType == "egress" {
							res.Clusters[cv.ClusterName].Namespaces[nv.NamespaceName].ResourceTypes[rtk].Resources[rsdk].SumData.EgressConnection = append(res.Clusters[cv.ClusterName].Namespaces[nv.NamespaceName].ResourceTypes[rtk].Resources[rsdk].SumData.EgressConnection, &opb.SysNwSummaryData{
								Protocol:  sd.Protocol,
								Command:   sd.Command,
								IP:        sd.PodSvcIP,
								Port:      sd.ServerPort,
								Labels:    sd.Labels,
								Namespace: sd.Namespace,
							})
						} else if sd.NetType == "bind" {
							res.Clusters[cv.ClusterName].Namespaces[nv.NamespaceName].ResourceTypes[rtk].Resources[rsdk].SumData.BindConnection = append(res.Clusters[cv.ClusterName].Namespaces[nv.NamespaceName].ResourceTypes[rtk].Resources[rsdk].SumData.
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
	var processData, fileData []types.SysObsProcFileData
	var nwData []types.SysObsNwData
	var reportSummaryData ReportData = ReportData{
		Clusters: map[string]Clusters{},
	}
	var sysSummary []types.SystemSummary

	sysSummary, err = libs.GetSystemSummary(CfgDB, nil, reportOptions)

	if err != nil {
		return nil, err
	}

	for _, ss := range sysSummary {

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
		_, ok = reportSummaryData.Clusters[ss.ClusterName].Namespaces[ss.NamespaceName].ResourceTypesData["Deployment"]
		if !ok {
			reportSummaryData.Clusters[ss.ClusterName].Namespaces[ss.NamespaceName].ResourceTypesData["Deployment"] = ResourceTypeData{
				ResourceType:        "Deployment",
				ResourceSummaryData: map[string]ResourceData{},
			}
		}
		_, ok = reportSummaryData.Clusters[ss.ClusterName].Namespaces[ss.NamespaceName].ResourceTypesData["Deployment"].ResourceSummaryData[ss.Deployment]
		if !ok {
			reportSummaryData.Clusters[ss.ClusterName].Namespaces[ss.NamespaceName].ResourceTypesData["Deployment"].ResourceSummaryData[ss.Deployment] = ResourceData{
				ResourceType: "Deployment",
				ResourceName: ss.Deployment,
				MetaData: &types.MetaData{
					Label:         ss.Labels,
					ContainerName: ss.ContainerName,
				},
				SummaryData: &SummaryData{
					ProcessData: processData,
					FileData:    fileData,
					NetworkData: nwData,
				},
			}
		}

		//t := time.Unix(ss.UpdatedTime, 0)

		if ss.Operation == "Process" {
			//ExtractProcessData
			processData = append(processData, types.SysObsProcFileData{
				Source:      ss.Source,
				Destination: ss.Destination,
				Status:      ss.Action,
				//Count:       uint32(ss.Count),
				//: t.Format(time.UnixDate),
			})
		} else if ss.Operation == "File" {
			//ExtractFileData
			fileData = append(fileData, types.SysObsProcFileData{
				Source:      ss.Source,
				Destination: ss.Destination,
				Status:      ss.Action,
				//:       uint32(ss.Count),
				//UpdatedTime: t.Format(time.UnixDate),
			})
		} else if ss.Operation == "Network" {
			//ExtractNwData
			nwData = append(nwData, types.SysObsNwData{
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

		reportSummaryData.Clusters[ss.ClusterName].Namespaces[ss.NamespaceName].ResourceTypesData["Deployment"].ResourceSummaryData[ss.Deployment].SummaryData.ProcessData = processData
		reportSummaryData.Clusters[ss.ClusterName].Namespaces[ss.NamespaceName].ResourceTypesData["Deployment"].ResourceSummaryData[ss.Deployment].SummaryData.FileData = observability.AggregateProcFileData(fileData)
		reportSummaryData.Clusters[ss.ClusterName].Namespaces[ss.NamespaceName].ResourceTypesData["Deployment"].ResourceSummaryData[ss.Deployment].SummaryData.NetworkData = nwData
	}

	return &reportSummaryData, nil

}
