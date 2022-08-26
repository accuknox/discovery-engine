package observability

import (
	"errors"
	"strconv"

	opb "github.com/accuknox/auto-policy-discovery/src/protobuf/v1/observability"
)

func GetSummaryData(request *opb.Request) (*opb.Response, error) {
	resp := opb.Response{}
	var err error = nil

	if request.Type == "system" || request.Type == "all" {
		proc, file, nw, podInfo := GetKubearmorSummaryData(request)

		if len(proc) <= 0 && len(file) <= 0 && len(nw) <= 0 {
			return nil, errors.New("no system summary info present for the requested pod")
		}

		procResp := []*opb.SysProcFileSummaryData{}
		fileResp := []*opb.SysProcFileSummaryData{}
		inNwResp := []*opb.SysNwSummaryData{}
		outNwResp := []*opb.SysNwSummaryData{}

		resp.PodName = podInfo.PodName
		resp.ClusterName = podInfo.ClusterName
		resp.Namespace = podInfo.Namespace
		resp.Label = podInfo.Labels
		resp.ContainerName = podInfo.ContainerName

		if len(proc) > 0 {
			for _, loc_proc := range proc {
				procResp = append(procResp, &opb.SysProcFileSummaryData{
					ParentProcName: loc_proc.ParentProcName,
					ProcName:       loc_proc.ProcName,
					Count:          strconv.Itoa(int(loc_proc.Count)),
					Status:         loc_proc.Status,
					UpdatedTime:    loc_proc.UpdatedTime,
				})
			}
		}

		if len(file) > 0 {
			for _, loc_file := range file {
				fileResp = append(fileResp, &opb.SysProcFileSummaryData{
					ParentProcName: loc_file.ParentProcName,
					ProcName:       loc_file.ProcName,
					Count:          strconv.Itoa(int(loc_file.Count)),
					Status:         loc_file.Status,
					UpdatedTime:    loc_file.UpdatedTime,
				})
			}
		}

		if len(nw) > 0 {
			for _, loc_nw := range nw {
				if loc_nw.InOut == "IN" {
					inNwResp = append(inNwResp, &opb.SysNwSummaryData{
						Protocol:  loc_nw.Protocol,
						Command:   loc_nw.Command,
						IP:        loc_nw.PodSvcIP,
						Port:      loc_nw.ServerPort,
						Labels:    loc_nw.Labels,
						Namespace: loc_nw.Namespace,
					})
				} else if loc_nw.InOut == "OUT" {
					outNwResp = append(outNwResp, &opb.SysNwSummaryData{
						Protocol:  loc_nw.Protocol,
						Command:   loc_nw.Command,
						IP:        loc_nw.PodSvcIP,
						Port:      loc_nw.ServerPort,
						Labels:    loc_nw.Labels,
						Namespace: loc_nw.Namespace,
					})
				}
			}
		}
		resp.ProcessData = procResp
		resp.FileData = fileResp
		resp.InNwData = inNwResp
		resp.OutNwData = outNwResp
	}

	if request.Type == "network" || request.Type == "all" {
		nwSummaryData, podInfo := GetCiliumSummaryData(request)

		if len(nwSummaryData) <= 0 && request.Type == "network" {
			return nil, errors.New("no ingress/egress summary info present for the requested pod")
		}

		ingressEgressSummData := []*opb.CiliumSummData{}

		for _, locNwSummData := range nwSummaryData {
			ingressEgressSummData = append(ingressEgressSummData, &opb.CiliumSummData{
				SrcDestPod:  locNwSummData.SrcDestPod,
				Protocol:    locNwSummData.Protocol,
				Port:        locNwSummData.Port,
				Count:       locNwSummData.Count,
				Status:      locNwSummData.Status,
				UpdatedTime: locNwSummData.UpdatedTime,
			})
		}

		if request.Type == "network" {
			resp.PodName = podInfo.PodName
			resp.Namespace = podInfo.Namespace
			resp.Label = podInfo.Labels
			resp.IngressEgressData = ingressEgressSummData
		}
	}

	return &resp, err
}
