package observability

import (
	"errors"
	"strconv"
	"strings"

	opb "github.com/accuknox/auto-policy-discovery/src/protobuf/v1/observability"
)

func GetSummaryData(request *opb.Request) (*opb.Response, error) {
	resp := opb.Response{}
	var err error = nil

	if strings.Contains(request.Type, "process") || strings.Contains(request.Type, "file") ||
		strings.Contains(request.Type, "network") || strings.Contains(request.Type, "all") {
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

		if len(proc) > 0 && (strings.Contains(request.Type, "process") || strings.Contains(request.Type, "all")) {
			for _, loc_proc := range proc {
				procResp = append(procResp, &opb.SysProcFileSummaryData{
					ParentProcName: loc_proc.Source,
					ProcName:       loc_proc.Destination,
					Count:          strconv.Itoa(int(loc_proc.Count)),
					Status:         loc_proc.Status,
					UpdatedTime:    loc_proc.UpdatedTime,
				})
			}
		}

		if len(file) > 0 && (strings.Contains(request.Type, "file") || strings.Contains(request.Type, "all")) {
			for _, loc_file := range file {
				fileResp = append(fileResp, &opb.SysProcFileSummaryData{
					ParentProcName: loc_file.Source,
					ProcName:       loc_file.Destination,
					Count:          strconv.Itoa(int(loc_file.Count)),
					Status:         loc_file.Status,
					UpdatedTime:    loc_file.UpdatedTime,
				})
			}
		}

		if len(nw) > 0 && (strings.Contains(request.Type, "network") || strings.Contains(request.Type, "all")) {
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

	if strings.Contains(request.Type, "ingress") || strings.Contains(request.Type, "egress") || strings.Contains(request.Type, "all") {
		ingressData, egressData, podInfo := GetCiliumSummaryData(request)

		if len(ingressData) <= 0 && len(egressData) <= 0 && request.Type == "network" {
			return nil, errors.New("no ingress/egress summary info present for the requested pod")
		}

		ingressSummData := []*opb.CiliumSummData{}
		egressSummData := []*opb.CiliumSummData{}

		if len(ingressData) > 0 && (strings.Contains(request.Type, "ingress") || strings.Contains(request.Type, "all")) {
			for _, locIngressData := range ingressData {
				ingressSummData = append(ingressSummData, &opb.CiliumSummData{
					Protocol:    locIngressData.Protocol,
					Port:        locIngressData.Port,
					Count:       locIngressData.Count,
					Status:      locIngressData.Status,
					UpdatedTime: locIngressData.UpdatedTime,
				})
			}
		}

		if len(egressData) > 0 && (strings.Contains(request.Type, "egress") || strings.Contains(request.Type, "all")) {
			for _, locIngressData := range ingressData {
				egressSummData = append(egressSummData, &opb.CiliumSummData{
					Protocol:    locIngressData.Protocol,
					Port:        locIngressData.Port,
					Count:       locIngressData.Count,
					Status:      locIngressData.Status,
					UpdatedTime: locIngressData.UpdatedTime,
				})
			}
		}

		if request.Type == "network" {
			resp.PodName = podInfo.PodName
			resp.Namespace = podInfo.Namespace
			resp.Label = podInfo.Labels
		}
		resp.IngressData = ingressSummData
		resp.EgressData = egressSummData
	}

	return &resp, err
}
