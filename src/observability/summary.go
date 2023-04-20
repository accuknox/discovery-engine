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

	if strings.Contains(request.Type, "process") || strings.Contains(request.Type, "file") || strings.Contains(request.Type, "network") {

		proc, file, nw, podInfo := GetKubearmorSummaryData(request)

		if len(proc) <= 0 && len(file) <= 0 && len(nw) <= 0 {
			return nil, errors.New("no system summary info present for the requested pod name")
		}

		procResp := []*opb.SysProcFileSummaryData{}
		fileResp := []*opb.SysProcFileSummaryData{}
		inNwResp := []*opb.SysNwSummaryData{}
		outNwResp := []*opb.SysNwSummaryData{}
		bindNwResp := []*opb.SysNwSummaryData{}

		resp.DeploymentName = podInfo.DeployName
		resp.PodName = podInfo.PodName
		resp.ClusterName = podInfo.ClusterName
		resp.Namespace = podInfo.Namespace
		resp.Label = podInfo.Labels
		resp.ContainerName = podInfo.ContainerName

		if len(proc) > 0 && strings.Contains(request.Type, "process") {
			for _, loc_proc := range proc {
				procResp = append(procResp, &opb.SysProcFileSummaryData{
					Source:      loc_proc.Source,
					Destination: loc_proc.Destination,
					Count:       strconv.Itoa(int(loc_proc.Count)),
					Status:      loc_proc.Status,
					UpdatedTime: loc_proc.UpdatedTime,
				})
			}
		}

		if len(file) > 0 && strings.Contains(request.Type, "file") {
			for _, loc_file := range file {
				fileResp = append(fileResp, &opb.SysProcFileSummaryData{
					Source:      loc_file.Source,
					Destination: loc_file.Destination,
					Count:       strconv.Itoa(int(loc_file.Count)),
					Status:      loc_file.Status,
					UpdatedTime: loc_file.UpdatedTime,
				})
			}
		}

		if len(nw) > 0 && strings.Contains(request.Type, "network") {
			for _, loc_nw := range nw {
				if loc_nw.NetType == "ingress" {
					inNwResp = append(inNwResp, &opb.SysNwSummaryData{
						Protocol:    loc_nw.Protocol,
						Command:     loc_nw.Command,
						IP:          loc_nw.PodSvcIP,
						Port:        loc_nw.ServerPort,
						Labels:      loc_nw.Labels,
						Namespace:   loc_nw.Namespace,
						Count:       strconv.Itoa(int(loc_nw.Count)),
						UpdatedTime: loc_nw.UpdatedTime,
					})
				} else if loc_nw.NetType == "egress" {
					outNwResp = append(outNwResp, &opb.SysNwSummaryData{
						Protocol:    loc_nw.Protocol,
						Command:     loc_nw.Command,
						IP:          loc_nw.PodSvcIP,
						Port:        loc_nw.ServerPort,
						Labels:      loc_nw.Labels,
						Namespace:   loc_nw.Namespace,
						Count:       strconv.Itoa(int(loc_nw.Count)),
						UpdatedTime: loc_nw.UpdatedTime,
					})
				} else if loc_nw.NetType == "bind" {
					bindNwResp = append(bindNwResp, &opb.SysNwSummaryData{
						Protocol:    loc_nw.Protocol,
						Command:     loc_nw.Command,
						IP:          loc_nw.PodSvcIP,
						BindPort:    loc_nw.BindPort,
						BindAddress: loc_nw.BindAddress,
						Labels:      loc_nw.Labels,
						Namespace:   loc_nw.Namespace,
						Count:       strconv.Itoa(int(loc_nw.Count)),
						UpdatedTime: loc_nw.UpdatedTime,
					})
				}
			}
		}
		resp.ProcessData = procResp
		resp.FileData = fileResp
		resp.IngressConnection = inNwResp
		resp.EgressConnection = outNwResp
		resp.BindConnection = bindNwResp
	}

	if strings.Contains(request.Type, "ingress") || strings.Contains(request.Type, "egress") {

		ingressData, egressData, podInfo := GetCiliumSummaryData(request)

		if len(ingressData) <= 0 && len(egressData) <= 0 && request.Type == "network" {
			return nil, errors.New("no ingress/egress summary info present for the requested pod")
		}

		ingressSummData := []*opb.CiliumSummData{}
		egressSummData := []*opb.CiliumSummData{}

		if len(ingressData) > 0 && strings.Contains(request.Type, "ingress") {
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

		if len(egressData) > 0 && strings.Contains(request.Type, "egress") {
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

func GetSummaryDataPerDeploy(request *opb.Request) (*opb.Response, error) {
	resp := opb.Response{}
	var err error = nil

	podResp, err := GetPodNames(&opb.Request{DeployName: request.DeployName})
	if err != nil {
		return nil, errors.New("no system summary info present for the requested deployment")
	}
	var podNames []string
	for _, pod := range podResp.PodName {
		request.PodName = pod
		podDataResp, err := GetSummaryData(request)
		if err != nil {
			return nil, errors.New("no system summary info present for the requested pod")
		}
		resp.IngressData = append(resp.IngressData, podDataResp.IngressData...)
		resp.EgressData = append(resp.EgressData, podDataResp.EgressData...)
		resp.ProcessData = append(resp.ProcessData, podDataResp.ProcessData...)
		resp.FileData = append(resp.FileData, podDataResp.FileData...)
		resp.IngressConnection = append(resp.IngressConnection, podDataResp.IngressConnection...)
		resp.EgressConnection = append(resp.EgressConnection, podDataResp.EgressConnection...)
		resp.BindConnection = append(resp.BindConnection, podDataResp.BindConnection...)
		resp.DeploymentName = podDataResp.DeploymentName
		resp.ClusterName = podDataResp.ClusterName
		resp.Namespace = podDataResp.Namespace
		resp.Label = podDataResp.Label
		resp.ContainerName = podDataResp.ContainerName
		podNames = append(podNames, pod)
	}
	resp.PodName = strings.Join(podNames, ",")
	return &resp, err
}
