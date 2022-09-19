package insight

import (
	ipb "github.com/accuknox/auto-policy-discovery/src/protobuf/v1/insight"
	types "github.com/accuknox/auto-policy-discovery/src/types"
)

func populateAggregatedResp(sysInsightData []ipb.SystemInsightData, netInsightData []ipb.NetworkInsightData) (ipb.Response, error) {
	var response ipb.Response

	for index, sysdata := range sysInsightData {
		if index == 0 {
			sysresp := ConvertSysInsDataToInsResponse(sysdata)
			response.Res = append(response.Res, &sysresp)
		} else {
			idx := 0
			for locindex := range response.Res {
				if response.Res[locindex].ClusterName == sysdata.ClusterName && response.Res[locindex].NameSpace == sysdata.Namespace && response.Res[locindex].Labels == sysdata.Labels {
					response.Res[locindex].SystemResource = append(response.Res[locindex].SystemResource, &ipb.SystemInsightData{
						ContainerName: sysdata.ContainerName,
						SysResource:   sysdata.SysResource})
					break
				} else {
					idx++
				}
			}
			if idx == len(response.Res) {
				sysresp := ConvertSysInsDataToInsResponse(sysdata)
				response.Res = append(response.Res, &sysresp)
			}
		}
	}

	for _, netdata := range netInsightData {
		idx := 0
		for index := range response.Res {
			if response.Res[index].ClusterName == netdata.ClusterName && response.Res[index].NameSpace == netdata.Namespace && response.Res[index].Labels == netdata.Labels {
				response.Res[index].NetworkResource = append(response.Res[index].NetworkResource, &ipb.NetworkInsightData{
					Type:        netdata.Type,
					Rule:        netdata.Rule,
					NetResource: netdata.NetResource})
				break
			} else {
				idx++
			}
		}
		if idx == len(response.Res) {
			netresp := ConvertNetInsDataToInsResponse(netdata)
			response.Res = append(response.Res, &netresp)
		}
	}

	return response, nil
}

func getAllInsightData(req types.InsightRequest) (ipb.Response, error) {

	sysData, err := GetSysInsightData(req)
	if err != nil {
		return ipb.Response{}, err
	}

	netData, err := GetNetInsightData(req)
	if err != nil {
		return ipb.Response{}, err
	}

	insightResponse, err := populateAggregatedResp(sysData, netData)

	return insightResponse, err
}

func GetInsightData(req types.InsightRequest) (ipb.Response, error) {

	if req.Source == "system" {
		resp, err := GetSystemInsightData(req)
		return resp, err
	} else if req.Source == "network" {
		resp, err := GetNetworkInsightData(req)
		return resp, err
	} else if req.Source == "all" {
		resp, err := getAllInsightData(req)
		return resp, err
	}

	return ipb.Response{}, nil
}
