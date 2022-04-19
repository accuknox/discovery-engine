package insight

import (
	"errors"

	"github.com/accuknox/auto-policy-discovery/src/libs"
	network "github.com/accuknox/auto-policy-discovery/src/networkpolicy"
	ipb "github.com/accuknox/auto-policy-discovery/src/protobuf/v1/insight"
	types "github.com/accuknox/auto-policy-discovery/src/types"
)

func ClearNetworkDB() {
	libs.ClearNetworkDBTable(network.CfgDB)
}

func ConvertNetInsDataToInsResponse(netdata ipb.NetworkInsightData) ipb.InsightResponse {
	var locnetinsdata ipb.NetworkInsightData
	var insresp ipb.InsightResponse

	locnetinsdata.Type = netdata.Type
	locnetinsdata.Rule = netdata.Rule
	locnetinsdata.NetResource = netdata.NetResource

	insresp.ClusterName = netdata.ClusterName
	insresp.NameSpace = netdata.Namespace
	insresp.Labels = netdata.Labels
	insresp.NetworkResource = append(insresp.NetworkResource, &locnetinsdata)

	return ipb.InsightResponse{
		ClusterName:     insresp.ClusterName,
		NameSpace:       insresp.NameSpace,
		Labels:          insresp.Labels,
		NetworkResource: insresp.NetworkResource,
	}
}

func aggregateNetInsightData(networkData []ipb.NetworkInsightData) []ipb.NetworkInsightData {

	var net []ipb.NetworkInsightData

	for index, nwpolicy := range networkData {
		if index == 0 {
			net = append(net, ipb.NetworkInsightData{
				ClusterName: nwpolicy.ClusterName,
				Namespace:   nwpolicy.Namespace,
				Labels:      nwpolicy.Labels,
				Type:        nwpolicy.Type,
				Rule:        nwpolicy.Rule,
				NetResource: nwpolicy.NetResource,
			})
		} else {
			locIdx := 0
			for _, nwdata := range net {
				if nwdata.ClusterName == nwpolicy.ClusterName && nwdata.Namespace == nwpolicy.Namespace &&
					nwdata.Rule == nwpolicy.Rule && nwdata.Type == nwpolicy.Type && nwdata.Labels == nwpolicy.Labels {
					nwdata.NetResource = append(nwdata.NetResource, nwpolicy.NetResource...)
					break
				} else {
					locIdx++
				}
			}
			if locIdx == len(net) {
				net = append(net, ipb.NetworkInsightData{
					ClusterName: nwpolicy.ClusterName,
					Namespace:   nwpolicy.Namespace,
					Labels:      nwpolicy.Labels,
					Type:        nwpolicy.Type,
					Rule:        nwpolicy.Rule,
					NetResource: nwpolicy.NetResource,
				})
			}
		}
	}

	return net
}

func populateNwInsightData(policy types.KnoxNetworkPolicy) ipb.NetworkData {

	pbEgresses := []*ipb.Egress{}
	pbIngressess := []*ipb.Ingress{}
	pbNetSpec := &ipb.NetworkData{}

	// Spec
	for k, v := range policy.Spec.Selector.MatchLabels {
		pbNetSpec.Labels = k + "=" + v
	}

	// Spec Egress
	for _, egress := range policy.Spec.Egress {
		pbEgress := ipb.Egress{}
		pbEgress.MatchLabels = egress.MatchLabels
		pbToPorts := []*ipb.SpecPort{}
		pbToCIDRs := []*ipb.SpecCIDR{}
		pbToServices := []*ipb.SpecService{}
		pbToFQDNs := []*ipb.SpecFQDN{}
		pbToHTTPs := []*ipb.SpecHTTP{}

		for _, toPort := range egress.ToPorts {
			pbToPort := ipb.SpecPort{}
			pbToPort.Port = toPort.Port
			pbToPort.Protocol = toPort.Protocol
			pbToPorts = append(pbToPorts, &pbToPort)
		}

		for _, toCIDR := range egress.ToCIDRs {
			pbToCIDR := ipb.SpecCIDR{}
			pbToCIDR.CIDRs = append(pbToCIDR.CIDRs, toCIDR.CIDRs...)
			pbToCIDR.Except = append(pbToCIDR.Except, toCIDR.Except...)
			pbToCIDRs = append(pbToCIDRs, &pbToCIDR)
		}

		pbEgress.ToEndtities = append(pbEgress.ToEndtities, egress.ToEntities...)

		for _, toService := range egress.ToServices {
			pbToService := ipb.SpecService{}
			pbToService.Namespace = toService.Namespace
			pbToService.ServiceName = toService.ServiceName
			pbToServices = append(pbToServices, &pbToService)
		}

		for _, toFQDN := range egress.ToFQDNs {
			pbToFQDN := ipb.SpecFQDN{}
			pbToFQDN.MatchNames = append(pbToFQDN.MatchNames, toFQDN.MatchNames...)
			pbToFQDNs = append(pbToFQDNs, &pbToFQDN)
		}

		for _, toHTTP := range egress.ToHTTPs {
			pbToHttp := ipb.SpecHTTP{}
			pbToHttp.Path = toHTTP.Path
			pbToHttp.Method = toHTTP.Method
			pbToHttp.Aggregated = toHTTP.Aggregated
			pbToHTTPs = append(pbToHTTPs, &pbToHttp)
		}

		pbEgress.ToPorts = pbToPorts
		pbEgress.ToCIDRs = pbToCIDRs
		pbEgress.ToServices = pbToServices
		pbEgress.ToFQDNs = pbToFQDNs
		pbEgress.ToHTTPs = pbToHTTPs
		pbEgresses = append(pbEgresses, &pbEgress)
	}

	// Spec Ingress
	for _, ingress := range policy.Spec.Ingress {
		pbIngress := ipb.Ingress{}
		pbToPorts := []*ipb.SpecPort{}
		pbToHTTPs := []*ipb.SpecHTTP{}
		pbFromCIDRs := []*ipb.SpecCIDR{}

		pbIngress.MatchLabels = ingress.MatchLabels
		pbIngress.FromEntities = append(pbIngress.FromEntities, ingress.FromEntities...)

		for _, toPort := range ingress.ToPorts {
			pbToPort := ipb.SpecPort{}
			pbToPort.Port = toPort.Port
			pbToPort.Protocol = toPort.Protocol
			pbToPorts = append(pbToPorts, &pbToPort)
		}

		for _, toHTTP := range ingress.ToHTTPs {
			pbToHttp := ipb.SpecHTTP{}
			pbToHttp.Path = toHTTP.Path
			pbToHttp.Method = toHTTP.Method
			pbToHttp.Aggregated = toHTTP.Aggregated
			pbToHTTPs = append(pbToHTTPs, &pbToHttp)
		}

		for _, fromCIDR := range ingress.FromCIDRs {
			pbFromCIDR := ipb.SpecCIDR{}
			pbFromCIDR.CIDRs = append(pbFromCIDR.CIDRs, fromCIDR.CIDRs...)
			pbFromCIDR.Except = append(pbFromCIDR.Except, fromCIDR.Except...)
			pbFromCIDRs = append(pbFromCIDRs, &pbFromCIDR)
		}

		pbIngress.FromEntities = append(pbIngress.FromEntities, ingress.FromEntities...)

		pbIngress.ToPorts = pbToPorts
		pbIngress.ToHTTPs = pbToHTTPs
		pbIngress.FromCIDRs = pbFromCIDRs
		pbIngressess = append(pbIngressess, &pbIngress)
	}

	pbNetSpec.Egressess = pbEgresses
	pbNetSpec.Ingressess = pbIngressess

	return *pbNetSpec
}

func GetNetInsightData(req types.InsightRequest) ([]ipb.NetworkInsightData, error) {

	var networkData []ipb.NetworkInsightData

	nwpolicies := libs.GetNetworkPolicies(network.CfgDB, req.ClusterName, req.Namespace, "latest", req.Type, req.Rule)

	for _, nwpolicy := range nwpolicies {

		var locRes ipb.NetworkInsightData

		nwPbSpec := populateNwInsightData(nwpolicy)

		locRes.ClusterName = nwpolicy.Metadata["cluster_name"]
		locRes.Namespace = nwpolicy.Metadata["namespace"]
		locRes.Type = nwpolicy.Metadata["type"]
		locRes.Rule = nwpolicy.Metadata["rule"]
		locRes.Labels = nwPbSpec.Labels
		nwPbSpec.Labels = ""
		locRes.NetResource = append(locRes.NetResource, &nwPbSpec)

		if (req.Labels == "") || (req.Labels != "" && locRes.Labels == req.Labels) {
			networkData = append(networkData, ipb.NetworkInsightData{
				ClusterName: locRes.ClusterName,
				Namespace:   locRes.Namespace,
				Labels:      locRes.Labels,
				Type:        locRes.Type,
				Rule:        locRes.Rule,
				NetResource: locRes.NetResource,
			})
		}
	}

	newNetData := aggregateNetInsightData(networkData)

	return newNetData, nil
}

func getNetworkData(request types.InsightRequest) ([]ipb.NetworkInsightData, error) {

	if request.Request == "dbclear" {
		ClearNetworkDB()
		return nil, nil
	} else if request.Request == "observe" {
		nwdata, err := GetNetInsightData(request)
		return nwdata, err
	}

	return nil, errors.New("not a valid request, use observe/dbclear")
}

func GetNetworkInsightData(req types.InsightRequest) (ipb.Response, error) {
	var resp ipb.Response

	netData, err := getNetworkData(req)

	if req.Request != "observe" || netData == nil || len(netData) == 0 {
		return resp, err
	}

	locInsightNetResp := ipb.InsightResponse{}
	idx := 0
	for idx < len(netData) {
		locInsightNetResp.NetworkResource = append(locInsightNetResp.NetworkResource, &netData[idx])
		idx++
	}

	resp.Res = append(resp.Res, &locInsightNetResp)
	return resp, nil
}
