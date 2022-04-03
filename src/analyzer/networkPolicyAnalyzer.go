package analyzer

import (
	netpolicy "github.com/accuknox/auto-policy-discovery/src/networkpolicy"
	apb "github.com/accuknox/auto-policy-discovery/src/protobuf/v1/analyzer"
	types "github.com/accuknox/auto-policy-discovery/src/types"
)

func populatePbNetPolicyFromNetPolicy(KnoxNwPolicy types.KnoxNetworkPolicy) apb.KnoxNetworkPolicy {
	pbNwPolicy := apb.KnoxNetworkPolicy{}
	pbEgresses := []*apb.Egress{}
	pbIngressess := []*apb.Ingress{}
	pbNetSpec := &apb.KnoxNetworkSpec{}
	pbNetSelector := &apb.Selector{}

	pbNwPolicy.APIVersion = KnoxNwPolicy.APIVersion
	pbNwPolicy.Kind = KnoxNwPolicy.Kind

	// FlowIDs
	for _, flowId := range KnoxNwPolicy.FlowIDs {
		pbNwPolicy.FlowIDs = append(pbNwPolicy.FlowIDs, int32(flowId))
	}

	pbNwPolicy.Metadata = KnoxNwPolicy.Metadata
	pbNwPolicy.Outdated = KnoxNwPolicy.Outdated

	// Spec
	pbNetSelector.MatchLabels = KnoxNwPolicy.Spec.Selector.MatchLabels
	pbNetSpec.NetworkSelector = pbNetSelector

	// Spec Egress
	for _, egress := range KnoxNwPolicy.Spec.Egress {
		pbEgress := apb.Egress{}
		pbEgress.MatchLabels = egress.MatchLabels
		pbToPorts := []*apb.SpecPort{}
		pbToCIDRs := []*apb.SpecCIDR{}
		pbToServices := []*apb.SpecService{}
		pbToFQDNs := []*apb.SpecFQDN{}
		pbToHTTPs := []*apb.SpecHTTP{}

		for _, toPort := range egress.ToPorts {
			pbToPort := apb.SpecPort{}
			pbToPort.Port = toPort.Port
			pbToPort.Protocol = toPort.Protocol
			pbToPorts = append(pbToPorts, &pbToPort)
		}

		for _, toCIDR := range egress.ToCIDRs {
			pbToCIDR := apb.SpecCIDR{}
			pbToCIDR.CIDRs = append(pbToCIDR.CIDRs, toCIDR.CIDRs...)
			pbToCIDR.Except = append(pbToCIDR.Except, toCIDR.Except...)
			pbToCIDRs = append(pbToCIDRs, &pbToCIDR)
		}

		pbEgress.ToEndtities = append(pbEgress.ToEndtities, egress.ToEndtities...)

		for _, toService := range egress.ToServices {
			pbToService := apb.SpecService{}
			pbToService.Namespace = toService.Namespace
			pbToService.ServiceName = toService.ServiceName
			pbToServices = append(pbToServices, &pbToService)
		}

		for _, toFQDN := range egress.ToFQDNs {
			pbToFQDN := apb.SpecFQDN{}
			pbToFQDN.MatchNames = append(pbToFQDN.MatchNames, toFQDN.MatchNames...)
			pbToFQDNs = append(pbToFQDNs, &pbToFQDN)
		}

		for _, toHTTP := range egress.ToHTTPs {
			pbToHttp := apb.SpecHTTP{}
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
	for _, ingress := range KnoxNwPolicy.Spec.Ingress {
		pbIngress := apb.Ingress{}
		pbToPorts := []*apb.SpecPort{}
		pbToHTTPs := []*apb.SpecHTTP{}
		pbFromCIDRs := []*apb.SpecCIDR{}

		pbIngress.MatchLabels = ingress.MatchLabels
		pbIngress.FromEntities = append(pbIngress.FromEntities, ingress.FromEntities...)

		for _, toPort := range ingress.ToPorts {
			pbToPort := apb.SpecPort{}
			pbToPort.Port = toPort.Port
			pbToPort.Protocol = toPort.Protocol
			pbToPorts = append(pbToPorts, &pbToPort)
		}

		for _, toHTTP := range ingress.ToHTTPs {
			pbToHttp := apb.SpecHTTP{}
			pbToHttp.Path = toHTTP.Path
			pbToHttp.Method = toHTTP.Method
			pbToHttp.Aggregated = toHTTP.Aggregated
			pbToHTTPs = append(pbToHTTPs, &pbToHttp)
		}

		for _, fromCIDR := range ingress.FromCIDRs {
			pbFromCIDR := apb.SpecCIDR{}
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

	pbNwPolicy.NetSpec = pbNetSpec
	pbNwPolicy.GeneratedTime = KnoxNwPolicy.GeneratedTime

	return pbNwPolicy
}

func extractNetworkPoliciesFromNetworkLogs(networkLogs []types.KnoxNetworkLog) []*apb.KnoxNetworkPolicy {

	pbNetPolicies := []*apb.KnoxNetworkPolicy{}
	netPoliciesPerNamespace := netpolicy.PopulateNetworkPoliciesFromNetworkLogs(networkLogs)

	for _, netPolicies := range netPoliciesPerNamespace {
		for _, netPolicy := range netPolicies {
			pbNetPolicy := populatePbNetPolicyFromNetPolicy(netPolicy)
			pbNetPolicies = append(pbNetPolicies, &pbNetPolicy)
		}
	}

	return pbNetPolicies
}

func populateNetworkLogs(pbNetworkLog []*apb.KnoxNetworkLog) []types.KnoxNetworkLog {
	networkLogs := []types.KnoxNetworkLog{}

	// Populate KnoxNetworkLog from Protobuf's NetworkLog
	for _, pbNetLog := range pbNetworkLog {
		netLog := types.KnoxNetworkLog{}
		netLog.FlowID = int(pbNetLog.FlowID)
		netLog.ClusterName = pbNetLog.ClusterName
		netLog.SrcNamespace = pbNetLog.SrcNamespace
		netLog.SrcPodName = pbNetLog.SrcPodName
		netLog.DstNamespace = pbNetLog.DstNamespace
		netLog.DstPodName = pbNetLog.DstPodName
		netLog.EtherType = int(pbNetLog.EtherType)
		netLog.Protocol = int(pbNetLog.Protocol)
		netLog.SrcIP = pbNetLog.SrcIP
		netLog.DstIP = pbNetLog.DstIP
		netLog.SrcPort = int(pbNetLog.SrcPort)
		netLog.DstPort = int(pbNetLog.DstPort)
		netLog.SynFlag = pbNetLog.SynFlag
		netLog.IsReply = pbNetLog.IsReply
		netLog.DNSQuery = pbNetLog.DNSQuery
		netLog.DNSRes = pbNetLog.DNSRes
		netLog.DNSResIPs = append(netLog.DNSResIPs, pbNetLog.DNSResIPs...)
		netLog.HTTPMethod = pbNetLog.HTTPMethod
		netLog.HTTPPath = pbNetLog.HTTPPath
		netLog.Direction = pbNetLog.Direction
		netLog.Action = pbNetLog.Action

		networkLogs = append(networkLogs, netLog)
	}

	return networkLogs
}

func GetNetworkPolicies(pbNetworkLog []*apb.KnoxNetworkLog) []*apb.KnoxNetworkPolicy {

	networkLogs := populateNetworkLogs(pbNetworkLog)
	networkPolicies := extractNetworkPoliciesFromNetworkLogs(networkLogs)

	return networkPolicies
}
