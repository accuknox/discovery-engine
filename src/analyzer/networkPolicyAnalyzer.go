package analyzer

import (
	"encoding/json"

	netpolicy "github.com/accuknox/knoxAutoPolicy/src/networkpolicy"
	apb "github.com/accuknox/knoxAutoPolicy/src/protobuf/v1/analyzer"
	types "github.com/accuknox/knoxAutoPolicy/src/types"
)

func extractNetworkPoliciesFromNetworkLogs(networkLogs []types.KnoxNetworkLog) []*apb.KnoxNetworkPolicy {

	pbNetPolicies := []*apb.KnoxNetworkPolicy{}
	netPolicies := netpolicy.PopulateNetworkPoliciesFromNetworkLogs(networkLogs)

	for _, netPolicy := range netPolicies {
		pbNetPolicy := apb.KnoxNetworkPolicy{}
		pbNetPolicyBytes, err := json.Marshal(netPolicy)
		if err != nil {
			return nil
		} else {
			pbNetPolicy.NetworkPolicy = pbNetPolicyBytes
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
