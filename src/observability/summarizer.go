package observability

import (
	"errors"
	"strconv"
	"strings"

	"github.com/accuknox/auto-policy-discovery/src/cluster"
	"github.com/accuknox/auto-policy-discovery/src/config"
	"github.com/accuknox/auto-policy-discovery/src/types"
	pb "github.com/kubearmor/KubeArmor/protobuf"
)

func extractNetworkInfoFromSystemLog(netLog pb.Log) (string, string, string, string, string, string, error) {
	var ip, destNs, destLabel, port, protocol, nwrule string = "", "", "", "", "", ""
	err := errors.New("not a valid incoming/outgoing connection")

	if strings.Contains(netLog.Data, "tcp_connect") || strings.Contains(netLog.Data, "SYS_CONNECT") {
		nwrule = "egress"
	} else if strings.Contains(netLog.Data, "tcp_accept") {
		nwrule = "ingress"
	} else {
		return ip, destNs, destLabel, port, protocol, nwrule, err
	}

	if strings.Contains(netLog.Data, "tcp_") {
		resslice := strings.Split(netLog.Resource, " ")
		for _, locres := range resslice {
			if strings.Contains(locres, "remoteip") {
				ip, destLabel, destNs = cluster.ExtractPodSvcInfoFromIP(strings.Split(locres, "=")[1], netLog.ClusterName)
			}
			if strings.Contains(locres, "port") {
				port = strings.Split(locres, "=")[1]
			}
			if strings.Contains(locres, "protocol") {
				protocol = strings.Split(locres, "=")[1]
			}
		}
	} else if strings.Contains(netLog.Resource, "AF_UNIX") {
		var path string
		resslice := strings.Split(netLog.Resource, " ")
		for _, locres := range resslice {
			if strings.Contains(locres, "sun_path") {
				path = strings.Split(locres, "=")[1]
				if path != "" {
					ip = path
					protocol = "UNIX"
					break
				}
			}
		}
	} else {
		return "", "", "", "", "", "", err
	}

	return ip, destNs, destLabel, port, protocol, nwrule, nil
}

func convertSysLogToSysSummaryMap(syslogs []*pb.Log) {

	deployments := cluster.GetDeploymentsFromK8sClient()

	for _, syslog := range syslogs {
		sysSummary := types.SystemSummary{}

		if strings.HasPrefix(syslog.Source, "./") {
			continue
		}

		if strings.HasPrefix(syslog.Resource, "./") {
			continue
		}

		if syslog.Operation != "File" && syslog.Operation != "Process" && syslog.Operation != "Network" {
			continue
		}

		if syslog.Type == "MatchedPolicy" || syslog.Type == "MatchedHostPolicy" {
			if syslog.Result == "Passed" {
				sysSummary.Action = "Audit"
			} else {
				sysSummary.Action = "Deny"
			}
		} else {
			sysSummary.Action = "Allow"
		}

		if config.GetCfgClusterName() == "" {
			sysSummary.ClusterName = syslog.ClusterName
		} else {
			sysSummary.ClusterName = config.GetCfgClusterName()
		}

		workspaceId, _ := strconv.ParseInt(config.GetCfgWorkspaceId(), 0, 32)

		sysSummary.WorkspaceId = int32(workspaceId)
		sysSummary.NamespaceName = syslog.NamespaceName
		sysSummary.ContainerName = syslog.ContainerName
		sysSummary.ContainerImage = syslog.ContainerImage
		sysSummary.ContainerID = syslog.ContainerID
		sysSummary.PodName = syslog.PodName
		sysSummary.Operation = syslog.Operation
		sysSummary.Source = strings.Split(syslog.Source, " ")[0]
		sysSummary.Labels = syslog.Labels
		sysSummary.Deployment = ""

		for _, d := range deployments {
			if d.Labels == syslog.Labels && d.Namespace == syslog.NamespaceName {
				sysSummary.Deployment = d.Name
				break
			}
		}

		if syslog.Operation == "Network" {
			ip, destNs, destLabel, portStr, protocol, nwrule, err := extractNetworkInfoFromSystemLog(*syslog)
			if err != nil {
				continue
			}
			port, _ := strconv.ParseInt(portStr, 10, 32)
			sysSummary.NwType = nwrule
			sysSummary.IP = ip
			sysSummary.Port = int32(port)
			sysSummary.Protocol = protocol
			sysSummary.DestNamespace = destNs
			sysSummary.DestLabels = destLabel
		} else if syslog.Operation == "File" || syslog.Operation == "Process" {
			sysSummary.NwType = ""
			sysSummary.IP = ""
			sysSummary.Port = 0
			sysSummary.Protocol = ""
			sysSummary.DestNamespace = ""
			sysSummary.DestLabels = ""
			sysSummary.Destination = strings.Split(syslog.Resource, " ")[0]
		}

		if syslog.Type == "ContainerLog" && syslog.NamespaceName == types.PolicyDiscoveryContainerNamespace {
			sysSummary.NamespaceName = types.PolicyDiscoveryContainerNamespace
			sysSummary.PodName = types.PolicyDiscoveryContainerPodName
		}

		if syslog.Type == "HostLog" || syslog.Type == "MatchedHostPolicy" {
			sysSummary.ContainerName = syslog.HostName
			sysSummary.NamespaceName = types.PolicyDiscoveryVMNamespace
			sysSummary.PodName = types.PolicyDiscoveryVMPodName
		}

		appendSummaryDataToSummaryMap(sysSummary, syslog.Timestamp)
	}
}

func appendSummaryDataToSummaryMap(summary types.SystemSummary, ts int64) {
	SummarizerMap[summary] = types.SysSummaryTimeCount{
		Count:       SummarizerMap[summary].Count + 1,
		UpdatedTime: ts,
	}
}
