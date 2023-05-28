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

func extractNetworkInfoFromSystemLog(netLog pb.Alert, pods []types.Pod, services []types.Service) (string, string, string, string, string, string, string, string, error) {
	var ip, destNs, destLabel, port, bindPort, bindAddress, protocol, nwrule string = "", "", "", "", "", "", "", ""
	err := errors.New("not a valid incoming/outgoing connection")

	if strings.Contains(netLog.Data, "tcp_connect") || strings.Contains(netLog.Data, "SYS_CONNECT") {
		nwrule = "egress"
	} else if strings.Contains(netLog.Data, "tcp_accept") {
		nwrule = "ingress"
	} else if strings.Contains(netLog.Data, "SYS_BIND") {
		nwrule = "bind"
	} else {
		return ip, destNs, destLabel, port, bindPort, bindAddress, protocol, nwrule, err
	}

	if strings.Contains(netLog.Data, "tcp_") {
		resslice := strings.Split(netLog.Resource, " ")
		for _, locres := range resslice {
			if strings.Contains(locres, "remoteip") {
				ip, destLabel, destNs = cluster.ExtractPodSvcInfoFromIP(strings.Split(locres, "=")[1], netLog.ClusterName, pods, services)
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
		protocol = "AF_UNIX"
		resslice := strings.Split(netLog.Resource, " ")
		for _, locres := range resslice {
			if strings.Contains(locres, "sun_path") {
				path = strings.Split(locres, "=")[1]
				if path != "" {
					ip = path
					bindAddress = path
					break
				}
			}
		}
	} else if strings.Contains(netLog.Data, "SYS_BIND") {
		resslice := strings.Split(netLog.Resource, " ")
		for _, locres := range resslice {
			if strings.Contains(locres, "sin_port") {
				bindPort = strings.Split(locres, "=")[1]
			}
			if strings.Contains(locres, "sin_addr") {
				bindAddress = strings.Split(locres, "=")[1]
			}
			if strings.Contains(locres, "sa_family") {
				protocol = strings.Split(locres, "=")[1]
			}
		}

	} else {
		return "", "", "", "", "", "", "", "", err
	}

	return ip, destNs, destLabel, port, bindPort, bindAddress, protocol, nwrule, nil
}

func convertSysLogToSysSummaryMap(syslogs []*pb.Alert) {

	var services []types.Service
	var pods []types.Pod
	var err error
	existingClustername := ""

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

		if syslog.Action != "" {
			sysSummary.Action = syslog.Action
		} else {
			sysSummary.Action = "Allow"
		}

		if config.GetCfgClusterName() == "" {
			sysSummary.ClusterName = syslog.ClusterName
		} else {
			sysSummary.ClusterName = config.GetCfgClusterName()
		}

		sysSummary.WorkspaceId = config.GetCfgWorkspaceId()
		sysSummary.ClusterId = config.GetCfgClusterId()
		sysSummary.NamespaceName = syslog.NamespaceName
		sysSummary.ContainerName = syslog.ContainerName
		sysSummary.ContainerImage = syslog.ContainerImage
		sysSummary.ContainerID = syslog.ContainerID
		sysSummary.PodName = syslog.PodName
		sysSummary.Operation = syslog.Operation
		sysSummary.Source = strings.Split(syslog.Source, " ")[0]
		sysSummary.Labels = syslog.Labels
		sysSummary.Enforcer = syslog.Enforcer
		sysSummary.Tags = syslog.Tags
		sysSummary.Message = syslog.Message
		sysSummary.Severity = syslog.Severity
		sysSummary.PolicyName = syslog.PolicyName
		sysSummary.Workload.Type = syslog.Owner.Ref
		sysSummary.Workload.Name = syslog.Owner.Name
		sysSummary.Deployment = syslog.Owner.Name

		if syslog.Operation == "Network" {
			if existingClustername != syslog.ClusterName {
				_, services, _, pods, err = cluster.GetAllClusterResources(syslog.ClusterName)
				if err == nil {
					existingClustername = syslog.ClusterName
				}
			}

			ip, destNs, destLabel, portStr, bindPort, bindAddress, protocol, nwrule, err := extractNetworkInfoFromSystemLog(*syslog, pods, services)

			if err != nil {
				continue
			}
			port, _ := strconv.ParseInt(portStr, 10, 32)
			sysSummary.NwType = nwrule
			sysSummary.IP = ip
			sysSummary.Port = int32(port)
			sysSummary.BindPort = bindPort
			sysSummary.BindAddress = bindAddress
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
