package observability

import (
	"errors"
	"regexp"
	"strings"

	"github.com/accuknox/auto-policy-discovery/src/libs"
	opb "github.com/accuknox/auto-policy-discovery/src/protobuf/v1/observability"
	"github.com/accuknox/auto-policy-discovery/src/types"
)

func deDuplicateServerInOutConn(connList []types.SysNwConnDetail) []types.SysNwConnDetail {
	occurred := map[types.SysNwConnDetail]bool{}
	result := []types.SysNwConnDetail{}
	for index := range connList {
		if occurred[connList[index]] != true {
			occurred[connList[index]] = true
			// Append to result slice.
			result = append(result, connList[index])
		}
	}
	return result
}

func mapPodSvcNameFromIP(ip string) string {

	// Get matching pod name from IP
	pod := GetPodDetailFromPodIP(ip)
	if pod.PodName != "" {
		return "pod/" + pod.PodName
	}

	// Get matching service name from IP
	svc := GetServiceDetailFromClusterIP(ip)
	if svc.ServiceName != "" {
		return "svc/" + svc.ServiceName
	}
	return ip
}

func fetchSysServerConnDetail(log types.KubeArmorLog) (types.SysNwConnDetail, error) {
	conn := types.SysNwConnDetail{}
	err := errors.New("not a valid incoming/outgoing connection")

	// get Syscall
	if strings.Contains(log.Data, "SYS_CONNECT") {
		conn.InOut = "OUT"
	} else if strings.Contains(log.Data, "SYS_ACCEPT") {
		conn.InOut = "IN"
	} else {
		return types.SysNwConnDetail{}, err
	}

	// get AF detail
	if strings.Contains(log.Resource, "AF_INET") {
		var ip, port string
		resslice := strings.Split(log.Resource, " ")
		for _, locres := range resslice {
			if strings.Contains(locres, "sin_addr") {
				ip = strings.Split(locres, "=")[1]
			}
			if strings.Contains(locres, "sin_port") {
				port = strings.Split(locres, "=")[1]
			}
			if ip != "" && port != "" {
				conn.PodSvcIP = mapPodSvcNameFromIP(ip)
				conn.ServerPort = port
				conn.Protocol = ""
				conn.Labels = log.Labels
				break
			}
		}
	} else if strings.Contains(log.Resource, "AF_UNIX") {
		var path string
		resslice := strings.Split(log.Resource, " ")
		for _, locres := range resslice {
			if strings.Contains(locres, "sun_path") {
				path = strings.Split(locres, "=")[1]
				if path != "" {
					conn.PodSvcIP = path
					conn.Protocol = ""
					conn.Labels = log.Labels
					break
				}
			}
		}
	} else {
		return types.SysNwConnDetail{}, err
	}

	if conn.PodSvcIP == "" {
		return types.SysNwConnDetail{}, err
	}

	conn.PodName = log.PodName

	return conn, nil
}

//GetSummaryLogs - Give Summary logs of Pod based on Label and Namespace Input
func GetSummaryLogs(pbRequest *opb.LogsRequest, stream opb.Summary_FetchLogsServer) error {
	log.Info().Msg("Get Summary Log Called")
	systemPods := make(map[string][]types.SystemSummary)
	networkPods := make(map[string][]types.NetworkSummary)
	// Thsi type is used for comparison
	syserverconn := []types.SysNwConnDetail{}

	//Fetch network Logs
	networkLogs, networkTotal, err := libs.GetCiliumLogs(CfgDB, types.CiliumLog{
		SourceLabels:    pbRequest.Label,
		SourceNamespace: pbRequest.Namespace,
	})
	if err != nil {
		return err
	}

	for nwindex, locNetLog := range networkLogs {
		networkPods[locNetLog.SourcePodName] = append(networkPods[locNetLog.SourcePodName], types.NetworkSummary{
			Verdict:              locNetLog.Verdict,
			DestinationLabels:    locNetLog.DestinationLabels,
			DestinationNamespace: locNetLog.DestinationNamespace,
			Type:                 locNetLog.Type,
			L4TCPSourcePort:      locNetLog.L4TCPSourcePort,
			L4TCPDestinationPort: locNetLog.L4TCPDestinationPort,
			L4UDPSourcePort:      locNetLog.L4UDPSourcePort,
			L4UDPDestinationPort: locNetLog.L4UDPDestinationPort,
			L4ICMPv4Code:         locNetLog.L4ICMPv4Code,
			L4ICMPv6Code:         locNetLog.L4ICMPv6Code,
			L7DnsCnames:          locNetLog.L7DnsCnames,
			L7HttpMethod:         locNetLog.L7HttpMethod,
			TrafficDirection:     locNetLog.TrafficDirection,
			UpdatedTime:          locNetLog.UpdatedTime,
			Count:                int32(networkTotal[nwindex]),
		})
	}

	//Fetch System Logs
	systemLogs, systemTotal, err := libs.GetKubearmorLogs(CfgDB, types.KubeArmorLog{
		Labels:        pbRequest.Label,
		NamespaceName: pbRequest.Namespace,
	})
	if err != nil {
		return err
	}
	for sysindex, locSysLog := range systemLogs {
		if locSysLog.Operation == "Network" {
			nwConnDetail, err := fetchSysServerConnDetail(locSysLog)
			if err == nil {
				syserverconn = append(syserverconn, nwConnDetail)
			}
		}
		systemPods[locSysLog.PodName] = append(systemPods[locSysLog.PodName], types.SystemSummary{
			Operation:   locSysLog.Operation,
			Source:      locSysLog.Source,
			Resource:    locSysLog.Resource,
			Action:      locSysLog.Action,
			UpdatedTime: locSysLog.UpdatedTime,
			Count:       int32(systemTotal[sysindex]),
		})
	}

	// De-duplicate syserverconn
	syserverconn = deDuplicateServerInOutConn(syserverconn)

	for podName, sysLogs := range systemPods {

		var podns string
		var listOfFile, listOfProcess, listOfNetwork []*opb.ListOfSource
		var inServerConn, outServerConn []*opb.ServerConnections
		//System Block
		fileSource := make(map[string][]*opb.ListOfDestination)
		processSource := make(map[string][]*opb.ListOfDestination)
		networkSource := make(map[string][]*opb.ListOfDestination)
		// source := make(map[string]int32)
		for _, sysLog := range sysLogs {
			source := strings.Split(sysLog.Source, " ")[0]
			//Checking System Operation that's File, Process and Network
			switch sysLog.Operation {
			case "File":
				fileSource[source] = convertListofDestination(fileSource[source], sysLog)
			case "Process":
				processSource[source] = convertListofDestination(processSource[source], sysLog)
			case "Network":
				protocol, _ := networkRegex(sysLog.Resource)
				if protocol != "" {
					networkSource[source] = convertListofDestination(networkSource[source], sysLog)
				}
			}
		}
		for source, resources := range fileSource {
			listOfFile = append(listOfFile, &opb.ListOfSource{
				Source:            source,
				ListOfDestination: resources,
			})
		}
		for source, resources := range processSource {
			listOfProcess = append(listOfProcess, &opb.ListOfSource{
				Source:            source,
				ListOfDestination: resources,
			})
		}

		for source, protocols := range networkSource {
			listOfNetwork = append(listOfNetwork, &opb.ListOfSource{
				Source:            source,
				ListOfDestination: protocols,
			})
		}
		var networkIngress, networkEgress []*opb.ListOfConnection
		//Network Block
		for _, netLog := range networkPods[podName] {
			//Check Traffic Direction is Ingress or Egress
			switch netLog.TrafficDirection {
			case "INGRESS":
				networkIngress = convertNetworkConnection(netLog, networkIngress)
			case "EGRESS":
				networkEgress = convertNetworkConnection(netLog, networkEgress)
			}
		}

		// ServerConnection
		for _, servConn := range syserverconn {
			if servConn.PodName == podName {
				if servConn.InOut == "IN" {
					inServerConn = append(inServerConn, &opb.ServerConnections{
						Protocol:   servConn.Protocol,
						PodSvcIP:   servConn.PodSvcIP,
						ServerPort: servConn.ServerPort,
						Labels:     servConn.Labels,
					})
				} else if servConn.InOut == "OUT" {
					outServerConn = append(outServerConn, &opb.ServerConnections{
						Protocol:   servConn.Protocol,
						PodSvcIP:   servConn.PodSvcIP,
						ServerPort: servConn.ServerPort,
						Labels:     servConn.Labels,
					})
				}
			}
		}

		for _, locpod := range Pods {
			if locpod.PodName == podName {
				podns = locpod.Namespace
				break
			}
		}

		//Stream Block
		if err := stream.Send(&opb.LogsResponse{
			PodDetail:     podName,
			Namespace:     podns,
			ListOfFile:    listOfFile,
			ListOfProcess: listOfProcess,
			ListOfNetwork: listOfNetwork,
			Ingress:       networkIngress,
			Egress:        networkEgress,
			InServerConn:  inServerConn,
			OutServerConn: outServerConn,
		}); err != nil {
			log.Error().Msg("Error in Streaming Summary Logs : " + err.Error())
		}
	}

	return nil
}

//networkRegex - To Get the Protocol using Regex
func networkRegex(str string) (string, error) {
	var retcp, reudp, reicmp, reraw *regexp.Regexp

	retcp, err := regexp.Compile("domain=.*type=SOCK_STREAM")
	if err != nil {
		log.Error().Msgf("failed tcp regexp compile err=%s", err.Error())
		return "", err
	}
	if retcp.MatchString(str) {
		return "TCP", nil
	}
	reudp, err = regexp.Compile("domain=.*type=SOCK_DGRAM")
	if err != nil {
		log.Error().Msgf("failed udp regexp compile err=%s", err.Error())
		return "", err
	}
	if reudp.MatchString(str) {
		return "UDP", nil
	}
	reicmp, err = regexp.Compile(`domain=.*protocol=(\b58\b|\b1\b)`) //1=icmp, 58=icmp6
	if err != nil {
		log.Error().Msgf("failed icmp regexp compile err=%s", err.Error())
		return "", err
	}
	if reicmp.MatchString(str) {
		return "ICMP", nil
	}
	reraw, err = regexp.Compile("domain=.*type=SOCK_RAW")
	if err != nil {
		log.Error().Msgf("failed raw regexp compile err=%s", err.Error())
		return "", err
	}
	if reraw.MatchString(str) {
		return "RAW", nil
	}
	return "", nil
}

//convertListofDestination - Create the mapping between Source and Destination/Resource/Protocol
func convertListofDestination(arr []*opb.ListOfDestination, sysLog types.SystemSummary) []*opb.ListOfDestination {
	destination := aggregateFolder(sysLog.Resource)
	//Check Operation is Network
	if sysLog.Operation == "Network" {
		destination, _ = networkRegex(sysLog.Resource)
	}
	for _, value := range arr {
		if value.Destination == destination && value.Status == sysLog.Action {
			value.Count += sysLog.Count
			value.LastUpdatedTime = sysLog.UpdatedTime
			return arr
		}
	}
	arr = append(arr, &opb.ListOfDestination{
		Destination:     destination,
		Count:           sysLog.Count,
		Status:          sysLog.Action,
		LastUpdatedTime: sysLog.UpdatedTime,
	})
	return arr
}

/* aggregateFolder - Aggreagte the Folder or File path with Parent name
For Example - Folder Name is /abc/bin/1234 or /abc/xyz.txt --> convert this into /abc/*
*/
func aggregateFolder(str string) string {

	switch str {
	case "":
		return str
	case "/":
		return str
	default:
		if strings.HasPrefix(str, "/") {
			s := strings.SplitAfterN(str, "/", -1)[1]
			if strings.HasSuffix(s, "/") {
				return "/" + s + "*"
			}

			return "/" + s
		}
		return str
	}
}

func convertNetworkConnection(netLog types.NetworkSummary, list []*opb.ListOfConnection) []*opb.ListOfConnection {

	var listOfConn opb.ListOfConnection

	listOfConn.DestinationLabels = netLog.DestinationLabels
	listOfConn.DestinationNamespace = netLog.DestinationNamespace

	var portTCP, portUDP uint32
	//Based on Traffic Direction assign SourcePort or Destination Port
	switch netLog.TrafficDirection {
	case "INGRESS":
		portTCP = netLog.L4TCPSourcePort
		portUDP = netLog.L4UDPSourcePort
	case "EGRESS":
		portTCP = netLog.L4TCPDestinationPort
		portUDP = netLog.L4UDPDestinationPort
	}
	//Check Protocol Type
	if netLog.L4TCPDestinationPort != 0 {

		listOfConn.Port = portTCP
		if netLog.L7HttpMethod != "" {
			listOfConn.Protocol = "HTTP"
		} else {
			listOfConn.Protocol = "TCP"
		}
	} else if netLog.L4UDPDestinationPort != 0 {

		listOfConn.Port = portUDP
		if netLog.L7DnsCnames != "" {
			listOfConn.Protocol = "DNS"
		} else {
			listOfConn.Protocol = "UDP"
		}
	} else if netLog.L4ICMPv4Code != 0 {
		listOfConn.Protocol = "ICMPv4"
	} else {
		listOfConn.Protocol = "ICMPv6"
	}

	//Convert Status based on Verdict
	switch netLog.Verdict {
	case "FORWARDED", "REDIRECTED":
		listOfConn.Status = "ALLOW"
	case "DROPPED", "ERROR":
		listOfConn.Status = "DENY"
	case "AUDIT":
		listOfConn.Status = "AUDIT"
	}

	for _, value := range list {
		if value.DestinationLabels == listOfConn.DestinationLabels && value.DestinationNamespace == listOfConn.DestinationNamespace &&
			value.Protocol == listOfConn.Protocol && value.Port == listOfConn.Port && value.Status == listOfConn.Status {
			value.Count += netLog.Count
			value.LastUpdatedTime = netLog.UpdatedTime
			return list
		}
	}
	listOfConn.Count = netLog.Count
	listOfConn.LastUpdatedTime = netLog.UpdatedTime
	list = append(list, &listOfConn)
	return list
}
