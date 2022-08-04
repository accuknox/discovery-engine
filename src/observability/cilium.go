package observability

import (
	"errors"
	"reflect"

	"github.com/accuknox/auto-policy-discovery/src/common"
	"github.com/accuknox/auto-policy-discovery/src/libs"
	"github.com/accuknox/auto-policy-discovery/src/types"
	"github.com/cilium/cilium/api/v1/flow"
	"github.com/golang/protobuf/ptypes/wrappers"
)

func convertFlowLogToCiliumLog(flowLog *flow.Flow) (types.CiliumLog, error) {
	ciliumLog := types.CiliumLog{}

	if flowLog == nil {
		return ciliumLog, errors.New("cilium flow log empty")
	}

	// l3
	var ip flow.IP
	//Check l3 exist
	if flowLog.IP != nil {
		ip = *flowLog.IP
	}
	// l4
	var l4TCP flow.TCP
	var l4UDP flow.UDP
	var l4ICMPv4 flow.ICMPv4
	var l4ICMPv6 flow.ICMPv6
	//Check l4 exist
	if flowLog.L4 != nil {
		//Check TCP exist
		if flowLog.L4.GetTCP() != nil {
			l4TCP = *flowLog.L4.GetTCP()
		}
		//Check UDP exist
		if flowLog.L4.GetUDP() != nil {
			l4UDP = *flowLog.L4.GetUDP()
		}
		//Check ICMPv4 exist
		if flowLog.L4.GetICMPv4() != nil {
			l4ICMPv4 = *flowLog.L4.GetICMPv4()
		}
		//Check ICMPv6 exist
		if flowLog.L4.GetICMPv6() != nil {
			l4ICMPv6 = *flowLog.L4.GetICMPv6()
		}
	}
	//Endpoint for source and destination
	var source, destination flow.Endpoint
	//Check Source Endpoint exist
	if flowLog.Source != nil {
		source = *flowLog.Source
	}
	//Check Destination Endpoint exist
	if flowLog.Destination != nil {
		destination = *flowLog.Destination
	}

	//l7
	var l7 flow.Layer7
	var l7Type string
	var l7DNS flow.DNS
	var l7HTTP flow.HTTP
	var l7HTTPHeaders string
	//Check l7 exist
	if flowLog.L7 != nil {
		l7 = *flowLog.GetL7()
		l7Type = l7.GetType().Enum().String()
		//Check DNS exist
		if l7.GetDns() != nil {
			l7DNS = *l7.GetDns()
		}
		//Check HTTP exist
		if l7.GetHttp() != nil {
			l7HTTP = *l7.GetHttp()
			var headers []string
			//Check Headers exist
			if l7HTTP.GetHeaders() != nil {
				//convert headers in key=value format.
				for _, header := range l7HTTP.Headers {
					headers = append(headers, header.Key+"="+header.Value)
				}
				//convert http Header into string format
				l7HTTPHeaders = common.ConvertArrayToString(headers)
			}
		}
	}

	//EventType
	var eventType, eventSubType int32
	if flowLog.EventType != nil {
		eventType = flowLog.EventType.GetType()
		eventSubType = flowLog.EventType.GetSubType()
	}

	//Service Name for source and destination
	var sourceService, destinationService flow.Service
	//Check Service Source exist
	if flowLog.SourceService != nil {
		sourceService = *flowLog.GetSourceService()
	}
	//Check Service Destination exist
	if flowLog.DestinationService != nil {
		destinationService = *flowLog.GetDestinationService()
	}

	var isReply wrappers.BoolValue
	//Check IsReply exist
	if flowLog.IsReply != nil {
		isReply = *flowLog.IsReply
	}

	var dropReason string
	//Check Verdict is Dropped
	if flowLog.GetVerdict().Enum().String() == "DROPPED" {
		dropReason = flowLog.GetDropReasonDesc().Enum().String()
	}

	ciliumLog.Verdict = flowLog.GetVerdict().Enum().String()
	ciliumLog.IpSource = ip.Source
	ciliumLog.IpDestination = ip.Destination
	ciliumLog.IpVersion = ip.GetIpVersion().Enum().String()
	ciliumLog.IpEncrypted = ip.Encrypted
	ciliumLog.L4TCPSourcePort = l4TCP.SourcePort
	ciliumLog.L4TCPDestinationPort = l4TCP.DestinationPort
	ciliumLog.L4UDPSourcePort = l4UDP.SourcePort
	ciliumLog.L4UDPDestinationPort = l4UDP.DestinationPort
	ciliumLog.L4ICMPv4Type = l4ICMPv4.Type
	ciliumLog.L4ICMPv4Code = l4ICMPv4.Code
	ciliumLog.L4ICMPv6Type = l4ICMPv6.Type
	ciliumLog.L4ICMPv6Code = l4ICMPv6.Code
	ciliumLog.SourceNamespace = source.Namespace
	ciliumLog.SourceLabels = common.ConvertArrayToString(source.Labels)
	ciliumLog.SourcePodName = source.PodName
	ciliumLog.DestinationNamespace = destination.Namespace
	ciliumLog.DestinationLabels = common.ConvertArrayToString(destination.Labels)
	ciliumLog.DestinationPodName = destination.PodName
	ciliumLog.Type = flowLog.GetType().Enum().String()
	ciliumLog.NodeName = flowLog.NodeName
	ciliumLog.L7Type = l7Type
	ciliumLog.L7DnsCnames = common.ConvertArrayToString(l7DNS.Cnames)
	ciliumLog.L7DnsObservationsource = l7DNS.ObservationSource
	ciliumLog.L7HttpCode = l7HTTP.Code
	ciliumLog.L7HttpMethod = l7HTTP.Method
	ciliumLog.L7HttpUrl = l7HTTP.Url
	ciliumLog.L7HttpProtocol = l7HTTP.Protocol
	ciliumLog.L7HttpHeaders = l7HTTPHeaders
	ciliumLog.EventTypeType = eventType
	ciliumLog.EventTypeSubType = eventSubType
	ciliumLog.SourceServiceName = sourceService.Name
	ciliumLog.SourceServiceNamespace = sourceService.Namespace
	ciliumLog.DestinationServiceName = destinationService.Name
	ciliumLog.DestinationServiceNamespace = destinationService.Namespace
	ciliumLog.TrafficDirection = flowLog.GetTrafficDirection().Enum().String()
	ciliumLog.TraceObservationPoint = flowLog.GetTraceObservationPoint().Enum().String()
	ciliumLog.DropReasonDesc = dropReason
	ciliumLog.IsReply = isReply.Value
	ciliumLog.StartTime = flowLog.Time.Seconds
	ciliumLog.UpdatedTime = flowLog.Time.Seconds

	return ciliumLog, nil
}

func ProcessNetworkLogs() {
	var isEntryExist bool
	var newLogs, updateLogs []types.CiliumLog

	if len(NetworkLogs) > 0 {

		NetworkLogsMutex.Lock()
		locNetLogs := NetworkLogs
		NetworkLogs = []*flow.Flow{} //reset
		NetworkLogsMutex.Unlock()

		networkLogs, err := getNetworkLogs()
		if err != nil {
			return
		}

		for _, flowLog := range locNetLogs {
			isEntryExist = false

			netLog, err := convertFlowLogToCiliumLog(flowLog)
			if err != nil {
				log.Error().Msg(err.Error())
			} else {
				for _, locNetLog := range networkLogs {
					locNetLog.StartTime = 0
					locNetLog.UpdatedTime = 0
					locNetLog.Total = 0
					if reflect.DeepEqual(locNetLog, netLog) {
						isEntryExist = true
						break
					}
				}

				if isEntryExist {
					updateLogs = append(updateLogs, netLog)
				} else {
					newLogs = append(newLogs, netLog)
					networkLogs = append(networkLogs, netLog)
				}
			}
		}
		pushCiliumLogs(newLogs, updateLogs)
	}
}

func ProcessCiliumFlow(flowLog *flow.Flow) {
	NetworkLogsMutex.Lock()
	NetworkLogs = append(NetworkLogs, flowLog)
	NetworkLogsMutex.Unlock()
}

func getNetworkLogs() ([]types.CiliumLog, error) {

	logs, _, err := libs.GetCiliumLogs(CfgDB, types.CiliumLog{})
	if err != nil {
		return nil, err
	}
	return logs, nil
}

func pushCiliumLogs(newLogs, updateLogs []types.CiliumLog) {
	NetObsMutex.Lock()
	for _, newlog := range newLogs {
		if err := libs.InsertCiliumLogs(CfgDB, newlog); err != nil {
			log.Error().Msg(err.Error())
		}
	}
	for _, updatelog := range updateLogs {
		if err := libs.UpdateCiliumLogs(CfgDB, updatelog); err != nil {
			log.Error().Msg(err.Error())
		}
	}
	NetObsMutex.Unlock()
}
