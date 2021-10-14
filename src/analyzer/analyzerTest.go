package analyzer

import (
	"context"
	"fmt"
	"log"
	"time"

	nwpolicy "github.com/accuknox/knoxAutoPolicy/src/networkpolicy"
	apb "github.com/accuknox/knoxAutoPolicy/src/protobuf/v1/analyzer"
	syspolicy "github.com/accuknox/knoxAutoPolicy/src/systempolicy"
	"google.golang.org/grpc"
)

var (
	client apb.AnalyzerClient
)

func analyzerSystemTest() {
	time.Sleep(2 * 60 * time.Second)
	fmt.Println("START ANALYZER SYSTEM POLICY TEST")
	systemLogs := apb.SystemLogs{}
	syslogs := syspolicy.GetSystemLogs()

	for _, syslog := range syslogs {
		pbsyslog := apb.KnoxSystemLog{}
		pbsyslog.LogID = int32(syslog.LogID)
		pbsyslog.ClusterName = syslog.ClusterName
		pbsyslog.HostName = syslog.Namespace
		pbsyslog.PodName = syslog.Namespace
		pbsyslog.SourceOrigin = syslog.SourceOrigin
		pbsyslog.Source = syslog.Source
		pbsyslog.Operation = syslog.Operation
		pbsyslog.ResourceOrigin = syslog.ResourceOrigin
		pbsyslog.Resource = syslog.Resource
		pbsyslog.Data = syslog.Data
		pbsyslog.ReadOnly = syslog.ReadOnly
		pbsyslog.Result = syslog.Result

		systemLogs.SysLog = append(systemLogs.SysLog, &pbsyslog)

		fmt.Printf("Converted PB sys log :%v\n", pbsyslog)
	}

	response, err := client.GetSystemPolicies(context.Background(), &systemLogs)
	if err != nil {
		log.Fatal("Error")
	} else {
		log.Printf("System test Response  : %v\n", response)
	}
}

func analyzerNetworkTest() {

	for {

		netLogs := apb.NetworkLogs{}

		time.Sleep(60 * time.Second)
		fmt.Println("START ANALYZER NETWORK POLICY TEST")

		nwlogs := nwpolicy.GetNetworkLogs()
		fmt.Printf("analyzerNetworkTest - nwlogs [%v]\n", nwlogs)

		for _, nwlog := range nwlogs {
			pbNetLog := apb.KnoxNetworkLog{}
			pbNetLog.FlowID = int32(nwlog.FlowID)
			pbNetLog.ClusterName = nwlog.ClusterName
			pbNetLog.SrcNamespace = nwlog.SrcNamespace
			pbNetLog.SrcPodName = nwlog.SrcPodName
			pbNetLog.DstNamespace = nwlog.DstNamespace
			pbNetLog.DstPodName = nwlog.DstPodName
			pbNetLog.EtherType = int32(nwlog.EtherType)
			pbNetLog.Protocol = int32(nwlog.Protocol)
			pbNetLog.SrcIP = nwlog.SrcIP
			pbNetLog.DstIP = nwlog.DstIP
			pbNetLog.SrcPort = int32(nwlog.SrcPort)
			pbNetLog.DstPort = int32(nwlog.DstPort)
			pbNetLog.SynFlag = nwlog.SynFlag
			pbNetLog.IsReply = nwlog.IsReply
			pbNetLog.DNSQuery = nwlog.DNSQuery
			pbNetLog.DNSRes = nwlog.DNSRes
			pbNetLog.DNSResIPs = nwlog.DNSResIPs
			pbNetLog.HTTPMethod = nwlog.HTTPMethod
			pbNetLog.HTTPPath = nwlog.HTTPPath
			pbNetLog.Direction = nwlog.Direction
			pbNetLog.Action = nwlog.Action

			fmt.Printf("Converted PB nw log :%v\n", pbNetLog)

			netLogs.NwLog = append(netLogs.NwLog, &pbNetLog)
		}

		response, err := client.GetNetworkPolicies(context.Background(), &netLogs)
		if err != nil {
			log.Fatal("Error")
		} else {
			fmt.Printf("Network test Response : %v\n", response)
		}
	}
}

func StartAnalyzerTest() {
	time.Sleep(10 * time.Second)
	fmt.Println("START ANALYZER TEST")

	ctx, _ := context.WithTimeout(context.Background(), 30*time.Second)
	grpcClientConn, err := grpc.DialContext(ctx, ":9089", grpc.WithInsecure(), grpc.WithBlock())
	if err != nil {
		log.Println("gRPC Dial failed")
		log.Fatal(err)
	} else {
		log.Println("CONNECTION OK")
	}

	client = apb.NewAnalyzerClient(grpcClientConn)
	if client == nil {
		log.Fatal("invalid client handle")
	} else {
		log.Println("CLIENT NOT NIL")
	}

	go analyzerSystemTest()
	go analyzerNetworkTest()

}
