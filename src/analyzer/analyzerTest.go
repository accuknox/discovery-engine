package analyzer

import (
	"context"
	"fmt"
	"log"
	"time"

	apb "github.com/accuknox/knoxAutoPolicy/src/protobuf/v1/analyzer"
	"google.golang.org/grpc"
)

var (
	client apb.AnalyzerClient
)

func analyzerSystemTest() {
	time.Sleep(10 * time.Second)
	fmt.Println("START ANALYZER SYSTEM POLICY TEST")
	systemLogs := apb.SystemLogs{}
	systemTestLogData1 := apb.KnoxSystemLog{}
	systemTestLogData2 := apb.KnoxSystemLog{}

	// Test data
	systemTestLogData1.LogID = 100
	systemTestLogData1.ClusterName = "Test-Cluster-001"
	systemTestLogData1.HostName = "host-001"
	systemTestLogData1.Namespace = "linux-001"
	systemTestLogData1.PodName = "MyPod-001"
	systemTestLogData1.SourceOrigin = "origin-001"
	systemTestLogData1.Source = "source-001"
	systemTestLogData1.Operation = "operation-001"
	systemTestLogData1.ResourceOrigin = "resource-origin-001"
	systemTestLogData1.Resource = "resource-001"
	systemTestLogData1.Data = "data-001"
	systemTestLogData1.ReadOnly = true
	systemTestLogData1.Result = "result-001"
	systemLogs.SysLog = append(systemLogs.SysLog, &systemTestLogData1)

	systemTestLogData2.LogID = 200
	systemTestLogData2.ClusterName = "Test-Cluster-002"
	systemTestLogData2.HostName = "host-002"
	systemTestLogData2.Namespace = "linux-002"
	systemTestLogData2.PodName = "MyPod-002"
	systemTestLogData2.SourceOrigin = "origin-002"
	systemTestLogData2.Source = "source-002"
	systemTestLogData2.Operation = "operation-002"
	systemTestLogData2.ResourceOrigin = "resource-origin-002"
	systemTestLogData2.Resource = "resource-002"
	systemTestLogData2.Data = "data-002"
	systemTestLogData2.ReadOnly = false
	systemTestLogData2.Result = "result-002"
	systemLogs.SysLog = append(systemLogs.SysLog, &systemTestLogData2)

	response, err := client.GetSystemPolicies(context.Background(), &systemLogs)
	if err != nil {
		log.Fatal("Error")
	} else {
		log.Printf("System test Response  : %v\n", response)
	}
}

func analyzerNetworkTest() {
	time.Sleep(20 * time.Second)
	fmt.Println("START ANALYZER NETWORK POLICY TEST")
	netLogs := apb.NetworkLogs{}
	netTestLogData1 := apb.KnoxNetworkLog{}
	netTestLogData2 := apb.KnoxNetworkLog{}

	netTestLogData1.FlowID = 100
	netTestLogData1.ClusterName = "net-test-001"
	netTestLogData1.SrcNamespace = "net-ns-001"
	netTestLogData1.SrcPodName = "net-pod-001"
	netTestLogData1.DstNamespace = "net-dst-001"
	netTestLogData1.DstPodName = "dst-pod-001"
	netTestLogData1.EtherType = 1
	netTestLogData1.Protocol = 2
	netTestLogData1.SrcIP = "192.168.0.100"
	netTestLogData1.DstIP = "192.168.0.101"
	netTestLogData1.SrcPort = 3
	netTestLogData1.DstPort = 4
	netTestLogData1.SynFlag = true
	netTestLogData1.IsReply = false
	netTestLogData1.DNSQuery = "query-001"
	netTestLogData1.DNSRes = "dnsres-001"
	netTestLogData1.DNSResIPs = nil
	netTestLogData1.HTTPMethod = "net-http-method-001"
	netTestLogData1.HTTPPath = "net-http-path-001"
	netTestLogData1.Direction = "net-http-direction-001"
	netTestLogData1.Action = "Block"
	netLogs.NwLog = append(netLogs.NwLog, &netTestLogData1)

	netTestLogData2.FlowID = 200
	netTestLogData2.ClusterName = "net-test-002"
	netTestLogData2.SrcNamespace = "net-ns-002"
	netTestLogData2.SrcPodName = "net-pod-002"
	netTestLogData2.DstNamespace = "net-dst-002"
	netTestLogData2.DstPodName = "dst-pod-002"
	netTestLogData2.EtherType = 5
	netTestLogData2.Protocol = 6
	netTestLogData2.SrcIP = "192.168.0.102"
	netTestLogData2.DstIP = "192.168.0.103"
	netTestLogData2.SrcPort = 7
	netTestLogData2.DstPort = 8
	netTestLogData2.SynFlag = false
	netTestLogData2.IsReply = true
	netTestLogData2.DNSQuery = "query-002"
	netTestLogData2.DNSRes = "dnsres-002"
	netTestLogData2.DNSResIPs = nil
	netTestLogData2.HTTPMethod = "net-http-method-002"
	netTestLogData2.HTTPPath = "net-http-path-002"
	netTestLogData2.Direction = "net-http-direction-002"
	netTestLogData2.Action = "Allow"
	netLogs.NwLog = append(netLogs.NwLog, &netTestLogData2)

	response, err := client.GetNetworkPolicies(context.Background(), &netLogs)
	if err != nil {
		log.Fatal("Error")
	} else {
		log.Printf("Network test Response : %v\n", response)
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
