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
	systemTestLogData1.ClusterName = "Test Cluster 001"
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
	systemTestLogData2.ClusterName = "Test Cluster 002"
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
		log.Printf("Response : %v\n", response)
	}
}

func analyzerNetworkTest() {
	time.Sleep(20 * time.Second)
	fmt.Println("START ANALYZER NETWORK POLICY TEST")
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
