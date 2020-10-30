package main

import (
	"fmt"
	"time"

	"github.com/accuknox/knoxAutoPolicy/core"
	"github.com/accuknox/knoxAutoPolicy/libs"

	"github.com/robfig/cron/v3"
)

// network flow between [ startTime <= time < endTime ]
var startTime int64 = 0
var endTime int64 = 0

func init() {
	// init time filter
	endTime = time.Now().Unix()
	startTime = 0
}

func Generate() {
	// get network traffic from  knox aggregation Databse
	trafficList, err := libs.GetTrafficFlowByTime(startTime, endTime)
	if err != nil {
		fmt.Println(err)
		return
	}

	if len(trafficList) < 1 {
		fmt.Println("Traffic flow is not exist: ",
			time.Unix(startTime, 0).Format(libs.TimeFormSimple), " ~ ",
			time.Unix(endTime, 0).Format(libs.TimeFormSimple))

		startTime = endTime
		endTime = time.Now().Unix()
		return
	}

	// time filter update for next
	startTime = trafficList[len(trafficList)-1].TrafficFlow.Time + 1
	endTime = time.Now().Unix()

	namespaces := libs.K8s.GetK8sNamespaces()
	for _, namespace := range namespaces {
		fmt.Println("start for namespace: ", namespace)

		// convert network traffic -> network log, and filter traffic
		networkLogs := libs.ConvertTrafficFlowToLogs(namespace, trafficList)

		// get k8s services
		services := libs.K8s.GetServices(namespace)

		// get k8s endpoints
		endpoints := libs.K8s.GetEndpoints(namespace)

		// get pod information
		pods := libs.K8s.GetConGroups(namespace)

		// generate network policies
		policies := core.GenerateNetworkPolicies(namespace, 24, networkLogs, services, endpoints, pods)
		// libs.WritePolicyFile(policies)
		for _, policy := range policies {
			// cnp := libs.ToCiliumNetworkPolicy(policy)
			libs.InsertDiscoveredPolicy(policy)
		}

		fmt.Println("done generated policies for namespace: ", namespace, " ", len(policies))
	}
}

func CronJobDaemon() {
	// init cron job
	c := cron.New()
	c.AddFunc("@every 0h0m30s", Generate) // every time interval for test
	c.Start()

	sig := libs.GetOSSigChannel()
	<-sig
	println("Got a signal to terminate the auto policy discovery")

	c.Stop() // Stop the scheduler (does not stop any jobs already running).
}

func main() {
	Generate()
	// get network traffic from  knox aggregation Databse
	// trafficList, err := libs.GetTrafficFlowByTime(startTime, endTime)
	// if err != nil {
	// 	fmt.Println(err)
	// 	return
	// }

	// for _, flow := range trafficList {
	// 	if flow.TrafficFlow.L7 != nil && flow.TrafficFlow.L7.Dns != nil {
	// 		if flow.TrafficFlow.L7.GetType() == "REQUEST" &&
	// 			!strings.HasSuffix(flow.TrafficFlow.L7.Dns.GetQuery(), "cluster.local.") {
	// 			q := strings.TrimSuffix(flow.TrafficFlow.L7.Dns.GetQuery(), ".")
	// 			print(q, " ")
	// 			fmt.Println(flow.TrafficFlow.L7.Dns)

	// 			fmt.Println(flow.TrafficFlow.Source.Namespace, "->", flow.TrafficFlow.Destination.Namespace)
	// 			fmt.Println(flow.TrafficFlow.Source.Pod, "->", flow.TrafficFlow.Destination.Pod)
	// 		}
	// 	}
	// }
}
