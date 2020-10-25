package main

import (
	"fmt"
	"os"
	"time"

	"github.com/accuknox/knoxAutoPolicy/core"
	"github.com/accuknox/knoxAutoPolicy/libs"

	"github.com/robfig/cron/v3"
	"gopkg.in/yaml.v2"
)

// network flow between [ startTime <= time < endTime ]
var startTime int64 = 0
var endTime int64 = 0

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

		// create policy file
		f, err := os.Create("./policies_" + namespace + "_" + time.Unix(endTime, 0).Format(libs.TimeFormSimple) + ".yaml")
		if err != nil {
			fmt.Println(err)
			continue
		}

		// convert network traffic -> network log, and filter traffic
		networkLogs := libs.ConvertTrafficFlowToLogs(namespace, trafficList)

		// get k8s services
		services := libs.K8s.GetServices(namespace)

		// get pod information
		pods := libs.K8s.GetConGroups(namespace)

		// generate network policies
		policies := core.GenerateNetworkPolicies(namespace, 24, networkLogs, services, pods)
		for _, policy := range policies {
			ciliumPolicy := libs.ToCiliumNetworkPolicy(policy) // if you want to convert it to Cilium policy
			// PrintSimplePolicy(ciliumPolicy)	// simple print in terminal
			b, _ := yaml.Marshal(&ciliumPolicy)
			f.Write(b)
			f.WriteString("---\n")
			f.Sync()
		}

		f.Close()

		fmt.Println("done for namespace: ", namespace)
	}
}

func main() {
	// init time filter
	endTime = time.Now().Unix()
	startTime = endTime - 30

	// init cron job
	c := cron.New()
	c.AddFunc("@every 0h0m5s", Generate) // every 5s for test
	c.Start()

	sig := libs.GetOSSigChannel()
	<-sig
	println("Got a signal to terminate the auto policy discovery")

	c.Stop() // Stop the scheduler (does not stop any jobs already running).
}
