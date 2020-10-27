# knoxAutoPolicy
Auto Policy Generation

# Overview
![overview](http://seungsoo.net/autopolicy.png)

# Directories

* Source code for Knox Auto Policy

```
core - Core functions for Knox Auto Policy
libs - Libraries used for generating network policies
types - Type definitions
```

# Installation

```
go get github.com/accuknox/knoxAutoPolicy
```

# Usage 1: Cron job daemon

* Assuming that it runs in the master node and the mysql database has network_flows

```
$ cd knoxAutoPolicy
$ go build
$ NETWORKFLOW_DB_DRIVER=mysql NETWORKFLOW_DB_USER=root NETWORKFLOW_DB_PASS=password NETWORKFLOW_DB_NAME=flow_management ./knoxAutoPolicy
```

# Usage 2: Library

```
import (
  ...
	"github.com/accuknox/knoxAutoPolicy/core"
	"github.com/accuknox/knoxAutoPolicy/libs"
	"github.com/accuknox/knoxAutoPolicy/types"
  ...
)

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
		for _, policy := range policies {
			// ciliumPolicy := libs.ToCiliumNetworkPolicy(policy)
			libs.InsertDiscoveredPolicy(policy)
		}

		fmt.Println("done generated policies for namespace: ", namespace, " ", len(policies))
	}
}
```

