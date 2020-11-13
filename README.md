# knoxAutoPolicy
Auto Policy Generation

# Overview
![overview](http://seungsoo.net/autopolicy3.png)

# Directories

* Source code for Knox Auto Policy

```
bin - shell script to start program with environment variables
build - build container image
database - mongodb container
deployments - deployment file for kubenetes
policies - example policies (.yaml)
src - source codes
  core - Core functions for Knox Auto Policy
  libs - Libraries used for generating network policies
  types - Type definitions
```

# Installation

```
go get github.com/accuknox/knoxAutoPolicy
```

# Start script
```
#!/bin/bash

KNOX_AUTO_HOME=`dirname $(realpath "$0")`/..

DB_DRIVER=mysql
DB_PORT=27017
DB_USER=root
DB_PASS=password
DB_NAME=flow_management

COL_NETWORK_FLOW=network_flow
COL_DISCOVERED_POLICY=discovered_policy

$KNOX_AUTO_HOME/src/knoxAutoPolicy
```

# Run 
```
$ cd knoxAutoPolicy
$ ./bin/startKnoxAutoPolicy.sh
```

# Main Code 

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

	// time filter update for next interval
	startTime = trafficList[len(trafficList)-1].TrafficFlow.Time + 1
	endTime = time.Now().Unix()

	fmt.Println("the total number of traffic flow from db: ", len(trafficList))

	// get all the namespaces from k8s
	namespaces := libs.K8s.GetK8sNamespaces()
	for _, namespace := range namespaces {
		if namespace != targetNamespace {
			continue
		}

		fmt.Println("policy discovery started for namespace: ", namespace)

		// convert network traffic -> network log, and filter traffic
		networkLogs := libs.ConvertTrafficFlowToLogs(namespace, trafficList)

		// get k8s services
		services := libs.K8s.GetServices(namespace)

		// get k8s endpoints
		endpoints := libs.K8s.GetEndpoints(namespace)

		// get pod information
		pods := libs.K8s.GetConGroups(namespace)

		// generate network policies
		policies := core.GenerateNetworkPolicies(namespace, cidrBits, networkLogs, services, endpoints, pods)

		if len(policies) > 0 {
			// write discovered policies to files
			libs.WriteCiliumPolicyToFile(namespace, policies)

			// insert discovered policies to db
			libs.InsertDiscoveredPoliciesToMongoDB(policies)
		}

		fmt.Println("policy discovery done for namespace: ", namespace, " ", len(policies))
	}
}
```

