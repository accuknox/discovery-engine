# knoxAutoPolicy
Auto Policy Generation

# Overview
![overview](http://seungsoo.net/autopolicy3.png)

# Directories

* Source code for Knox Auto Policy

```
build - build container image
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

# Configuration
```
# Database
knox_database:
  db_driver: "mysql"
  db_user: "root"
  db_pass: "password"
  db_name: "flow_management"
  db_table_network_flow: "network_flow"
  db_table_discovered_policy: "discovered_policy"

# Plug-in
plugin:
  input: "knox_database"
  output: "knox_policy" # 'knox_policy' or 'cilium policy'

# Policy
policy:
  cidr_bits: 24
  namespace: "default"
```

# Run 
```
# cd knoxAutoPolicy/src
# make
# ./knoxAutoPolicy -config=../config.yaml
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
	cfg := loadConfiguration()

	// get network traffic from  knox aggregation Databse
	trafficList, err := libs.GetTrafficFlowByTime(cfg, startTime, endTime)
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
		if cfg.Policy.Namespace != namespace {
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
		policies := core.GenerateNetworkPolicies(namespace, cfg.Policy.CidrBits, networkLogs, services, endpoints, pods)

		if len(policies) > 0 {
			// write discovered policies to files
			libs.WriteCiliumPolicyToFile(namespace, policies)

			// insert discovered policies to db
			libs.InsertDiscoveredPolicies(cfg, policies)
		}

		fmt.Println("policy discovery done for namespace: ", namespace, " ", len(policies))
	}
}
```

