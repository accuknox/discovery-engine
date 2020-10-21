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

# Usage

```
import (
  ...
	"github.com/accuknox/knoxAutoPolicy/core"
	"github.com/accuknox/knoxAutoPolicy/libs"
	"github.com/accuknox/knoxAutoPolicy/types"
  ...
)

func Generate() {
  // set target namespace
	targetNS := "default"

	// get network traffic from 'knoxServiceFlowMgmt'
	trafficList, _ := GetTrafficFlow()

	// 1. network traffic -> network log
	networkLogs := []types.NetworkLog{}
	for _, traffic := range trafficList {
		log := libs.TrafficToLog(traffic)
		networkLogs = append(networkLogs, log)
	}

	// 2. get k8s services
	services := libs.K8s.GetServices(targetNS)

	// 3. get pod information
	pods := libs.K8s.GetConGroups(targetNS)

	policies := core.GenerateNetworkPolicies(targetNS, 24, networkLogs, services, pods)
	for _, policy := range policies {
		// ciliumPolicy := libs.ToCiliumNetworkPolicy(policy) // if you want to convert it to Cilium policy
		b, _ := yaml.Marshal(&policy)
		fmt.Print(string(b))
		fmt.Println("---")
	}
}
```
