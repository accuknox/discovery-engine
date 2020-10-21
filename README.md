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
	// define target namespace
	targetNamespace := "default"

	// 1. get network traffic from  knox aggregation Databse
	trafficList, _ := GetTrafficFlow()

	// 2. convert network traffic -> network log
	networkLogs := libs.ConvertTrafficToLogs(trafficList)

	// 3. get k8s services
	services := libs.K8s.GetServices(targetNamespace)

	// 4. get pod information
	pods := libs.K8s.GetConGroups(targetNamespace)

	// 5. generate network policies
	policies := core.GenerateNetworkPolicies(targetNamespace, 24, networkLogs, services, pods)
	for _, policy := range policies {
		// ciliumPolicy := libs.ToCiliumNetworkPolicy(policy) // if you want to convert it to Cilium policy
		b, _ := yaml.Marshal(&policy)
		fmt.Print(string(b))
		fmt.Println("---")
	}
}
```
