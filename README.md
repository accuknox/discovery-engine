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
	f, err := os.Create("./policies.yaml")
	if err != nil {
		fmt.Println(err)
	}
	defer f.Close()

	// define target namespace
	targetNamespace := "default"

	// get network traffic from  knox aggregation Databse
	trafficList, _ := libs.GetTrafficFlow()

	// convert network traffic -> network log
	networkLogs := libs.ConvertTrafficToLogs(trafficList)

	// get k8s services
	services := libs.K8s.GetServices(targetNamespace)

	// get pod information
	pods := libs.K8s.GetConGroups(targetNamespace)

	// 5. generate network policies
	policies := core.GenerateNetworkPolicies(targetNamespace, 24, networkLogs, services, pods)
	for _, policy := range policies {
		ciliumPolicy := libs.ToCiliumNetworkPolicy(policy) // if you want to convert it to Cilium policy
		// PrintSimplePolicy(ciliumPolicy)	// simple print in terminal
		b, _ := yaml.Marshal(&ciliumPolicy)
		f.Write(b)
		f.WriteString("---\n")
		f.Sync()
	}
}
```

