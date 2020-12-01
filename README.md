# knoxAutoPolicy
Auto Policy Generation


# Overview
![overview](http://seungsoo.net/autopolicy4.png)

# Directories

* Source code for Knox Auto Policy

```
build - build container image
database - mongodb container for local test
deployments - deployment file for kubenetes
policies - discovered policies (.yaml)
scripts - shell script to start program with environment variables
src - source codes
  core - Core functions for Knox Auto Policy
  libs - Libraries used for generating network policies
  plugin - Plug-ins used for supporting various CNIs (currently, Cilium)
  types - Type definitions
```

# Setup Instructions
```
git clone https://github.com/accuknox/knoxServicePolicy.git
cd knoxAutoPolicy
git submodule update --init --recursive
make -C common
```

# Installation

```
go get github.com/accuknox/knoxAutoPolicy
```

# Start script
```
#!/bin/bash

KNOX_AUTO_HOME=`dirname $(realpath "$0")`/..

DB_DRIVER=mongodb
DB_PORT=27017
DB_USER=root
DB_PASS=password
DB_NAME=flow_management

COL_NETWORK_FLOW=network_flow
COL_DISCOVERED_POLICY=discovered_policy

OUT_DIR=$KNOX_AUTO_HOME/policies/

DB_DRIVER=$DB_DRIVER DB_PORT=$DB_PORT DB_USER=$DB_USER DB_PASS=$DB_PASS DB_NAME=$DB_NAME COL_NETWORK_FLOW=$COL_NETWORK_FLOW COL_DISCOVERED_POLICY=$COL_DISCOVERED_POLICY OUT_DIR=$OUT_DIR $KNOX_AUTO_HOME/src/knoxAutoPolicy
```

# Run 
```
$ cd knoxAutoPolicy
$ ./scripts/startKnoxAutoPolicy.sh
```

# Main Code 

```
func StartToDiscoverNetworkPolicies() {
	// get network traffic from  knox aggregation Databse
	docs, err := libs.GetTrafficFlowFromMongo(startTime, endTime)
	if err != nil {
		log.Err(err)
		return
	}

	if len(docs) < 1 {
		log.Info().Msgf("Traffic flow is not exist: %s ~ %s",
			time.Unix(startTime, 0).Format(libs.TimeFormSimple),
			time.Unix(endTime, 0).Format(libs.TimeFormSimple))

		endTime = time.Now().Unix()
		return
	}

	log.Info().Msgf("the total number of traffic flow from db: [%d]", len(docs))

	updateTimeInterval(docs[len(docs)-1])

	// get k8s services
	services := libs.GetServices()

	// get k8s endpoints
	endpoints := libs.GetEndpoints()

	// get all the namespaces from k8s
	namespaces := libs.GetNamespaces()

	// iterate each namespace
	for _, namespace := range namespaces {
		if namespace == "kube-system" {
			continue
		}

		// convert cilium network traffic -> network log, and filter traffic
		networkLogs := plugin.ConvertCiliumFlowsToKnoxLogs(namespace, docs)
		if len(networkLogs) == 0 {
			continue
		}

		log.Info().Msgf("policy discovery started for namespace: [%s]", namespace)

		// get pod information
		pods := libs.GetPods(namespace)

		// discover network policies
		discoveredPolicies := DiscoverNetworkPolicies(namespace, cidrBits, networkLogs, services, endpoints, pods)

		// get existing policies in db
		existingPolicies, _ := libs.GetNetworkPolicies()

		// remove duplication
		newPolicies := DeduplicatePolicies(existingPolicies, discoveredPolicies)

		if len(newPolicies) > 0 {
			// insert discovered policies to db
			libs.InsertPoliciesToMongoDB(newPolicies)

			// write discovered policies to files
			libs.WriteCiliumPolicyToYamlFile(namespace, newPolicies)

			log.Info().Msgf("policy discovery done for namespace: [%s], [%d] policies discovered", namespace, len(newPolicies))
		} else {
			log.Info().Msgf("policy discovery done for namespace: [%s], no policy discovered", namespace)
		}
	}
}
```

