# Deployment Guide

1. Setup Instructions
```
$ git clone https://github.com/accuknox/knoxAutoPolicy.git
$ cd knoxAutoPolicy
$ git submodule update --init --recursive
$ make -C common
```

2. Installation
```
$ cd src
& make 
```

3. Run KnoxAutoPolicy

- scripts/start.sh has the environment variables as follow.

```
#!/bin/bash

export KNOX_AUTO_HOME=`dirname $(realpath "$0")`/..

export DB_DRIVER=mysql
export DB_PORT=3306
export DB_USER=root
export DB_PASS=password
export DB_NAME=flow_management
export DB_HOST=127.0.0.1

export COL_NETWORK_FLOW=network_flow
export COL_DISCOVERED_POLICY=discovered_policy

export OUT_DIR=$KNOX_AUTO_HOME/policies/

export DISCOVERY_MODE=egressingress

$KNOX_AUTO_HOME/src/knoxAutoPolicy
```

- run the script file
    
```
$ cd knoxAutoPolicy
$ ./scripts/startService.sh
```

# Main Code 

```
func StartToDiscoverNetworkPolicies() {
	log.Info().Msg("Get network traffic from the database")

	flows, valid := libs.GetTrafficFlowFromDB()
	if !valid {
		return
	}

	// convert db flows -> cilium flows
	ciliumFlows := plugin.ConvertDocsToCiliumFlows(flows)

	// get k8s services
	services := libs.GetServices()

	// get k8s endpoints
	endpoints := libs.GetEndpoints()

	// get k8s pods
	pods := libs.GetPods()

	// get k8s namespaces
	namespaces := libs.GetNamespaces()

	// get existing policies in db
	existingPolicies, err := libs.GetNetworkPolicies("", "latest")
	if err != nil {
		log.Error().Msg(err.Error())
		return
	}

	// update exposed ports (k8s service, docker-compose portbinding)
	updateServiceEndpoint(services, endpoints, pods)

	// update DNS to IPs
	updateDNSToIPs(ciliumFlows, DNSToIPs)

	// iterate each namespace
	for _, namespace := range namespaces {
		// convert cilium network traffic -> network log, and filter traffic
		networkLogs := plugin.ConvertCiliumFlowsToKnoxLogs(namespace, ciliumFlows, DNSToIPs)
		if len(networkLogs) == 0 {
			continue
		}

		log.Info().Msgf("Policy discovery started for namespace: [%s]", namespace)

		// discover network policies based on the network logs
		discoveredPolicies := DiscoverNetworkPolicies(namespace, cidrBits, networkLogs, services, endpoints, pods)

		// remove duplication
		newPolicies := DeduplicatePolicies(existingPolicies, discoveredPolicies, DNSToIPs)

		if len(newPolicies) > 0 {
			// insert discovered policies to db
			if err := libs.InsertDiscoveredPolicies(newPolicies); err != nil {
				log.Error().Msg(err.Error())
				continue
			}

			// retrieve policies from the db
			policies, _ := libs.GetNetworkPolicies(namespace, "latest")

			// write discovered policies to files
			libs.WriteKnoxPolicyToYamlFile(namespace, policies)

			log.Info().Msgf("Policy discovery done    for namespace: [%s], [%d] policies discovered", namespace, len(newPolicies))
		} else {
			log.Info().Msgf("Policy discovery done    for namespace: [%s], no policy discovered", namespace)
		}
	}
}
```

# Directories

* Source code for KnoxAutoPolicy

```
common - common sub modules
deployments - deployment file for kubenetes
policies - discovered policies (.yaml)
scripts - shell script to start program with environment variables
src - source codes
  core - Core functions for Knox Auto Policy
  libs - Libraries used for generating network policies
  plugin - Plug-ins used for supporting various CNIs (currently, Cilium)
  types - Type definitions
tools - unit test scripts
```

