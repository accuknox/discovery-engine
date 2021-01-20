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

# database info
export DB_DRIVER=mysql
export DB_PORT=3306
export DB_USER=root
export DB_PASS=password
export DB_NAME=flow_management
export DB_HOST=127.0.0.1

# table info
export TB_NETWORK_FLOW=network_flow
export TB_DISCOVERED_POLICY=discovered_policy

# output dir info
export OUT_DIR=$KNOX_AUTO_HOME/policies/

# available discovery modes: egress | ingress | egress+ingress
export DISCOVERY_MODE=egress+ingress

# available network log source: hubble | db
export NETWORK_LOG_FROM=hubble

# cilium hubble info (if connect to hubble directly)
export HUBBLE_URL=127.0.0.1
export HUBBLE_PORT=4245

# operation mode: c=cronjob | a=at once
if [ $# -eq 1 ]
  then
    export OPERATION_MODE=$1
fi

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
	ciliumFlows := []*flow.Flow{}

	if NetworkLogFrom == "db" {
		log.Info().Msg("Get network traffic from the database")

		results := libs.GetTrafficFlowFromDB()
		if len(results) == 0 {
			return
		}

		// convert db flows -> cilium flows
		ciliumFlows = plugin.ConvertDocsToCiliumFlows(results)
	} else if NetworkLogFrom == "hubble" { // from hubble directly
		log.Info().Msg("Get network traffic from the Cilium Hubble directly")

		results := plugin.GetCiliumFlowsFromHubble()
		if len(results) == 0 {
			return
		}

		ciliumFlows = results
	} else {
		log.Error().Msgf("Network log source not correct: %s", NetworkLogFrom)

		return
	}

	// get k8s services
	services := libs.GetServices()

	// get k8s endpoints
	endpoints := libs.GetEndpoints()

	// get k8s pods
	pods := libs.GetPods()

	// get k8s namespaces
	namespaces := libs.GetNamespaces()

	// get existing policies in db
	existingPolicies := libs.GetNetworkPolicies("", "latest")

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
			libs.InsertDiscoveredPolicies(newPolicies)

			// retrieve the latest policies from the db
			policies := libs.GetNetworkPolicies(namespace, "latest")

			// convert knoxPolicy to CiliumPolicy
			ciliumPolicies := plugin.ConvertKnoxPoliciesToCiliumPolicies(services, policies)

			// write discovered policies to files
			libs.WriteCiliumPolicyToYamlFile(namespace, ciliumPolicies)

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

