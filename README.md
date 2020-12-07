# KnoxAutoPolicy
KnoxAutoPolicy is a policy recommendation system that suggests network policies based on the collected network logs from the various container network interfaces (CNI) such as Cilium, Bastion, and Calico.

Basically, KnoxAutoPolicy operates as plug-ins because each CNI employs its own scheme for the network log and network policy. Thus, KnoxAutoPolicy can convert each scheme to Knox General Scheme (network log/policy) and vice versa. From these functionalities, we can minimize its dependency on each CNI.

KnoxAutoPolicy is designed for Kubernetes environments; it focuses on pod/services, and its fundamental principle is to produce a Minimal policy set covering maximum flows. To do this, we actively use the label information assigned from the Kubernetes resources.

Currently, KnoxAutoPolicy can discover egress/ingress network policy for Pod-to -Pod, -(External)Service, -Entity, -CIDR, -FQDN, -HTTP. Further detail is available here.

<center><img src=./documentation/resources/autopolicy_overview.png></center>

# Directories

* Source code for Knox Auto Policy

```
common - common sub modules
database - mongodb container for local test
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

# Setup Instructions
```
git clone https://github.com/accuknox/knoxAutoPolicy.git
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
$ ./scripts/startService.sh
```

# Main Code 

```
func StartToDiscoverNetworkPolicies() {
	endTime = time.Now().Unix()

	log.Info().Msg("Get network traffic from the database")
	docs, valid := libs.GetTrafficFlowFromMongo(startTime, endTime)
	if !valid {
		return
	}
	updateTimeInterval(docs[len(docs)-1])
	ciliumFlows := plugin.ConvertMongoDocsToCiliumFlows(docs)

	// get k8s services
	services := libs.GetServices()

	// get k8s endpoints
	endpoints := libs.GetEndpoints()

	// get k8s pods
	pods := libs.GetPods()

	// get k8s namespaces
	namespaces := libs.GetNamespaces()

	// get existing policies in db
	existingPolicies, _ := libs.GetNetworkPolicies()

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
			libs.InsertPoliciesToMongoDB(newPolicies)

			// convert knoxPolicy to CiliumPolicy
			ciliumPolicies := plugin.ConvertKnoxPoliciesToCiliumPolicies(services, newPolicies)

			// write discovered policies to files
			libs.WriteCiliumPolicyToYamlFile(namespace, services, ciliumPolicies)

			log.Info().Msgf("Policy discovery done    for namespace: [%s], [%d] policies discovered", namespace, len(newPolicies))
		} else {
			log.Info().Msgf("Policy discovery done    for namespace: [%s], no policy discovered", namespace)
		}
	}
}
```

