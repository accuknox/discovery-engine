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

- scripts/startService.sh has the environment variables as follow.

```
#!/bin/bash

export KNOX_AUTO_HOME=`dirname $(realpath "$0")`/..

# database info
export DB_DRIVER=mysql
export DB_HOST=127.0.0.1
export DB_PORT=3306
export DB_USER=root
export DB_PASS=password
export DB_NAME=flow_management

# database table info
export TB_NETWORK_FLOW=network_flow
export TB_DISCOVERED_POLICY=discovered_policy
export TB_CONFIGURATION=auto_policy_config

# cilium hubble info (if want to connect with hubble relay directly)
export HUBBLE_URL=127.0.0.1
export HUBBLE_PORT=4245

# operation mode: cronjob: 1
#                 onetime job: 2
export OPERATION_MODE=2
export CRON_JOB_TIME_INTERVAL="@every 0h0m5s"

# network log source: hubble | db
export NETWORK_LOG_FROM=db

# discovered policy output: db or db|file
export DISCOVERED_POLICY_TO="db|file"
export POLICY_DIR=$KNOX_AUTO_HOME/policies/

# discovery policy types: egress only   : 1
#                         ingress only  : 2
#                         all           : 3
export DISCOVERY_POLICY_TYPES=3

# discovery rule types: matchLabels: matchLabels: 1
#                                    toPorts    : 2
#                                    toHTTPs    : 4
#                                    toCIDRs    : 8
#                                    toEntities : 16
#                                    toServices : 32
#                                    toFQDNs    : 64
#                                    fromCIDRs  : 128
#                                    fromEntities : 256
#                                    all        : 511
export DISCOVERY_RULE_TYPES=511

# skip namepsace info
export IGNORING_NAMESPACES="kube-system|knox-auto-policy|cilium|hipster"

$KNOX_AUTO_HOME/src/knoxAutoPolicy
```

- run the script file
    
```
$ cd knoxAutoPolicy
$ ./scripts/startService.sh
```

# Main Code 

```
func StartToDiscoveryWorker() {
	// get network logs
	networkLogs := getNetworkLogs()
	if networkLogs == nil {
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

	// update exposed ports (k8s service, docker-compose portbinding)
	updateServiceEndpoint(services, endpoints, pods)

	// get existing policies in db
	existingPolicies := libs.GetNetworkPolicies(Cfg.ConfigDB, "", "")

	// filter ignoring network logs from configuration
	configFilteredLogs := FilterNetworkLogsByConfig(networkLogs, pods)

	// iterate each namespace
	for _, namespace := range namespaces {
		// skip uninterested namespaces
		if libs.ContainsElement(SkipNamespaces, namespace) {
			continue
		}

		// filter network logs by target namespace
		nsFilteredLogs := FilterNetworkLogsByNamespace(namespace, configFilteredLogs)
		if len(nsFilteredLogs) == 0 {
			continue
		}

		log.Info().Msgf("Policy discovery started for namespace: [%s]", namespace)

		// reset flow id track every target namespace
		resetTrackFlowID()

		// discover network policies based on the network logs
		discoveredPolicies := DiscoverNetworkPolicy(namespace, nsFilteredLogs, services, endpoints, pods)

		// remove duplicated policy
		newPolicies := RemoveDuplicatePolicy(existingPolicies, discoveredPolicies, DomainToIPs)

		if len(newPolicies) > 0 {
			// insert discovered policies to db
			libs.InsertDiscoveredPolicies(Cfg.ConfigDB, newPolicies)

			if strings.Contains(Cfg.DiscoveredPolicyTo, "file") {
				// retrieve the latest policies from the db
				latestPolicies := libs.GetNetworkPolicies(Cfg.ConfigDB, namespace, "latest")

				// write discovered policies to files
				libs.WriteKnoxPolicyToYamlFile(namespace, latestPolicies)

				// convert knoxPolicy to CiliumPolicy
				ciliumPolicies := plugin.ConvertKnoxPoliciesToCiliumPolicies(services, latestPolicies)

				// write discovered policies to files
				libs.WriteCiliumPolicyToYamlFile(namespace, ciliumPolicies)
			}

			log.Info().Msgf("Policy discovery done for namespace: [%s], [%d] policies discovered", namespace, len(newPolicies))
		} else {
			log.Info().Msgf("Policy discovery done for namespace: [%s], no policy discovered", namespace)
		}
	}

	if Cfg.OperationMode == 2 && Status == StatusRunning {
		Status = StatusIdle
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
  protos - ProtoBuf definitions for gRPC server
  server - gRPC server implementation
  types - Type definitions
tools - unit test scripts
```

