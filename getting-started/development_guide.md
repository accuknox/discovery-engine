# Development Guide

## Code Directories

Here, we briefly give you an overview of KnoxAutoPolicy's directories.

* Source code for KnoxAutoPolicy
```
src/
  build         - Build scripts for knoxAutoPolicy image
  cluster       - Cluster handling functions for getting k8s resources
  conf          - .yaml files for the local configuration
  config        - Configuration handling functions for dynamically managing the configuration values
  feedconsumer  - Feed consumer functions for getting the logs from knox feeder services
  libs          - Libraries used for managing the database functions
  logging       - Logging functions for KnoxAutoPolicy
  networkpolicy - Network policy discovery functions
  plugin        - Plug-ins used for supporting CNIs and system policy enforcement system (e.g., Cilium, KubeArmor)
  protobuf      - ProtoBuf definitions for gRPC server
  server        - gRPC server implementation
  systempolicy  - System policy discovery functions
  types         - Type definitions
```

* Deployemnt
```
deployments/k8s  - .yaml files for deploying KnoxAutoPolicy service
```

* Documents
```
getting-started/ - Docuemnts files for explaining KnoxAutoPolicy service
```

* CI/CD
```
helm/            - helm files for CI/CD pipeline process
```

* Onboarding
```
onboarding/     - script files for checking the environments
```

* Resource
```
resource/       - .yaml file for building KnoxAutoPolicy image
```

* Scripts for executing knoxAutoPolicy
```
scripts/        - Script files for running knoxAutoPolicy service
```

* Files for testing
```
tests/
  multi-ubuntu  - Example microservices for testing
  unit-tests    - Automated unit test framework for knoxAutoPolicy
```

## Setting up dev env

Assuming you have the knoxAutoPolicy repo checked out.
Setup Cilium env in minikube or in k8s-VMs. Ensure following:

#### Ensure Hubble relay service is enabled and port-forwarding is enabled on the host
```
$ kubectl -n kube-system port-forward service/hubble-relay --address 0.0.0.0 --address :: 4245:80
```

#### Setup mysql
```
$ cd tests/mysql
$ docker-compose -f docker-compose.yml up
```

#### Compile knoxAutoPolicy
```
$ cd src
$ make
```
This should generate the binary `knoxAutoPolicy` in the src folder.

#### Update configuration
Edit `src/conf/local.yaml` to ensure that:
* `cilium-hubble: url` address is set to the localhost and port is set to 4245
* `network-log-from: "hubble"` is set
* `cluster-info-from: "k8sclient"` is set
Note that this must already be set to these values by default.

#### Execute knoxAutoPolicy
```
$ ./scripts/start_service.sh
```

#### Trigger policy discovery
```
$ ./scripts/start_net_worker.sh
```
