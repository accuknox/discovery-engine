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
