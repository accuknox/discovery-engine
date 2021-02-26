# Development Guide

## Code Directories

Here, we briefly give you an overview of KnoxAutoPolicy's directories.

* Source code for KnoxAutoPolicy \(/knoxAutoPolicy\)

```
knoxAutoPolicy/
  build         - Build scripts for knoxAutoPolicy image
  core          - Core functions for Knox Auto Policy
  libs          - Libraries used for generating network policies
  plugin        - Plug-ins used for supporting various CNIs (currently, Cilium)
  protobuf      - ProtoBuf definitions for gRPC server
  server        - gRPC server implementation
  types         - Type definitions
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
