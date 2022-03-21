# Discovery Engine

Discovery Engine discovers the security posture for your workloads and auto-discovers the policy-set required to put the workload in least-permissive mode.
The engine leverages the rich visibility provided by [KubeArmor](https://github.com/kubearmor/kubearmor) and [Cilium](https://github.com/cilium/cilium) to auto discover the systems and network security posture.

<p align="center"> <img src="./getting-started/resources/policy-discovery.png" width="75%"/> </p>

# Getting Started Guide

<p align="center"> <img src="./getting-started/resources/k8s-auto-disco.png" width="75%"/> </p>

## Quick Install

### Install
```
curl -s https://raw.githubusercontent.com/accuknox/tools/main/install.sh | bash
```
If Cilium or KubeArmor is already installed in `kube-system` namespace then the corresponding installation is skipped.

### Get discovered policies
```
curl -s https://raw.githubusercontent.com/accuknox/tools/main/get_discovered_yamls.sh | bash
```

### Uninstall
```
curl -s https://raw.githubusercontent.com/accuknox/tools/main/uninstall.sh | bash
```

[Original Ref](https://help.accuknox.com/open-source/quick_start_guide/)

<details> <summary>Install/Uninstall (option 2) </summary>

### Install
Assumes that KubeArmor + Cilium is already installed in the k8s cluster in the `kube-system` namespace.
```
helm install --wait mysql bitnami/mysql --version 8.6.1 \
		--namespace explorer --set auth.user="test-user" --set auth.password="password" \
		--set auth.rootPassword="password" --set auth.database="knoxautopolicy"

kubectl apply -f deployments/k8s/ --namespace explorer
```
Note that the namespace and the DB parameters are set based on above values in the default config. If you change any parameter please ensure to change in [deployments/k8s/dev-config.yaml](deployments/k8s/dev-config.yaml) file as well before deploying.

### Get the discovered policies
```
curl -s https://raw.githubusercontent.com/accuknox/tools/main/get_discovered_yamls.sh | bash
```

### Uninstall
```
helm uninstall mysql --namespace explorer
kubectl delete -f deployments/k8s/ --namespace explorer
```
</details>

### Want to do more with the discovered policies?

The discovered policies contains the execution posture for your workloads. You can use these policies to check what the workloads are doing. Check [this guide](getting-started/filter_and_vis.md) to know more.

### Others
1. [Detailed functionality overview](getting-started/detailed_overview.md)
1. [Types of policies discovered](getting-started/detailed_overview.md#types-of-policies-discovered-by-the-engine)

