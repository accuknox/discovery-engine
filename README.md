# Auto Policy Discovery
Auto Policy Discovery discovers network and system policies based on the collected network and system logs respectively from the various container network interfaces (CNI) such as [Cilium](https://github.com/cilium/cilium/) and [KubeArmor](https://github.com/kubearmor/kubearmor).

Auto Policy Discovery operates as plug-ins because each CNI and CRSE employ their own scheme for the network log/policy and system log/policy. The engine discovers a generic policy (network log/policy and system log/policy) and then employs converter adapter to convert it to KubeArmorPolicy or CiliumNetworkPolicy. The aim is to minimize the dependency on CNI, CRSE specific quirks.

Auto Policy Discovery is designed for Kubernetes environments; it focuses on pods/services, and its fundamental principle is to produce a minimal network and system policy set covering maximum behavior. To do this, we actively use the label information assigned from the Kubernetes workloads/resources.

Currently, it can discover (i) egress/ingress network policy for Pod-to- Pod, (External)Service, Entity, CIDR, FQDN, HTTP. Further detail is available [here](./getting-started/knox_network_policy_specification.md). And, it can also discover (ii) process, file, and network-relevant system policy.



# Functionality Overview

* Produce a minimum network policy set covering maximum network flows

When discovering the network policies, if we generate the policies applied to a single pod statically, there would be lots of network policies. In contrast, this engine produces the minimum network policy set that can cover the maximum network flows so that we can manage the network policies more efficiently and effectively.
For example, the discovery engine collects the label information of the pods, and then computes the intersection of labels, which is included in the source (or destination) pods.

* Integrate with Cilium

* Identify overlapped network policy

Regarding the external destination, the discovery engine builds CIDR or FQDN-based policies, and to do this it takes two steps. First, if the engine comes across the external IP address as the destination, it tries to convert the IP address to the domain name by leveraging the reverse domain services. Next, if it fails to find the domain name, it retrieves the domain name from an internal map that matches the domain name to the IP address collected by DNS query and response packets from the kube-dns traffic. Thus, building FQDN based policies has a higher priority than CIDR policies.

Inevitably, CIDR policies could be discovered if there is no information on the matched domain names. However, if we build an FQDN policy that overlaps the prior CIDR policy, the discovery engine can tag and update those policies so that we can maintain the latest network policies.

* Operate in runtime or on the collected network logs in advance

Generally, the engine discovers the network policies by extracting the network logs from the database every time intervals. In addition, the engine can connect to a log monitor directly (e.g., Cilium Hubble), and receive the network log, and then produce the network policies in runtime.

* Support various network policy discovery modes

Fundamentally, a pod has two types of network policy in Kubernetes; egress and ingress. The egress policy restricts the outbound network flows and the other way, the ingress policy operates against the inbound network flows. In this context, the engine supports three different types of policy discovery modes; egress+ingress, ingress-centric, and egress-centric. Thus, users can choose one of them depending on their demand.

# Getting Started

Please take a look at the following documents.

1. [Deployment Guide](./getting-started/deployment_guide.md)
2. [Network Policy Specification](./getting-started/knox_network_policy_specification.md)
3. [Network Policy Discovery Examples](./getting-started/policy_discovery_examples.md)
4. [Development Guide](./getting-started/development_guide.md)

