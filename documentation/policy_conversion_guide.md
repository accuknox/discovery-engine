# Policy Conversion Guide

### KnoxNetworkPolicy --> CiliumNetworkPolicy

1. Selector

|KnoxNetworkPolicy|CiliumNetworkPolicy|
|-----------------|-------------------|
|<pre>spec:<br />  selector:<br />    matchLabels:<br />      [key1]: [value1]<br />      [keyN]: [valueN]</pre>|<pre>spec:<br />  endpointSelector:<br />    matchLabels:<br />      [key1]: [value1]<br />      [keyN]: [valueN]</pre>|


2. Egress

- matchLabel
   
|KnoxNetworkPolicy|CiliumNetworkPolicy|
|-----------------|-------------------|
|<pre>egress:<br />  - matchLabels:<br />      [key1]: [value1]<br />      [keyN]: [valueN]</pre>|<pre>egress:<br />- toEndpoints:<br />  - matchLabels:<br />      [key1]: [value1]<br />      [keyN]: [valueN]</pre>|

- toPorts

|KnoxNetworkPolicy|CiliumNetworkPolicy|
|-----------------|-------------------|
|<pre>egress:<br />  - toPorts:<br />    - port: [port number]<br />      protocol: [protocol]</pre>|<pre>egress:<br />  - toPorts:<br />    - ports:<br />      - port: [port number]<br />        protocol: [protocol]</pre>|

- toCIDRs

|KnoxNetworkPolicy|CiliumNetworkPolicy|
|-----------------|-------------------|
|<pre>egress:<br />  - toCIDRs:<br />    - cidrs:<br />      - [ip addr]/[cidr bits]</pre>|<pre>egress:<br />- toCIDR:<br />  - [ip addr]/[cidr bits]</pre>|

- toEntities (the same)

|KnoxNetworkPolicy|CiliumNetworkPolicy|
|-----------------|-------------------|
|<pre>egress:<br />  - toEntities:<br />    - [entity]</pre>|<pre>egress:<br />  - toEntities:<br />    - [entity]</pre>|

- toServices

|KnoxNetworkPolicy|CiliumNetworkPolicy|
|-----------------|-------------------|
|<pre>egress:<br />  - toServices:<br />    - serviceName: [service name]<br />      namespace: [namespace]</pre>|<pre>egress:<br />- toServices:<br />  - k8sService:<br />      serviceName: [service name]<br />      namespace: [namespace]</pre>|

- toFQDNs: **to enforce 'toFQDNs' rule in Cilium, we need to have the toEndpoints rule for kube-dns as well**

|KnoxNetworkPolicy|CiliumNetworkPolicy|
|-----------------|-------------------|
|<pre>egress:<br />  - toFQDNs:<br />    - matchNames:<br />      - [domain name]</pre>|<pre>egress:<br />  - toEndpoints:<br />    - matchLabels:<br />        "k8s:io.kubernetes.pod.namespace": kube-system<br />        "k8s:k8s-app": kube-dns<br />    toPorts:<br />      - ports:<br />         - port: "53"<br />           protocol: ANY<br />        rules:<br />          dns:<br />            - matchPattern: "*"<br />  - toFQDNs:<br />      - matchName: [domain name]</pre>|

- toHTTPs **to enforce 'toHTTPs' rule in Cilium, 'toPorts' rule should be defined together, and toHTTPs resides in its inner rules**

|KnoxNetworkPolicy|CiliumNetworkPolicy|
|-----------------|-------------------|
|<pre>egress:<br />  - toPorts:<br />    - port: [port number]<br />      protocol: [protocol]<br />    toHTTPs:<br />    - method: [http method]<br />      path: [http path]</pre>|<pre>egress:<br />  - toPorts:<br />    - ports:<br />      - port: [port number]<br />        protocol: [protocol]<br />      rules:<br />        http:<br />        - method: [http method]<br />          path: [http path]
</pre>|

3. Ingress

- matchLabel
   
|KnoxNetworkPolicy|CiliumNetworkPolicy|
|-----------------|-------------------|
|<pre>egress:<br />  - matchLabels:<br />      [key1]: [value1]<br />      [keyN]: [valueN]</pre>|<pre>egress:<br />- fromEndpoints:<br />  - matchLabels:<br />      [key1]: [value1]<br />      [keyN]: [valueN]</pre>|

- fromCIDRs

|KnoxNetworkPolicy|CiliumNetworkPolicy|
|-----------------|-------------------|
|<pre>egress:<br />  - fromCIDRs:<br />    - cidrs:<br />      - [ip addr]/[cidr bits]</pre>|<pre>egress:<br />- fromCIDR:<br />  - [ip addr]/[cidr bits]</pre>|

- fromEntities (the same)

|KnoxNetworkPolicy|CiliumNetworkPolicy|
|-----------------|-------------------|
|<pre>egress:<br />  - fromEntities:<br />    - [entity]</pre>|<pre>egress:<br />  - fromEntities:<br />    - [entity]</pre>|

- toPorts and toHTTPs rules are the same as the egress
