# Knox Network Policy Specification

The specification of a knox network policy is as follow.

```
apiVersion: v1
kind:KnoxNetworkPolicy

metadata:
  name: [policy name]
  namespace: [namespace name]
  type: [egress|ingress]
  rule: [matchLabels|toPorts|toCIDRs|fromCIDRs|toEntities|fromEntities|toServices|toFQDNs|toHTTPs]
  status: [outdated|latest]
  
outdated: [overlapped policy name]
generatedTime: [unix time second]

spec:
  selector:
    matchLabels:
      [key1]: [value1]
      [keyN]: [valueN]  
      
  egress:
    - matchLabels:
        [key1]: [value1]
        [keyN]: [valueN]
        
      toPorts:
      - port: [port number]
        protocol: [protocol]
        
      toCIDRs:
      - cidrs:
        - [ip addr]/[cidr bits]
        
      toEntities:
      - [entity]
      
      toServices:
      - serviceName: [service name]
        namespace: [namespace]
        
      toFQDNs:
      - matchNames:
        - [domain name]
        
      toHTTPs:
      - method: [http method]
        path: [http path]
        aggregated: [true/false]
        
  ingress:
    - matchLabels:
        [key1]: [value1]
        [keyN]: [valueN]
        
      toPorts:
      - port: [port number]
        protocol: [protocol]
      
      toHTTPs:
      - method: [http method]
        path: [http path]
        aggregated: [true/false]
        
      fromCIDRs:
      - cidrs:
        - [ip addr]/[cidr bits]
        
      fromEntities:
      - [entity]
        
  action: [allow|deny]
```

# Policy Spec Description

Here, we will briefly explain how to define the knox network policy.

- Base

    The knox network policy starts with base information such as apiVersion, kind, metadata, outdated, and generatedTime. The apiVersion and kind would be the same in any network policies.
    
    In the case of metadata, we show the discovered policy name (in general, it's a random string) and the name of a namespace where it will be applied to. In addition, we specify which type of this policy; egress/ingress, and its rule. The toPorts rule can be a combination with other rules. Lastly, the status means whether the policy is the latest one or outdated.
    
    The outdated field points to the overlapped policy name when it becomes the outdated status, and the generatedTime means when the policy is built based on the unix seconds.
    
    ```
    apiVersion: v1
    kind:KnoxNetworkPolicy
    metadata:
      name: [policy name]
      namespace: [namespace name]
      type: [egress|ingress]
      rule: [matchLabels|toPorts|toCIDRs|fromCIDRs|toEntities|fromEntities|toServices|toFQDNs|toHTTPs]
      status: [outdated|latest]
    outdated: [overlapped policy name]
    generatedTime: [unix time second]
    ```
    
- Selector

    The selector part is relatively straightforward. Similar to other Kubernetes configurations, you can specify target pods based on labels.
    
    ```
    selector:
      matchLabels:
        [key1]: [value1]
        [keyN]: [valueN]
     ```
     
 - Egress
 
    In the egress rule, we have 7 different types. First, matchLabels is the same as the selector case, so we can specify the destination pods based on the labels, which should include the namespace as well.
    
    ToPorts is a list of the port filter, and the port and protocol mean the port number and its protocol respectively. In the case of the protocol, TCP, UDP, and SCTP can be supported. In addition, toPorts should be combined with other rules. For example, matchLabels+toPorts, toCIDRs+toPorts, toFQDNs+toPorts, and matchLabels+toPorts+toHTTPs.
    
    ToCIDR rules are used to define policies to limit external access to a particular IP range. And with ToPorts rules, it can restrict the external IP addresses in a fine-grained manner.
    
    ToEntities rules are used to describe the entities that can be accessed by the selector. But, it can be used in Cilium-based CNI only. The applicable entities are host (the local host), remote-node (other hosts in the cluster than the local host), and world (the same as CIDR 0.0.0.0/0).
    
    ToServices rules can be used to restrict access to the service running in the cluster. But, these services should not use the selector. In other words, it supports the services without the selector only. Thus, if users want to use ToServices rules, there should be the service and its endpoints respectively.
    
    ToFQDNs rules are used to define the policies that have DNS queryable domain names. For now, multiple distinct names may be included in separate matchName entries.
    
    ToHTTPs rules are composed of the method and path of the HTTP protocol. If the method is omitted or empty, all methods are allowed. And in general, ToHTTPs are used with matchLabels and ToPorts rules. If paths are aggregated, the aggregate boolean value is set to true.
 
    ```
    egress:
    - matchLabels:
        [key1]: [value1]
        [keyN]: [valueN]
      toPorts:
      - port: [port number]
        protocol: [protocol]
      toCIDRs:
      - cidrs:
        - [ip addr]/[cidr bits]
        except:
        - [ip addr]/[cidr bits]
      toEntities:
      - [entity]
      toServices:
      - service_name: [service name]
        namespace: [namespace]
      toFQDNs:
      - matchNames:
        - [domain name]
      toHTTPs:
      - method: [http method]
        path: [http path]
        aggregated: [true/false]
    ```
    
- Ingress

    In the ingress rule, we have 4 different types; matchLables, toPorts, fromCIDRs, fromEntities. And these are working as the egress does. ToPorts rules in the ingress mean the destination port information that the selector exposes.
    
    ```
    ingress:
    - matchLabels:
        [key1]: [value1]
        [keyN]: [valueN]        
      toPorts:
      - port: [port number]
        protocol: [protocol]        
      fromCIDRs:
      - cidrs:
        - [ip addr]/[cidr bits]
        except:
        - [ip addr]/[cidr bits]        
      fromEntities:
      - [entity]
    ```
    
- Action

    Actions can be allow and deny, but for now, the knoxAutoPolicy supports only allow policy.
