# Knox Network Policy Specification

Here is the specification of a knox network policy.

```
apiVersion: v1
kind:KnoxNetworkPolicy
metadata:
  name: [policy name]
  namespace: [namespace name]
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
      - ports: [port number]
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

  ingress:
    - matchLabels:
        [key1]: [value1]
        [keyN]: [valueN]
        
      toPorts:
      - ports: [port number]
        protocol: [protocol]
        
      fromCIDRs:
      - cidrs:
        - [ip addr]/[cidr bits]
        except:
        - [ip addr]/[cidr bits]
        
      fromEntities:
      - [entity]
      
      fromServices:
      - service_name: [service name]
        namespace: [namespace]
        
  action: [allow|deny]
  
generated_time: [unix time second]
```
