#!/usr/bin/env python3

import sys
import yaml

actual = []
expected = []

# toPorts of kube-dns may be different from each cluster setting, so delete it
def delete_port_in_kube_dns(policy):
    if 'egress' in policy['spec']:
        for rule in policy['spec']['egress']:
            if 'toEndpoints' in rule and 'matchLabels' in rule['toEndpoints'][0]:
                if 'k8s-app' in rule['toEndpoints'][0]['matchLabels']:
                    if rule['toEndpoints'][0]['matchLabels']['k8s-app'] == 'kube-dns':
                        if 'ports' in rule['toPorts'][0]:
                            del rule['toPorts'][0]['ports']
    return policy

# python3 diff.py [actual policy path] [expected policy path]
if len(sys.argv) != 3:
    print("Incorrect arguments: python3 diff.py [actual policy path] [expected policy path]")
    sys.exit(1)

actual_f = sys.argv[1]
expected_f = sys.argv[2]

# load actually discovered policies
with open(actual_f) as f:
    docs = list(yaml.safe_load_all(f))
    for doc in docs:
        if doc is not None:
            doc['metadata']['name'] ='' # name clear
            actual.append(doc)
f.close()

# load policies expected to be discovered
with open(expected_f) as f:
    docs = list(yaml.safe_load_all(f))
    for doc in docs:
        if doc is not None:
            doc['metadata']['name'] ='' # name clear
            expected.append(doc)
f.close()

# check the expeceted policy exist in the actual ones
for e in expected:
    exist = False
    e = delete_port_in_kube_dns(e)

    for a in actual:
        a = delete_port_in_kube_dns(a)

        if e == a:
            exist = True

    if not exist:
        sys.exit(1) # if not exist, exit by err code 1
