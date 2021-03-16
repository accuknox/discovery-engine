#!/usr/bin/env python3

import sys
import yaml

actual = []
expected = []

if len(sys.argv) != 3:
    print("Incorrect arguments")
    sys.exit(1)

actual_f = sys.argv[1]
expected_f = sys.argv[2]

actual_f = '/home/sslee/knoxAutoPolicy/policies/cilium_policies_multiubuntu.yaml'
expected_f = '/home/sslee/knoxAutoPolicy/tests/multi-ubuntu/automation-tests/policies/TC_01_egress_matchLabels_toPorts_singlePort.yaml'

with open(actual_f) as f:
    docs = list(yaml.safe_load_all(f))
    for doc in docs:
        if doc is not None:
            doc['metadata']['name'] ='' # name clear
            actual.append(doc)
f.close()

with open(expected_f) as f:
    docs = list(yaml.safe_load_all(f))
    for doc in docs:
        if doc is not None:
            doc['metadata']['name'] ='' # name clear
            expected.append(doc)
f.close()

for e in expected:
    exist = False

    for a in actual:
        if e == a:
            exist = True

    if not exist:
        sys.exit(1) # if not exist, exit by err code 1
