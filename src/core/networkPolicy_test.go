package core

import (
	"encoding/json"
	"testing"

	types "github.com/accuknox/knoxAutoPolicy/src/types"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
)

func TestGenerateNetworkPolicies(t *testing.T) {
	/*
		{
		    "src_namespace": "multiubuntu",
		    "src_pod_name": "ubuntu-1-deployment-5ff5974cd4-dfdgt",
		    "dst_namespace": "multiubuntu",
		    "dst_pod_name": "ubuntu-4-deployment-5bbd4f6c69-frhlk",
		    "protocol": 6,
		    "src_ip": "10.0.2.74",
		    "dst_ip": "10.0.1.55",
		    "src_port": 58404,
		    "dst_port": 8080,
		    "direction": "EGRESS",
		    "action": "allow"
		}
	*/
	logB := []byte("{\"src_namespace\":\"multiubuntu\",\"src_pod_name\":\"ubuntu-1-deployment-5ff5974cd4-dfdgt\",\"dst_namespace\":\"multiubuntu\",\"dst_pod_name\":\"ubuntu-4-deployment-5bbd4f6c69-frhlk\",\"protocol\":6,\"src_ip\":\"10.0.2.74\",\"dst_ip\":\"10.0.1.55\",\"src_port\":58404,\"dst_port\":8080,\"direction\":\"EGRESS\",\"action\":\"allow\"}")
	log := types.KnoxNetworkLog{}
	json.Unmarshal(logB, &log)
	logs := []types.KnoxNetworkLog{log}

	/*
		{
		    "namespace": "multiubuntu",
		    "service_name": "ubuntu-4-service",
		    "labels": [
		        "service=ubuntu-4"
		    ],
		    "type": "ClusterIP",
		    "protocol": "TCP",
		    "cluster_ip": "10.100.49.226",
		    "service_port": 8080,
		    "node_port": 0,
		    "container_port": 8080,
		    "selector": {
		        "container": "ubuntu-4",
		        "group": "group-2"
		    }
		}
	*/
	svc4 := []byte("{\"namespace\":\"multiubuntu\",\"service_name\":\"ubuntu-4-service\",\"labels\":[\"service=ubuntu-4\"],\"type\":\"ClusterIP\",\"protocol\":\"TCP\",\"cluster_ip\":\"10.100.49.226\",\"service_port\":8080,\"node_port\":0,\"container_port\":8080,\"selector\":{\"container\":\"ubuntu-4\",\"group\":\"group-2\"}}")
	svc := types.Service{}
	json.Unmarshal(svc4, &svc)
	svcs := []types.Service{svc}

	/*
		{
		    "namespace": "multiubuntu",
		    "pod_uid": "a7c68cb1-047a-49a7-91fe-adcf35df06c4",
		    "pod_name": "ubuntu-1-deployment-5ff5974cd4-dfdgt",
		    "host_id": "",
		    "host_name": "",
		    "host_ip": "",
		    "labels": [
		        "group=group-1",
		        "pod-template-hash=5ff5974cd4",
		        "container=ubuntu-1"
		    ],
		    "port_bindings": null
		}
	*/
	pod1B := []byte("{\"namespace\":\"multiubuntu\",\"pod_uid\":\"a7c68cb1-047a-49a7-91fe-adcf35df06c4\",\"pod_name\":\"ubuntu-1-deployment-5ff5974cd4-dfdgt\",\"host_id\":\"\",\"host_name\":\"\",\"host_ip\":\"\",\"labels\":[\"group=group-1\",\"pod-template-hash=5ff5974cd4\",\"container=ubuntu-1\"],\"port_bindings\":null}")
	group1 := types.Pod{}
	json.Unmarshal(pod1B, &group1)

	/*
		{
		    "namespace": "multiubuntu",
		    "pod_uid": "e34298dc-c912-43fe-9eeb-afc5dafdeef0",
		    "pod_name": "ubuntu-4-deployment-5bbd4f6c69-frhlk",
		    "host_id": "",
		    "host_name": "",
		    "host_ip": "",
		    "labels": [
		        "container=ubuntu-4",
		        "group=group-2",
		        "pod-template-hash=5bbd4f6c69"
		    ],
		    "port_bindings": null
		}
	*/
	pod4B := []byte("{\"namespace\":\"multiubuntu\",\"pod_uid\":\"e34298dc-c912-43fe-9eeb-afc5dafdeef0\",\"pod_name\":\"ubuntu-4-deployment-5bbd4f6c69-frhlk\",\"host_id\":\"\",\"host_name\":\"\",\"host_ip\":\"\",\"labels\":[\"container=ubuntu-4\",\"group=group-2\",\"pod-template-hash=5bbd4f6c69\"],\"port_bindings\":null}")
	group2 := types.Pod{}
	json.Unmarshal(pod4B, &group2)
	pods := []types.Pod{group1, group2}

	/* Egress Rule
	{
	    "selector": {
	        "matchLabels": {
	            "container": "ubuntu-1",
	            "group": "group-1"
	        }
	    },
	    "egress": [
	        {
	            "matchLabels": {
	                "container": "ubuntu-4",
	                "group": "group-2",
	                "k8s:io.kubernetes.pod.namespace": "multiubuntu"
	            },
	            "toPorts": [
	                {
	                    "ports": "8080",
	                    "protocol": "tcp"
	                }
	            ]
	        }
	    ],
	    "action": "allow"
	}
	*/
	spec1 := types.Spec{}
	expectedSpec1b := []byte("{\"selector\":{\"matchLabels\":{\"container\":\"ubuntu-1\",\"group\":\"group-1\"}},\"egress\":[{\"matchLabels\":{\"container\":\"ubuntu-4\",\"group\":\"group-2\",\"k8s:io.kubernetes.pod.namespace\":\"multiubuntu\"},\"toPorts\":[{\"ports\":\"8080\",\"protocol\":\"tcp\"}]}],\"action\":\"allow\"}")
	json.Unmarshal(expectedSpec1b, &spec1)

	/* Ingress Rule
	{
	    "selector": {
	        "matchLabels": {
	            "container": "ubuntu-4",
	            "group": "group-2"
	        }
	    },
	    "ingress": [
	        {
	            "matchLabels": {
	                "container": "ubuntu-1",
	                "group": "group-1",
	                "k8s:io.kubernetes.pod.namespace": "multiubuntu"
	            }
	        }
	    ],
	    "action": "allow"
	}
	*/
	spec2 := types.Spec{}
	expectedSpec2b := []byte("{\"selector\":{\"matchLabels\":{\"container\":\"ubuntu-4\",\"group\":\"group-2\"}},\"ingress\":[{\"matchLabels\":{\"container\":\"ubuntu-1\",\"group\":\"group-1\",\"k8s:io.kubernetes.pod.namespace\":\"multiubuntu\"}}],\"action\":\"allow\"}")
	json.Unmarshal(expectedSpec2b, &spec2)

	policies := DiscoverNetworkPolicies("multiubuntu", 24, logs, svcs, nil, pods)
	for i, policy := range policies {
		if i == 0 && cmp.Equal(spec1, policy.Spec) {
			assert.Equal(t, spec1, policy.Spec, "they should be equal")
		} else if i == 1 && cmp.Equal(spec2, policy.Spec) {
			assert.Equal(t, spec2, policy.Spec, "they should be equal")
		}
	}
}
