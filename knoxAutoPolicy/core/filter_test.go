package core

import (
	"encoding/json"
	"testing"

	types "github.com/accuknox/knoxAutoPolicy/src/types"
	"github.com/stretchr/testify/assert"
)

func TestFilterNetworkLogsByConfig(t *testing.T) {
	LoadDefaultConfig()

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
	podB := []byte("{\"namespace\":\"multiubuntu\",\"pod_uid\":\"a7c68cb1-047a-49a7-91fe-adcf35df06c4\",\"pod_name\":\"ubuntu-1-deployment-5ff5974cd4-dfdgt\",\"host_id\":\"\",\"host_name\":\"\",\"host_ip\":\"\",\"labels\":[\"group=group-1\",\"pod-template-hash=5ff5974cd4\",\"container=ubuntu-1\"],\"port_bindings\":null}")
	pod := types.Pod{}
	json.Unmarshal(podB, &pod)
	pods := []types.Pod{pod}

	results := FilterNetworkLogsByConfig(logs, pods)

	assert.Equal(t, results, logs)
}

func TestFilterNetworkLogsByNamespace(t *testing.T) {
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

	results := FilterNetworkLogsByNamespace("multiubuntu", logs)

	assert.Equal(t, results, logs)
}
