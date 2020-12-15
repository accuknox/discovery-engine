package plugin

import (
	"encoding/json"
	"testing"

	"github.com/accuknox/knoxAutoPolicy/src/types"
	flow "github.com/cilium/cilium/api/v1/flow"
	"github.com/google/go-cmp/cmp"
)

func TestConvertCiliumFlowToKnoxLog(t *testing.T) {
	/*
		{
			"time": "2020-11-18T06:00:54.490913974Z",
			"verdict": "FORWARDED",
			"ethernet": {
				"source": "ee:b1:1c:70:84:15",
				"destination": "de:b5:f5:11:2b:5b"
			},
			"IP": {
				"source": "10.0.1.31",
				"destination": "10.0.1.144",
				"ipVersion": "IPv4"
			},
			"l4": {
				"TCP": {
					"source_port": 6379,
					"destination_port": 60416,
					"flags": {
						"FIN": true,
						"ACK": true
					}
				}
			},
			"source": {
				"ID": 51,
				"identity": 58574,
				"namespace": "default",
				"labels": [
					"k8s:app=redis-cart",
					"k8s:io.cilium.k8s.policy.cluster=default",
					"k8s:io.cilium.k8s.policy.serviceaccount=default",
					"k8s:io.kubernetes.pod.namespace=default"
				],
				"pod_name": "redis-cart-74594bd569-gw2xb"
			},
			"destination": {
				"identity": 1,
				"labels": [
					"reserved:host"
				]
			},
			"Type": "L3_L4",
			"node_name": "z100-n39",
			"reply": true,
			"event_type": {
				"type": 4,
				"sub_type": 3
			},
			"traffic_direction": "INGRESS",
			"trace_observation_point": "TO_STACK",
			"Summary": "TCP Flags: ACK, FIN"
		}
	*/
	flowBytes := []byte("{\"IP\":{\"destination\":\"10.0.1.144\",\"ipVersion\":\"IPv4\",\"source\":\"10.0.1.31\"},\"Summary\":\"TCP Flags: ACK, FIN\",\"Type\":\"L3_L4\",\"_id\":\"5fb4b896af8f91ae1dab8e13\",\"destination\":{\"identity\":1,\"labels\":[\"reserved:host\"]},\"ethernet\":{\"destination\":\"de:b5:f5:11:2b:5b\",\"source\":\"ee:b1:1c:70:84:15\"},\"event_type\":{\"sub_type\":3,\"type\":4},\"l4\":{\"TCP\":{\"destination_port\":60416,\"flags\":{\"ACK\":true,\"FIN\":true},\"source_port\":6379}},\"node_name\":\"z100-n39\",\"reply\":true,\"source\":{\"ID\":51,\"identity\":58574,\"labels\":[\"k8s:app=redis-cart\",\"k8s:io.cilium.k8s.policy.cluster=default\",\"k8s:io.cilium.k8s.policy.serviceaccount=default\",\"k8s:io.kubernetes.pod.namespace=default\"],\"namespace\":\"default\",\"pod_name\":\"redis-cart-74594bd569-gw2xb\"},\"time\":\"2020-11-18T06:00:54.490913974Z\",\"timestamp\":\"2020-11-18T06:00:54.49Z\",\"trace_observation_point\":\"TO_STACK\",\"traffic_direction\":\"INGRESS\",\"verdict\":\"FORWARDED\"}")

	/*
		{
			"src_namespace": "default",
			"src_pod_name": "redis-cart-74594bd569-gw2xb",
			"dst_namespace": "reserved:host",
			"dst_pod_name": "10.0.1.144",
			"protocol": 6,
			"src_ip": "10.0.1.31",
			"dst_ip": "10.0.1.144",
			"src_port": 6379,
			"dst_port": 60416,
			"direction": "INGRESS",
			"action": "allow"
		}
	*/
	logBytes := []byte("{\"src_namespace\":\"default\",\"src_pod_name\":\"redis-cart-74594bd569-gw2xb\",\"dst_namespace\":\"reserved:host\",\"dst_pod_name\":\"10.0.1.144\",\"protocol\":6,\"src_ip\":\"10.0.1.31\",\"dst_ip\":\"10.0.1.144\",\"src_port\":6379,\"dst_port\":60416,\"direction\":\"INGRESS\",\"action\":\"allow\"}")
	flow := &flow.Flow{}
	json.Unmarshal(flowBytes, flow)

	expected := &types.KnoxNetworkLog{}
	json.Unmarshal(logBytes, expected)

	dnsToIPs := map[string][]string{}

	actual, _ := ConvertCiliumFlowToKnoxLog(flow, dnsToIPs)
	if !cmp.Equal(*expected, actual) {
		t.Errorf("they should be equal %v %v", expected, actual)
	}
}

func TestConvertKnoxPolicyToCiliumPolicy(t *testing.T) {
	/*
		{
		    "apiVersion": "v1",
		    "kind": "KnoxNetworkPolicy",
		    "metadata": {
		        "name": "autogen-egress-lbzgbaicmr",
		        "namespace": "default"
		    },
		    "spec": {
		        "selector": {
		            "matchLabels": {
		                "app": "cartservice"
		            }
		        },
		        "egress": [
		            {
		                "matchLabels": {
		                    "app": "redis-cart",
		                    "k8s:io.kubernetes.pod.namespace": "default"
		                },
		                "toPorts": [
		                    {
		                        "port": "6379",
		                        "protocol": "tcp"
		                    }
		                ]
		            }
		        ],
		        "action": "allow"
		    },
		    "generated_time": 1605686921
		}
	*/
	knoxBytes := []byte("{\"apiVersion\":\"v1\",\"kind\":\"KnoxNetworkPolicy\",\"metadata\":{\"name\":\"autogen-egress-lbzgbaicmr\",\"namespace\":\"default\"},\"spec\":{\"selector\":{\"matchLabels\":{\"app\":\"cartservice\"}},\"egress\":[{\"matchLabels\":{\"app\":\"redis-cart\",\"k8s:io.kubernetes.pod.namespace\":\"default\"},\"toPorts\":[{\"port\":\"6379\",\"protocol\":\"tcp\"}]}],\"action\":\"allow\"},\"generated_time\":1605686921}")

	/*
		{
		    "apiVersion": "cilium.io/v2",
		    "kind": "CiliumNetworkPolicy",
		    "metadata": {
		        "name": "autogen-egress-lbzgbaicmr",
		        "namespace": "default"
		    },
		    "spec": {
		        "endpointSelector": {
		            "matchLabels": {
		                "app": "cartservice"
		            }
		        },
		        "egress": [
		            {
		                "toEndpoints": [
		                    {
		                        "matchLabels": {
		                            "app": "redis-cart",
		                            "k8s:io.kubernetes.pod.namespace": "default"
		                        }
		                    }
		                ],
		                "toPorts": [
		                    {
		                        "ports": [
		                            {
		                                "port": "6379",
		                                "protocol": "TCP"
		                            }
		                        ]
		                    }
		                ]
		            }
		        ]
		    }
		}
	*/
	ciliumBytes := []byte("{\"apiVersion\":\"cilium.io/v2\",\"kind\":\"CiliumNetworkPolicy\",\"metadata\":{\"name\":\"autogen-egress-lbzgbaicmr\",\"namespace\":\"default\"},\"spec\":{\"endpointSelector\":{\"matchLabels\":{\"app\":\"cartservice\"}},\"egress\":[{\"toEndpoints\":[{\"matchLabels\":{\"app\":\"redis-cart\",\"k8s:io.kubernetes.pod.namespace\":\"default\"}}],\"toPorts\":[{\"ports\":[{\"port\":\"6379\",\"protocol\":\"TCP\"}]}]}]}}")

	knoxPolicy := &types.KnoxNetworkPolicy{}
	json.Unmarshal(knoxBytes, knoxPolicy)

	expected := &types.CiliumNetworkPolicy{}
	json.Unmarshal(ciliumBytes, expected)

	svcs := []types.Service{}

	actual := ConvertKnoxPolicyToCiliumPolicy(svcs, *knoxPolicy)
	if !cmp.Equal(*expected, actual) {
		t.Errorf("they should be equal %v %v", expected, actual)
	}
}
