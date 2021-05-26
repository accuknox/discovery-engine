package feedconsumer

import (
	"bytes"
	"testing"

	types "github.com/accuknox/knoxAutoPolicy/src/types"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func initMockYaml() {
	viper.SetConfigType("yaml")
	viper.ReadConfig(bytes.NewBuffer(types.MockConfigYaml))
}

func TestProcessMessage(t *testing.T) {
	initMockYaml()

	var cilium string = `{
		"cluster_name":"accuknox-dev",
		"component_name":"cilium",
		"flow":{
		   "IP":{
			  "destination":"10.0.1.222",
			  "ipVersion":"IPv4",
			  "source":"10.0.6.227"
		   },
		   "Summary":"TCP Flags: ACK, PSH",
		   "Type":"L3_L4",
		   "destination":{
			  "identity":16498,
			  "labels":[
				 "k8s:app=elasticsearch",
				 "k8s:common.k8s.elastic.co/type=elasticsearch",
				 "k8s:elasticsearch.k8s.elastic.co/cluster-name=elasticsearch",
				 "k8s:elasticsearch.k8s.elastic.co/config-hash=4178477",
				 "k8s:elasticsearch.k8s.elastic.co/http-scheme=https",
				 "k8s:elasticsearch.k8s.elastic.co/node-data=true",
				 "k8s:elasticsearch.k8s.elastic.co/node-ingest=true",
				 "k8s:elasticsearch.k8s.elastic.co/node-master=true",
				 "k8s:elasticsearch.k8s.elastic.co/node-ml=true",
				 "k8s:elasticsearch.k8s.elastic.co/statefulset-name=elasticsearch-es-default",
				 "k8s:elasticsearch.k8s.elastic.co/version=7.8.0",
				 "k8s:io.cilium.k8s.policy.cluster=default",
				 "k8s:io.cilium.k8s.policy.serviceaccount=default",
				 "k8s:io.kubernetes.pod.namespace=default",
				 "k8s:statefulset.kubernetes.io/pod-name=elasticsearch-es-default-0"
			  ],
			  "namespace":"default",
			  "pod_name":"elasticsearch-es-default-0"
		   },
		   "ethernet":{
			  "destination":"62:67:e7:8c:09:79",
			  "source":"46:60:57:2c:8b:04"
		   },
		   "event_type":{
			  "sub_type":3,
			  "type":4
		   },
		   "l4":{
			  "TCP":{
				 "destination_port":9200,
				 "flags":{
					"ACK":true,
					"PSH":true
				 },
				 "source_port":39066
			  }
		   },
		   "node_name":"gke-accuknox-dev-knox-kafka-7fba650e-jg7n",
		   "source":{
			  "ID":1312,
			  "identity":18070,
			  "labels":[
				 "k8s:app=kibana",
				 "k8s:common.k8s.elastic.co/type=kibana",
				 "k8s:io.cilium.k8s.policy.cluster=default",
				 "k8s:io.cilium.k8s.policy.serviceaccount=default",
				 "k8s:io.kubernetes.pod.namespace=default",
				 "k8s:kibana.k8s.elastic.co/config-checksum=ce99fe9e80d43cc5a7c4f73f3124d91a24fa72c28883615decc00288",
				 "k8s:kibana.k8s.elastic.co/name=kibana",
				 "k8s:kibana.k8s.elastic.co/version=7.8.0"
			  ],
			  "namespace":"default",
			  "pod_name":"kibana-kb-6ff68f4bd-bkft6"
		   },
		   "time":"2021-03-22T04:25:00.169452145Z",
		   "trace_observation_point":"TO_STACK",
		   "traffic_direction":"EGRESS",
		   "verdict":"FORWARDED"
		},
		"node_name":"gke-accuknox-dev-knox-kafka-7fba650e-jg7n",
		"secret_key":"ZmVlZGVyLXNlcnZjaWU=",
		"tenant_id":"TVE9PQ==",
		"time":"2021-03-22T04:25:00.169452145Z"
	 }`

	dataBytes := []byte(cilium)
	consumer = &KnoxFeedsConsumer{}

	err := consumer.processNetworkLogMessage(dataBytes)
	assert.NoError(t, err)
}

func TestProcessSystemLogMessage(t *testing.T) {
	initMockYaml()

	var kubearmor string = `{
		"ContainerID":"78c4b0cb165d24e6ae4049fa2547507be26f7def6bf39a265b9360928a606e2a",
		"ContainerName":"k8s_server_recommendationservice-cb98b57c-6255h_default_57402aec-19ae-4119-a090-fa3d223cea11_745",
		"Data":"fd=6",
		"HostName":"gke-accuknox-dev-pool-1-deafdd21-3mng",
		"HostPID":1373474,
		"NamespaceName":"default",
		"Operation":"File",
		"PID":1385017,
		"PPID":1373459,
		"PodName":"recommendationservice-cb98b57c-6255h",
		"Resource":"SYS_CLOSE",
		"Result":"Bad file descriptor",
		"Source":"runc:[1:CHILD]",
		"Type":"SystemLog",
		"UpdatedTime":"2021-03-23T12:01:28.661031Z",
		"cluster_name":"accuknox-dev",
		"component_name":"kubearmor",
		"secret_key":"ZmVlZGVyLXNlcnZjaWU=",
		"tenant_id":"TVE9PQ=="
	 }`

	dataBytes := []byte(kubearmor)
	consumer = &KnoxFeedsConsumer{}

	err := consumer.processSystemLogMessage(dataBytes)
	assert.NoError(t, err)
}
