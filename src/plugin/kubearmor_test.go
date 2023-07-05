package plugin

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConvertMySQLKubeArmorLogsToKnoxSystemLogs(t *testing.T) {
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
		"component_name":"kubearmor"
	 }`

	dataBytes := []byte(kubearmor)
	doc := map[string]interface{}{}

	json.Unmarshal(dataBytes, &doc)

	results := ConvertMySQLKubeArmorLogsToKnoxSystemLogs([]map[string]interface{}{doc})
	assert.Equal(t, "fd=6", results[0].Data)
}

func TestConvertSQLiteKubeArmorLogsToKnoxSystemLogs(t *testing.T) {
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
                "component_name":"kubearmor"
         }`

	dataBytes := []byte(kubearmor)
	doc := map[string]interface{}{}

	json.Unmarshal(dataBytes, &doc)

	results := ConvertSQLiteKubeArmorLogsToKnoxSystemLogs([]map[string]interface{}{doc})
	assert.Equal(t, "fd=6", results[0].Data)
}
