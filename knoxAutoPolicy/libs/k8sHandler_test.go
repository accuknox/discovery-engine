package libs

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetK8sNamespaces(t *testing.T) {
	actual := GetNamespaces()

	assert.NotContains(t, actual, "kube-system")
}

func TestGetConGroups(t *testing.T) {
	actual := GetPods()

	for _, pod := range actual {
		if pod.PodName == "" {
			t.Errorf("it should have a pod name")
		}
	}
}

func TestGetServices(t *testing.T) {
	actual := GetServices()

	for _, svc := range actual {
		if svc.ServiceName == "" {
			t.Errorf("it should have a service name")
		}
	}
}

func TestGetEndpoints(t *testing.T) {
	actual := GetEndpoints()

	for _, endpoint := range actual {
		if endpoint.EndpointName == "" {
			t.Errorf("it should have a endpoint name")
		}
	}
}
