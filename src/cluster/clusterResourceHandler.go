package cluster

import (
	"errors"

	"github.com/accuknox/knoxAutoPolicy/src/config"
	"github.com/accuknox/knoxAutoPolicy/src/types"
)

func GetPods(clusterName string) []types.Pod {
	if config.GetCfgClusterInfoFrom() == "k8sclient" { // get from k8s client api
		pods := GetPodsFromK8sClient()
		return pods
	} else {
		clusterInstance := GetClusterFromClusterName(clusterName)
		if clusterInstance.ClusterID == 0 { // cluster not onboarded
			return nil
		}

		pods := GetPodsFromCluster(clusterInstance)
		return pods
	}
}

func GetAllClusterResources(cluster string) ([]string, []types.Service, []types.Endpoint, []types.Pod, error) {
	if config.GetCfgClusterInfoFrom() == "k8sclient" { // get from k8s client api
		namespaces := GetNamespacesFromK8sClient()
		services := GetServicesFromK8sClient()
		endpoints := GetEndpointsFromK8sClient()
		pods := GetPodsFromK8sClient()

		return namespaces, services, endpoints, pods, nil
	} else {
		clusterInstance := GetClusterFromClusterName(cluster)
		if clusterInstance.ClusterID == 0 { // cluster not onboarded
			return nil, nil, nil, nil, errors.New("Cluster " + cluster + " not onboarded")
		}

		namespaces := GetNamespacesFromCluster(clusterInstance)
		services := GetServicesFromCluster(clusterInstance)
		endpoints := GetEndpointsFromCluster(clusterInstance)
		pods := GetPodsFromCluster(clusterInstance)

		return namespaces, services, endpoints, pods, nil
	}
}
