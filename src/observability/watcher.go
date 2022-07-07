package observability

import (
	"encoding/json"
	"io"

	"github.com/accuknox/auto-policy-discovery/src/cluster"
	"github.com/accuknox/auto-policy-discovery/src/types"
)

func addPodToList(pod types.Pod) {
	podExist := false

	for _, locpod := range Pods {
		if locpod.IP == pod.IP && locpod.PodName == pod.PodName && locpod.Namespace == pod.Namespace {
			podExist = true
			break
		}
	}
	if !podExist {
		Pods = append(Pods, types.Pod{
			Namespace: pod.Namespace,
			PodName:   pod.PodName,
			IP:        pod.IP,
		})
	}
}

func updatePodList(pod types.Pod) {
	for index, locpod := range Pods {
		if locpod.PodName == pod.PodName && locpod.Namespace == pod.Namespace {
			Pods[index].IP = pod.IP
			break
		}
	}
}

func addServiceToList(svc types.Service) {
	svcExist := false

	for _, locsvc := range Services {
		if locsvc.ClusterIP == svc.ClusterIP && locsvc.Namespace == svc.ServiceName && locsvc.ServiceName == svc.ServiceName {
			svcExist = true
			break
		}
	}
	if !svcExist {
		Services = append(Services, types.Service{
			Namespace:   svc.Namespace,
			ServiceName: svc.ServiceName,
			ClusterIP:   svc.ClusterIP,
			Labels:      svc.Labels,
		})
	}
}

func updateServiceList(svc types.Service) {
	for index, locsvc := range Services {
		if locsvc.ClusterIP == svc.ClusterIP && locsvc.Namespace == svc.ServiceName && locsvc.ServiceName == svc.ServiceName {
			Services[index].ClusterIP = svc.ClusterIP
			break
		}
	}
}

// WatchK8sPods Function
func WatchK8sPods() {
	for {
		if resp := cluster.WatchK8sPods(); resp != nil {
			defer resp.Body.Close()

			decoder := json.NewDecoder(resp.Body)
			for {
				event := types.K8sPodEvent{}
				labels := []string{}
				if err := decoder.Decode(&event); err == io.EOF {
					break
				} else if err != nil {
					break
				}

				if event.Type != "ADDED" && event.Type != "MODIFIED" && event.Type != "DELETED" {
					continue
				}

				for key, val := range event.Object.Labels {
					labels = append(labels, key+"="+val)
				}

				pod := types.Pod{
					Namespace: event.Object.ObjectMeta.Namespace,
					PodName:   event.Object.ObjectMeta.Name,
					IP:        event.Object.Status.PodIP,
					Labels:    labels,
				}

				if event.Type == "ADDED" {
					addPodToList(pod)
				} else if event.Type == "MODIFIED" {
					updatePodList(pod)
				}
			}
		}
	}
}

// WatchK8sServices Function
func WatchK8sServices() {
	for {
		if resp := cluster.WatchK8sServices(); resp != nil {
			defer resp.Body.Close()

			decoder := json.NewDecoder(resp.Body)
			for {
				event := types.K8sServiceEvent{}
				labels := []string{}
				if err := decoder.Decode(&event); err == io.EOF {
					break
				} else if err != nil {
					break
				}

				if event.Type != "ADDED" && event.Type != "MODIFIED" && event.Type != "DELETED" {
					continue
				}

				for key, val := range event.Object.Labels {
					labels = append(labels, key+"="+val)
				}

				service := types.Service{
					ServiceName: event.Object.ObjectMeta.Name,
					Namespace:   event.Object.ObjectMeta.Namespace,
					ClusterIP:   event.Object.Spec.ClusterIP,
					Labels:      labels,
				}

				if event.Type == "ADDED" {
					addServiceToList(service)
				} else if event.Type == "MODIFIED" {
					updateServiceList(service)
				}
			}
		}
	}
}

func GetPodDetailFromPodIP(ip string) types.Pod {
	for _, pod := range Pods {
		if ip == pod.IP {
			return pod
		}
	}
	return types.Pod{}
}

func GetServiceDetailFromClusterIP(ip string) types.Service {
	for _, svc := range Services {
		if svc.ClusterIP == ip {
			return svc
		}
	}
	return types.Service{}
}
