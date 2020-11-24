package libs

import (
	"context"
	"flag"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/accuknox/knoxAutoPolicy/src/types"
	"github.com/rs/zerolog/log"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	rest "k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
)

var kubeconfig *string
var parsed bool = false

func init() {
	// if !isInCluster() {
	// 	homeDir := ""
	// 	if h := os.Getenv("HOME"); h != "" {
	// 		homeDir = h
	// 	} else {
	// 		homeDir = os.Getenv("USERPROFILE") // windows
	// 	}

	// 	if home := homeDir; home != "" {
	// 		kubeconfig = flag.String("kubeconfig", filepath.Join(home, ".kube", "config"), "(optional) absolute path to the kubeconfig file")
	// 	} else {
	// 		kubeconfig = flag.String("kubeconfig", "", "absolute path to the kubeconfig file")
	// 	}
	// 	flag.Parse()
	// }
}

// isInCluster Function
func isInCluster() bool {
	if _, ok := os.LookupEnv("KUBERNETES_PORT"); ok {
		return true
	}

	return false
}

// ConnectK8sClient Function
func ConnectK8sClient() *kubernetes.Clientset {
	if isInCluster() {
		return ConnectInClusterAPIClient()
	}

	return ConnectLocalAPIClient()
}

// ConnectLocalAPIClient Function
func ConnectLocalAPIClient() *kubernetes.Clientset {
	if !parsed {
		homeDir := ""
		if h := os.Getenv("HOME"); h != "" {
			homeDir = h
		} else {
			homeDir = os.Getenv("USERPROFILE") // windows
		}

		if home := homeDir; home != "" {
			kubeconfig = flag.String("kubeconfig", filepath.Join(home, ".kube", "config"), "(optional) absolute path to the kubeconfig file")
		} else {
			kubeconfig = flag.String("kubeconfig", "", "absolute path to the kubeconfig file")
		}
		flag.Parse()

		parsed = true
	}

	// use the current context in kubeconfig
	config, err := clientcmd.BuildConfigFromFlags("", *kubeconfig)
	if err != nil {
		log.Err(err)
		return nil
	}

	// creates the clientset
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Err(err)
		return nil
	}

	return clientset
}

// ConnectInClusterAPIClient Function
func ConnectInClusterAPIClient() *kubernetes.Clientset {
	host := ""
	port := ""
	token := ""

	if val, ok := os.LookupEnv("KUBERNETES_SERVICE_HOST"); ok {
		host = val
	} else {
		host = "127.0.0.1"
	}

	if val, ok := os.LookupEnv("KUBERNETES_PORT_443_TCP_PORT"); ok {
		port = val
	} else {
		port = "6443"
	}

	read, err := ioutil.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
	if err != nil {
		log.Err(err)
		return nil
	}

	token = string(read)

	// create the configuration by token
	kubeConfig := &rest.Config{
		Host:        "https://" + host + ":" + port,
		BearerToken: token,
		TLSClientConfig: rest.TLSClientConfig{
			Insecure: true,
		},
	}

	if client, err := kubernetes.NewForConfig(kubeConfig); err != nil {
		log.Err(err)
		return nil
	} else {
		return client
	}
}

// ============================== //
// == Microservice (Namespace) == //
// ============================== //

// GetK8sNamespaces Function
func GetK8sNamespaces() []string {
	client := ConnectK8sClient()
	if client == nil {
		return nil
	}

	// get namespaces from k8s api client
	namespaces, err := client.CoreV1().Namespaces().List(context.Background(), metav1.ListOptions{})
	if err != nil {
		log.Err(err)
		return nil
	}

	results := []string{}
	for _, namespace := range namespaces.Items {
		if namespace.Status.Phase != "Active" {
			continue
		}

		results = append(results, namespace.Name)
	}

	return results
}

// =========================== //
// == Container Group (Pod) == //
// =========================== //

// GetConGroups Function
func GetConGroups(targetNS string) []types.ContainerGroup {
	client := ConnectK8sClient()
	if client == nil {
		return nil
	}

	// get pods from k8s api client
	pods, err := client.CoreV1().Pods("").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		log.Err(err)
		return nil
	}

	conGroups := []types.ContainerGroup{}

	for _, pod := range pods.Items {
		if pod.Namespace != targetNS && pod.Namespace != "kube-system" {
			continue
		}

		group := types.ContainerGroup{
			MicroserviceName:   pod.Namespace,
			ContainerGroupUID:  string(pod.UID),
			ContainerGroupName: pod.Name,
			Labels:             []string{},
		}

		for k, v := range pod.Labels {
			group.Labels = append(group.Labels, k+"="+v)
		}

		conGroups = append(conGroups, group)
	}

	return conGroups
}

// ============== //
// == Services == //
// ============== //

// GetServices Function
func GetServices() []types.K8sService {
	client := ConnectK8sClient()
	if client == nil {
		return nil
	}

	// get pods from k8s api client
	svcs, err := client.CoreV1().Services("").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		log.Err(err)
		return nil
	}

	results := []types.K8sService{}
	for _, svc := range svcs.Items {

		k8sService := types.K8sService{}

		k8sService.MicroserviceName = svc.Namespace
		k8sService.ServiceName = svc.Name
		k8sService.Labels = []string{}

		for k, v := range svc.Labels {
			k8sService.Labels = append(k8sService.Labels, k+"="+v)
		}

		k8sService.Type = string(svc.Spec.Type)

		for _, port := range svc.Spec.Ports {
			k8sService.ClusterIP = string(svc.Spec.ClusterIP)
			k8sService.Protocol = string(port.Protocol)

			k8sService.ServicePort = int(port.Port)
			k8sService.NodePort = int(port.NodePort)
			k8sService.ContainerPort = port.TargetPort.IntValue()

			k8sService.Selector = map[string]string{}
			for k, v := range svc.Spec.Selector {
				k8sService.Selector[k] = v
			}

			results = append(results, k8sService)
		}
	}

	return results
}

// ============== //
// == Endpoint == //
// ============== //

// GetEndpoints Function
func GetEndpoints() []types.K8sEndpoint {
	client := ConnectK8sClient()
	if client == nil {
		return nil
	}

	// get pods from k8s api client
	endpoints, err := client.CoreV1().Endpoints("").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		log.Err(err)
		return nil
	}

	results := []types.K8sEndpoint{}
	for _, k8sEndpoint := range endpoints.Items {
		metadata := k8sEndpoint.ObjectMeta
		subsets := k8sEndpoint.Subsets

		// if no subset, skip
		if len(subsets) == 0 {
			continue
		}

		for _, subset := range subsets {
			addresses := subset.Addresses
			ports := subset.Ports

			// build endpoint
			endPoint := types.K8sEndpoint{}

			endPoint.MicroserviceName = metadata.Namespace
			endPoint.EndpointName = metadata.Name

			// get labels from metadata
			endPoint.Labels = []string{}
			for k, v := range metadata.Labels {
				endPoint.Labels = append(endPoint.Labels, k+"="+v)
			}
			sort.Strings(endPoint.Labels)

			// get network information
			endPoint.Endpoints = []types.Endpoint{}
			for _, address := range addresses {
				targetRef := address.TargetRef
				if targetRef != nil { // no selector
					continue
				}

				for _, port := range ports {
					mapping := types.Endpoint{}

					mapping.Protocol = strings.ToLower(string(port.Protocol))
					mapping.IP = address.IP
					mapping.Port = int(port.Port)

					endPoint.Endpoints = append(endPoint.Endpoints, mapping)
				}
			}

			if len(endPoint.Endpoints) > 0 {
				results = append(results, endPoint)
			}
		}
	}

	return results
}
