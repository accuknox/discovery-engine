package libs

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/accuknox/knoxAutoPolicy/src/types"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
	rest "k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// K8s Handler
var K8s *K8sHandler

func init() {
	K8s = NewK8sHandler()
}

// K8sHandler Structure
type K8sHandler struct {
	K8sClient *kubernetes.Clientset

	Namespaces []v1.Namespace
	Pods       []v1.Pod
	Services   []v1.Service
	Endpoints  []v1.Endpoints

	K8sToken string
	K8sHost  string
	K8sPort  string
}

// NewK8sHandler Function
func NewK8sHandler() *K8sHandler {
	kh := &K8sHandler{}

	if val, ok := os.LookupEnv("KUBERNETES_SERVICE_HOST"); ok {
		kh.K8sHost = val
	} else {
		kh.K8sHost = "127.0.0.1"
	}

	if val, ok := os.LookupEnv("KUBERNETES_PORT_443_TCP_PORT"); ok {
		kh.K8sPort = val
	} else {
		kh.K8sPort = "6443"
	}

	kh.Namespaces = []v1.Namespace{}
	kh.Pods = []v1.Pod{}
	kh.Services = []v1.Service{}
	kh.Endpoints = []v1.Endpoints{}

	return kh
}

// HomeDir Function
func (kh *K8sHandler) HomeDir() string {
	if h := os.Getenv("HOME"); h != "" {
		return h
	}

	return os.Getenv("USERPROFILE") // windows
}

// IsInCluster Function
func (kh *K8sHandler) IsInCluster() bool {
	if _, ok := os.LookupEnv("KUBERNETES_PORT"); ok {
		return true
	}

	return false
}

// InitAPIClient Function
func (kh *K8sHandler) InitAPIClient() bool {
	if kh.IsInCluster() {
		return kh.InitInclusterAPIClient()
	}

	return kh.InitLocalAPIClient()
}

// InitLocalAPIClient Function
func (kh *K8sHandler) InitLocalAPIClient() bool {
	var kubeconfig *string
	if home := kh.HomeDir(); home != "" {
		kubeconfig = flag.String("kubeconfig", filepath.Join(home, ".kube", "config"), "(optional) absolute path to the kubeconfig file")
	} else {
		kubeconfig = flag.String("kubeconfig", "", "absolute path to the kubeconfig file")
	}
	flag.Parse()

	// use the current context in kubeconfig
	config, err := clientcmd.BuildConfigFromFlags("", *kubeconfig)
	if err != nil {
		fmt.Println(err)
		return false
	}

	// creates the clientset
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		fmt.Println(err)
		return false
	}

	kh.K8sClient = clientset

	return true
}

// InitInclusterAPIClient Function
func (kh *K8sHandler) InitInclusterAPIClient() bool {
	read, err := ioutil.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
	if err != nil {
		fmt.Printf("%v", err)
		return false
	}
	kh.K8sToken = string(read)

	// create the configuration by token
	kubeConfig := &rest.Config{
		Host:        "https://" + kh.K8sHost + ":" + kh.K8sPort,
		BearerToken: kh.K8sToken,
		TLSClientConfig: rest.TLSClientConfig{
			Insecure: true,
		},
	}

	if client, err := kubernetes.NewForConfig(kubeConfig); err != nil {
		fmt.Printf("%v", err)
		return false
	} else {
		kh.K8sClient = client
	}

	return true
}

// ============================== //
// == Microservice (Namespace) == //
// ============================== //

// UpdateK8sNamespaces Function
func (kh *K8sHandler) UpdateK8sNamespaces() error {
	if kh.K8sClient == nil && !kh.InitAPIClient() {
		return errors.New("K8s api client is nil")
	}

	// get namespaces from k8s api client
	namespaces, err := kh.K8sClient.CoreV1().Namespaces().List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return err
	}

	newNamespaces := []v1.Namespace{}
	for _, namespace := range namespaces.Items {
		newNamespaces = append(newNamespaces, namespace)
	}

	kh.Namespaces = newNamespaces

	return nil
}

// GetK8sNamespaces Function
func (kh *K8sHandler) GetK8sNamespaces() []string {
	kh.UpdateK8sNamespaces()

	skipList := []string{"kube-system", "kube-public", "kube-node-lease"}

	results := []string{}
	for _, namespace := range kh.Namespaces {
		if ContainsElement(skipList, namespace.Name) {
			continue
		}

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

// UpdateK8sPods Function
func (kh *K8sHandler) UpdateK8sPods() error {
	if kh.K8sClient == nil && !kh.InitAPIClient() {
		return errors.New("K8s api client is nil")
	}

	// get pods from k8s api client
	pods, err := kh.K8sClient.CoreV1().Pods("").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return err
	}

	newPods := []v1.Pod{}
	for _, pod := range pods.Items {
		newPods = append(newPods, pod)
	}

	kh.Pods = newPods

	return nil
}

// GetConGroups Function
func (kh *K8sHandler) GetConGroups(targetNS string) []types.ContainerGroup {
	kh.UpdateK8sPods()

	conGroups := []types.ContainerGroup{}

	for _, pod := range kh.Pods {
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

// UpdateServices Function
func (kh *K8sHandler) UpdateServices() []types.K8sService {
	if kh.K8sClient == nil && !kh.InitAPIClient() {
		return nil
	}

	// get pods from k8s api client
	svcs, err := kh.K8sClient.CoreV1().Services("").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return nil
	}

	newServices := []v1.Service{}
	for _, svc := range svcs.Items {
		newServices = append(newServices, svc)
	}

	kh.Services = newServices

	return nil
}

// GetServices Function
func (kh *K8sHandler) GetServices(targetNS string) []types.K8sService {
	kh.UpdateServices()

	results := []types.K8sService{}
	for _, svc := range kh.Services {
		if svc.Namespace != targetNS && svc.Namespace != "kube-system" {
			continue
		}

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
			k8sService.ContainerPort = port.TargetPort.IntValue()

			results = append(results, k8sService)
		}

		k8sService.Selector = map[string]string{}
		for k, v := range svc.Spec.Selector {
			k8sService.Selector[k] = v
		}
	}

	return results
}

// ============== //
// == Endpoint == //
// ============== //

// UpdateEndpoints Function
func (kh *K8sHandler) UpdateEndpoints() []types.K8sService {
	if kh.K8sClient == nil && !kh.InitAPIClient() {
		return nil
	}

	// get pods from k8s api client
	endpoints, err := kh.K8sClient.CoreV1().Endpoints("").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return nil
	}

	endPoints := []v1.Endpoints{}
	for _, endpoint := range endpoints.Items {
		endPoints = append(endPoints, endpoint)
	}

	kh.Endpoints = endPoints

	return nil
}

// GetEndpoints Function
func (kh *K8sHandler) GetEndpoints(targetNS string) []types.K8sEndpoint {
	kh.UpdateEndpoints()

	results := []types.K8sEndpoint{}
	for _, k8sEndpoint := range kh.Endpoints {
		if k8sEndpoint.Namespace != targetNS && k8sEndpoint.Namespace != "kube-system" {
			continue
		}

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
