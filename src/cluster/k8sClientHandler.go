package cluster

import (
	"context"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/accuknox/auto-policy-discovery/src/libs"
	"github.com/accuknox/auto-policy-discovery/src/types"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	rest "k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
)

var parsed = false
var kubeconfig *string

type Config struct {
	K8sClient *kubernetes.Clientset
}

func isInCluster() bool {
	if _, ok := os.LookupEnv("KUBERNETES_PORT"); ok {
		return true
	}

	return false
}

func ConnectK8sClient() *kubernetes.Clientset {
	if isInCluster() {
		return ConnectInClusterAPIClient()
	}

	return ConnectLocalAPIClient()
}

func ConnectLocalAPIClient() *kubernetes.Clientset {
	if !parsed {
		homeDir := ""
		if h := os.Getenv("HOME"); h != "" {
			homeDir = h
		} else {
			homeDir = os.Getenv("USERPROFILE") // windows
		}

		envKubeConfig := os.Getenv("KUBECONFIG")
		if envKubeConfig != "" {
			kubeconfig = &envKubeConfig
		} else {
			if home := homeDir; home != "" {
				kubeconfig = flag.String("kubeconfig", filepath.Join(home, ".kube", "config"), "(optional) absolute path to the kubeconfig file")
			} else {
				kubeconfig = flag.String("kubeconfig", "", "absolute path to the kubeconfig file")
			}
			flag.Parse()
		}

		parsed = true
	}

	// use the current context in kubeconfig
	config, err := clientcmd.BuildConfigFromFlags("", *kubeconfig)
	if err != nil {
		log.Error().Msg(err.Error())
		return nil
	}

	// creates the clientset
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Error().Msg(err.Error())
		return nil
	}

	return clientset
}

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

	read, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
	if err != nil {
		log.Error().Msg(err.Error())
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
	client, err := kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		log.Error().Msg(err.Error())
		return nil
	}
	return client

}

// =============== //
// == Namespace == //
// =============== //

func GetNamespacesFromK8sClient() []string {
	results := []string{}

	client := ConnectK8sClient()
	if client == nil {
		log.Error().Msg("failed to create k8s client")
		return results
	}

	// get namespaces from k8s api client
	namespaces, err := client.CoreV1().Namespaces().List(context.Background(), metav1.ListOptions{})
	if err != nil {
		log.Error().Msg(err.Error())
		return results
	}

	for _, namespace := range namespaces.Items {
		if namespace.Status.Phase != "Active" {
			continue
		}

		results = append(results, namespace.Name)
	}

	return results
}

// ========= //
// == Pod == //
// ========= //

var skipLabelKey = []string{
	"pod-template-hash",                  // common k8s hash label
	"controller-revision-hash",           // from istana robot-shop
	"statefulset.kubernetes.io/pod-name"} // from istana robot-shop

func GetPodsFromK8sClient() []types.Pod {
	results := []types.Pod{}

	client := ConnectK8sClient()
	if client == nil {
		log.Error().Msg("failed to create k8s client")
		return nil
	}

	// get pods from k8s api client
	pods, err := client.CoreV1().Pods("").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		log.Error().Msg(err.Error())
		return results
	}

	for _, pod := range pods.Items {
		group := types.Pod{
			Namespace: pod.Namespace,
			PodName:   pod.Name,
			Labels:    []string{},
			PodIP:     pod.Status.PodIP,
		}

		for k, v := range pod.Labels {
			// skip hash or microservice default label key
			if libs.ContainsElement(skipLabelKey, k) {
				continue
			}

			group.Labels = append(group.Labels, k+"="+v)
		}
		sort.Strings(group.Labels)

		results = append(results, group)
	}

	return results
}

func SetAnnotationsToPodsInNamespaceK8s(namespace string, annotation map[string]string) error {
	client := ConnectK8sClient()
	if client == nil {
		return errors.New("no client")
	}

	// get pods from k8s api client
	pods, err := client.CoreV1().Pods(namespace).List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return err
	}

	for _, pod := range pods.Items {
		copied := pod.DeepCopy()
		ann := copied.ObjectMeta.Annotations
		if ann == nil {
			ann = make(map[string]string)
		}
		for k, v := range annotation {
			ann[k] = v
		}
		copied.SetAnnotations(ann)
		_, err := client.CoreV1().Pods(copied.ObjectMeta.Namespace).Update(context.Background(), copied, metav1.UpdateOptions{})
		if err != nil {
			return err
		}
	}

	return nil
}

func SetAnnotationsToPodK8s(podName string, annotation map[string]string) error {
	client := ConnectK8sClient()
	if client == nil {
		return errors.New("no client")
	}

	// get pods from k8s api client
	pods, err := client.CoreV1().Pods("").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return err
	}

	for _, pod := range pods.Items {
		if pod.Name == podName {
			copied := pod.DeepCopy()
			ann := copied.ObjectMeta.Annotations
			if ann == nil {
				ann = make(map[string]string)
			}
			for k, v := range annotation {
				ann[k] = v
			}
			copied.SetAnnotations(ann)
			_, err := client.CoreV1().Pods(copied.ObjectMeta.Namespace).Update(context.Background(), copied, metav1.UpdateOptions{})
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// ============= //
// == Service == //
// ============= //

func GetServicesFromK8sClient() []types.Service {
	results := []types.Service{}

	client := ConnectK8sClient()
	if client == nil {
		log.Error().Msg("failed to create k8s client")
		return results
	}

	// get pods from k8s api client
	svcs, err := client.CoreV1().Services("").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		log.Error().Msg(err.Error())
		return results
	}

	for _, svc := range svcs.Items {
		k8sService := types.Service{}

		k8sService.Namespace = svc.Namespace
		k8sService.ServiceName = svc.Name
		k8sService.Labels = []string{}
		k8sService.Type = string(svc.Spec.Type)

		for k, v := range svc.Labels {
			k8sService.Labels = append(k8sService.Labels, k+"="+v)
		}

		k8sService.ExternalIPs = append(k8sService.ExternalIPs, svc.Spec.ExternalIPs...)

		for _, port := range svc.Spec.Ports {
			k8sService.ClusterIP = string(svc.Spec.ClusterIP)
			k8sService.Protocol = string(port.Protocol)
			k8sService.ServicePort = int(port.Port)
			k8sService.NodePort = int(port.NodePort)
			k8sService.TargetPort = port.TargetPort.IntValue()

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

func GetEndpointsFromK8sClient() []types.Endpoint {
	results := []types.Endpoint{}

	client := ConnectK8sClient()
	if client == nil {
		log.Error().Msg("failed to create k8s client")
		return results
	}

	// get pods from k8s api client
	endpoints, err := client.CoreV1().Endpoints("").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		log.Error().Msg(err.Error())
		return results
	}

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
			endPoint := types.Endpoint{}

			endPoint.Namespace = metadata.Namespace
			endPoint.EndpointName = metadata.Name

			// get labels from metadata
			endPoint.Labels = []string{}
			for k, v := range metadata.Labels {
				endPoint.Labels = append(endPoint.Labels, k+"="+v)
			}
			sort.Strings(endPoint.Labels)

			// get network information
			endPoint.Endpoints = []types.Mapping{}
			for _, address := range addresses {
				targetRef := address.TargetRef
				if targetRef != nil { // no selector
					continue
				}

				for _, port := range ports {
					mapping := types.Mapping{}

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

// GKE only
func GetClusterNameFromK8sClient() string {
	client := ConnectK8sClient()
	if client == nil {
		log.Error().Msg("failed to create k8s client")
		return "default"
	}

	// get pods from k8s api client
	configMaps, err := client.CoreV1().ConfigMaps("kube-system").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		log.Error().Msg(err.Error())
		return "default"
	}

	for _, configMap := range configMaps.Items {
		if configMap.GetName() == "gke-metrics-agent-conf" {
			for _, v := range configMap.Data {
				lines := strings.Split(v, "\n")
				for _, line := range lines {
					if strings.Contains(line, "cluster_name:") {
						name := strings.TrimSpace(line)
						clusterName := strings.Split(name, ": ")[1]
						return clusterName
					}
				}
			}
		}
	}

	return "default"
}

// ================= //
// == Deployments == //
// ================= //

func GetDeploymentsFromK8sClient() []types.Deployment {
	results := []types.Deployment{}

	client := ConnectK8sClient()
	if client == nil {
		log.Error().Msg("failed to create k8s client")
		return results
	}

	// get namespaces from k8s api client
	deployments, err := client.AppsV1().Deployments("").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		log.Error().Msg(err.Error())
		return results
	}

	for _, d := range deployments.Items {
		if d.Namespace == "kube-system" {
			continue
		}

		if d.Spec.Selector.MatchLabels != nil {
			var labels []string

			for k, v := range d.Spec.Selector.MatchLabels {
				labels = append(labels, k+"="+v)
			}

			results = append(results, types.Deployment{
				Name:      d.Name,
				Namespace: d.Namespace,
				Labels:    strings.Join(labels, ","),
			})
		}
	}

	results = append(results, GetReplicaSetsFromK8sClient()...)
	results = append(results, GetStatefulSetsFromK8sClient()...)

	return results
}

// ================= //
// == ReplicaSet == //
// ================= //

func GetReplicaSetsFromK8sClient() []types.Deployment {
	results := []types.Deployment{}

	client := ConnectK8sClient()
	if client == nil {
		log.Error().Msg("failed to create k8s client")
		return results
	}

	// get namespaces from k8s api client
	replicasets, err := client.AppsV1().ReplicaSets("").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		log.Error().Msg(err.Error())
		return results
	}

	for _, rs := range replicasets.Items {
		if rs.OwnerReferences == nil {
			if rs.Namespace == "kube-system" {
				continue
			}

			if rs.Spec.Selector.MatchLabels != nil {
				var labels []string

				for k, v := range rs.Spec.Selector.MatchLabels {
					labels = append(labels, k+"="+v)
				}

				results = append(results, types.Deployment{
					Name:      rs.Name,
					Namespace: rs.Namespace,
					Labels:    strings.Join(labels, ","),
				})
			}
		}
	}
	return results
}

// ================= //
// == StatefulSet == //
// ================= //

func GetStatefulSetsFromK8sClient() []types.Deployment {
	results := []types.Deployment{}

	client := ConnectK8sClient()
	if client == nil {
		log.Error().Msg("failed to create k8s client")
		return results
	}

	// get namespaces from k8s api client
	statefulset, err := client.AppsV1().StatefulSets("").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		log.Error().Msg(err.Error())
		return results
	}

	for _, sts := range statefulset.Items {
		if sts.OwnerReferences == nil {
			if sts.Namespace == "kube-system" {
				continue
			}

			if sts.Spec.Selector.MatchLabels != nil {
				var labels []string

				for k, v := range sts.Spec.Selector.MatchLabels {
					labels = append(labels, k+"="+v)
				}

				results = append(results, types.Deployment{
					Name:      sts.Name,
					Namespace: sts.Namespace,
					Labels:    strings.Join(labels, ","),
				})
			}
		}
	}
	return results
}

// ================= //
// == Nodes == //
// ================= //

func GetNodesFromK8sClient() (*v1.NodeList, error) {

	client := ConnectK8sClient()
	nodeList, err := client.CoreV1().Nodes().List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		log.Error().Msg(err.Error())
		return &v1.NodeList{}, err
	}
	return nodeList, nil
}

func GetKubearmorRelayURL() string {
	var namespace string
	client := ConnectK8sClient()
	if client == nil {
		return ""
	}

	// get kubearmor-relay pod from k8s api client
	pods, err := client.CoreV1().Pods("").List(context.Background(), metav1.ListOptions{
		LabelSelector: "kubearmor-app=kubearmor-relay",
	})
	if err != nil {
		log.Error().Msg(err.Error())
		return ""
	}
	if pods == nil || len(pods.Items) == 0 {
		log.Error().Msgf("Unable to find kubearmor-relay")
		return ""
	}
	namespace = pods.Items[0].Namespace
	url := "kubearmor." + namespace + ".svc.cluster.local"
	return url
}

// GetSecrets to get secrets
func GetSecrets(k8sClient *kubernetes.Clientset, label string, namespace string, name string) (*v1.Secret, error) {
	if k8sClient == nil {
		return nil, errors.New("k8s client not created")
	}

	secrets, err := k8sClient.CoreV1().Secrets(namespace).Get(context.Background(), name, metav1.GetOptions{})

	if err != nil && !strings.Contains(err.Error(), "not found") {
		log.Error().Msgf("error while getting license secrets with name: %s from %s namespace, error: %s", name, namespace, err.Error())
		return nil, err
	}

	if secrets != nil && secrets.GetName() == "" {
		return nil, nil
	}

	return secrets, nil

}

// CreateLicenseSecret to create license secret
func CreateLicenseSecret(k8sClient *kubernetes.Clientset, namespace string, key string, userId string, name string, label string) (*v1.Secret, error) {
	if k8sClient == nil {
		return nil, errors.New("k8s client not created")
	}

	secret, err := GetSecrets(k8sClient, label, namespace, name)

	if err != nil {
		log.Error().Msgf("error while fetching secrets, error: %s", err.Error())
		return nil, err
	}

	if secret != nil {
		log.Info().Msgf("secrets already exists for discovery-engine license for user-id: %s", userId)
		return secret, nil
	}
	t := true

	secretSpec := v1.Secret{

		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			Labels: map[string]string{
				"app": "discovery-engine",
			},
		},
		Immutable: &t,
		Data:      nil,
		StringData: map[string]string{
			"key":     key,
			"user-id": userId,
		},
		Type: v1.SecretTypeOpaque,
	}

	secret, err = k8sClient.CoreV1().Secrets(namespace).Create(context.Background(), &secretSpec, metav1.CreateOptions{})
	if err != nil {
		log.Error().Msgf("error while creating secret for license key, error: %s", err.Error())
		return nil, err
	}
	log.Info().Msgf("secret created successfully for discovery-engine")
	return secret, nil
}

// DeleteSecrets to delete secrets
func DeleteSecrets(k8sClient *kubernetes.Clientset, name string, namespace string) error {
	if k8sClient == nil {
		return errors.New("k8s client not created")
	}

	err := k8sClient.CoreV1().Secrets(namespace).Delete(context.Background(), name, metav1.DeleteOptions{})
	if err != nil {
		log.Error().Msgf("error while deleting secrets for discovery-engine, error: %s", err.Error())
		return err
	}

	return nil
}

// GetKubeSystemUUID get kube-system namespace uuid
func GetKubeSystemUUID(k8sClient *kubernetes.Clientset) (string, error) {
	if k8sClient == nil {
		return "", errors.New("k8s client not created")
	}

	kubeSystem, err := k8sClient.CoreV1().Namespaces().Get(context.Background(), "kube-system", metav1.GetOptions{})
	if err != nil {
		return "", err
	}

	return string(kubeSystem.GetUID()), nil

}
