package cluster

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"

	"github.com/accuknox/auto-policy-discovery/src/libs"
	"github.com/accuknox/auto-policy-discovery/src/types"
	"github.com/clarketm/json"
	kspAPI "github.com/kubearmor/KubeArmor/pkg/KubeArmorController/api/security.kubearmor.com/v1"
	ksp "github.com/kubearmor/KubeArmor/pkg/KubeArmorController/client/clientset/versioned"
	kspScheme "github.com/kubearmor/KubeArmor/pkg/KubeArmorController/client/clientset/versioned/scheme"
	kspInformer "github.com/kubearmor/KubeArmor/pkg/KubeArmorController/client/informers/externalversions"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	patchTypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	rest "k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"

	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
)

var parsed bool = false
var kubeconfig *string
var Client *ClientSet

type ClientSet struct {
	K8sClient *kubernetes.Clientset
	KSPClient *ksp.Clientset
}

func isInCluster() bool {
	if _, ok := os.LookupEnv("KUBERNETES_PORT"); ok {
		return true
	}

	return false
}

func ConnectK8sClient() *ClientSet {
	if Client != nil {
		return Client
	}
	if isInCluster() {
		Client = ConnectInClusterAPIClient()
	}

	Client = ConnectLocalAPIClient()
	return Client
}

func ConnectLocalAPIClient() *ClientSet {
	cs := &ClientSet{}
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
	cs.K8sClient, err = kubernetes.NewForConfig(config)
	if err != nil {
		log.Error().Msg(err.Error())
		return nil
	}

	cs.KSPClient, err = ksp.NewForConfig(config)
	if err != nil {
		log.Error().Msg(err.Error())
		return nil
	}

	// register ksp scheme
	err = kspScheme.AddToScheme(scheme.Scheme)
	if err != nil {
		log.Error().Msgf("unable to register ksp scheme error= %s", err)
		return nil
	}

	return cs
}

func ConnectInClusterAPIClient() *ClientSet {
	cs := &ClientSet{}
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

	cs.KSPClient, err = ksp.NewForConfig(kubeConfig)
	if err != nil {
		log.Error().Msg(err.Error())
		return nil
	}

	// register ksp scheme
	err = kspScheme.AddToScheme(scheme.Scheme)
	if err != nil {
		log.Error().Msgf("unable to register ksp scheme error= %s", err)
		return nil
	}

	cs.K8sClient, err = kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		log.Error().Msg(err.Error())
		return nil
	}

	return cs
}

// =============== //
// == Namespace == //
// =============== //

func GetNamespacesFromK8sClient() []string {
	results := []string{}

	client := ConnectK8sClient()
	if client == nil {
		return results
	}

	// get namespaces from k8s api client
	namespaces, err := client.K8sClient.CoreV1().Namespaces().List(context.Background(), metav1.ListOptions{})
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

var skipLabelKey []string = []string{
	"pod-template-hash",                  // common k8s hash label
	"controller-revision-hash",           // from istana robot-shop
	"statefulset.kubernetes.io/pod-name"} // from istana robot-shop

func GetPodsFromK8sClient() []types.Pod {
	results := []types.Pod{}

	client := ConnectK8sClient()
	if client == nil {
		return nil
	}

	// get pods from k8s api client
	pods, err := client.K8sClient.CoreV1().Pods("").List(context.Background(), metav1.ListOptions{})
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
	pods, err := client.K8sClient.CoreV1().Pods(namespace).List(context.Background(), metav1.ListOptions{})
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
		_, err := client.K8sClient.CoreV1().Pods(copied.ObjectMeta.Namespace).Update(context.Background(), copied, metav1.UpdateOptions{})
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
	pods, err := client.K8sClient.CoreV1().Pods("").List(context.Background(), metav1.ListOptions{})
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
			_, err := client.K8sClient.CoreV1().Pods(copied.ObjectMeta.Namespace).Update(context.Background(), copied, metav1.UpdateOptions{})
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
		return results
	}

	// get pods from k8s api client
	svcs, err := client.K8sClient.CoreV1().Services("").List(context.Background(), metav1.ListOptions{})
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
		return results
	}

	// get pods from k8s api client
	endpoints, err := client.K8sClient.CoreV1().Endpoints("").List(context.Background(), metav1.ListOptions{})
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
		return "default"
	}

	// get pods from k8s api client
	configMaps, err := client.K8sClient.CoreV1().ConfigMaps("kube-system").List(context.Background(), metav1.ListOptions{})
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
		return results
	}

	// get namespaces from k8s api client
	deployments, err := client.K8sClient.AppsV1().Deployments("").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		log.Error().Msg(err.Error())
		return results
	}

	for _, d := range deployments.Items {
		if d.Namespace == "kube-system" {
			continue
		}

		var label string

		for k, v := range d.Spec.Selector.MatchLabels {
			label = k + "=" + v
		}

		results = append(results, types.Deployment{
			Name:      d.Name,
			Namespace: d.Namespace,
			Labels:    label,
		})
	}
	return results
}

// ================= //
// == Nodes == //
// ================= //

func GetNodesFromK8sClient() (*v1.NodeList, error) {

	client := ConnectK8sClient()
	nodeList, err := client.K8sClient.CoreV1().Nodes().List(context.TODO(), metav1.ListOptions{})
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
	pods, err := client.K8sClient.CoreV1().Pods("").List(context.Background(), metav1.ListOptions{
		LabelSelector: "kubearmor-app=kubearmor-relay",
	})
	if err != nil {
		log.Error().Msg(err.Error())
		return ""
	}
	if pods == nil {
		return ""
	}
	namespace = pods.Items[0].Namespace
	url := "kubearmor." + namespace + ".svc.cluster.local"
	return url
}

// ================ //
// == Deploy KSP == //
// ================ //

// DeployKSP func deploys discovered/hardening KSP
func DeployKSP(pol *types.KubeArmorPolicy) error {
	client := ConnectK8sClient()

	arr, err := json.Marshal(pol)

	if err != nil {
		log.Error().Msgf("Error Parsing ksp: %s", err)
	}

	decode := scheme.Codecs.UniversalDeserializer().Decode
	obj, _, err := decode(arr, nil, nil)
	if err != nil {
		log.Error().Msgf("unable to decode yaml error=%s", err)
		return err
	}

	switch obj.(type) {
	case *kspAPI.KubeArmorPolicy:
		ksp := obj.(*kspAPI.KubeArmorPolicy)
		// deploy as an inactive policy
		ksp.Spec.Status = "Inactive"
		ksp.Spec.Capabilities = kspAPI.CapabilitiesType{
			MatchCapabilities: append([]kspAPI.MatchCapabilitiesType{}, ksp.Spec.Capabilities.MatchCapabilities...),
		}
		ksp.Spec.Network = kspAPI.NetworkType{
			MatchProtocols: append([]kspAPI.MatchNetworkProtocolType{}, ksp.Spec.Network.MatchProtocols...),
		}

		result, err := client.KSPClient.SecurityV1().KubeArmorPolicies(ksp.Namespace).Create(context.TODO(), ksp, metav1.CreateOptions{})
		if err != nil {
			if strings.Contains(err.Error(), "already exists") {
				// check if policy is active or not and handle it accordingly
				if err := updateDiscoveredPolicy(ksp); err != nil {
					log.Error().Msgf("Unable to update ksp %s", ksp.Name)
					return err
				}
				return nil
			}
			log.Error().Msgf("Error deploying KSP: %s", err)
			return err
		}
		log.Info().Msgf("Created policy %q", result.GetObjectMeta().GetName())
	default:
		log.Info().Msg("Skiping..., Not a KubeArmorSecurityPolicy")
	}
	return nil
}

func updateDiscoveredPolicy(ksp *kspAPI.KubeArmorPolicy) error {

	client := ConnectK8sClient()

	pol, err := client.KSPClient.SecurityV1().KubeArmorPolicies(ksp.Namespace).Get(context.TODO(), ksp.Name, metav1.GetOptions{})
	if err != nil {
		log.Error().Msgf("Unable to get policy %s", ksp.Name)
		return err
	}

	// check if policy is already updated
	if isPolicyRulesSame(pol, ksp) {
		log.Info().Msgf("Policy %s is already up to date", pol.Name)
		return nil
	}

	// check if policy is inactive
	if pol.Spec.Status == "Inactive" {
		// update the policy
		js, _ := json.Marshal(ksp.Spec)
		patchData := fmt.Sprintf(`{"spec":%s}`, js)
		patchByte := []byte(patchData)

		res, err := client.KSPClient.SecurityV1().KubeArmorPolicies(pol.Namespace).Patch(context.TODO(), pol.Name, patchTypes.MergePatchType, patchByte, metav1.PatchOptions{})
		if err != nil {
			log.Error().Msgf("Error patching the ksp: %s", pol.Name)
			return err
		}
		log.Info().Msgf("Updated ksp %s ", res.Name)
		return nil
	}

	// check if there's a autopol.*updated policy (it will be inactive always)
	polName := ksp.Name + "-updated"
	pol, err = client.KSPClient.SecurityV1().KubeArmorPolicies(ksp.Namespace).Get(context.TODO(), polName, metav1.GetOptions{})
	if err != nil {
		// create a policy with autopol.*updated name
		policy := ksp
		policy.Name = polName
		res, err := client.KSPClient.SecurityV1().KubeArmorPolicies(ksp.Namespace).Create(context.TODO(), ksp, metav1.CreateOptions{})
		if err != nil {
			log.Error().Msgf("Error deploying KSP: %s", err)
			return err
		}
		log.Info().Msgf("Created policy %q", res.GetObjectMeta().GetName())
	}

	// check if policy autopol.*updated is already updated
	if isPolicyRulesSame(pol, ksp) {
		log.Info().Msgf("Policy %s is already up to date", pol.Name)
		return nil
	}

	// update autopol.*updated policy
	js, _ := json.Marshal(ksp.Spec)
	patchData := fmt.Sprintf(`{"spec":%s}`, js)
	patchByte := []byte(patchData)

	res, err := client.KSPClient.SecurityV1().KubeArmorPolicies(pol.Namespace).Patch(context.TODO(), polName, patchTypes.MergePatchType, patchByte, metav1.PatchOptions{})
	if err != nil {
		log.Error().Msgf("Error patching the ksp: %s", pol.Name)
		return err
	}
	log.Info().Msgf("Updated ksp %s ", res.Name)

	return nil
}

func isPolicyRulesSame(p1, p2 *kspAPI.KubeArmorPolicy) bool {
	if !reflect.DeepEqual(p1.Spec.Process, p2.Spec.Process) {
		return false
	}
	if !reflect.DeepEqual(p1.Spec.File, p2.Spec.File) {
		return false
	}
	if !reflect.DeepEqual(p1.Spec.Network, p2.Spec.Network) {
		return false
	}
	return true
}

func WatchDiscoveredKsp() {
	_ = ConnectK8sClient()
	factory := kspInformer.NewSharedInformerFactory(Client.KSPClient, 0)
	informer := factory.Security().V1().KubeArmorPolicies().Informer()

	if _, err := informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {},
		UpdateFunc: func(oldObj, newObj interface{}) {
			if ksp, ok := newObj.(*kspAPI.KubeArmorPolicy); ok {
				if ksp.Spec.Status == "Active" {
					// check if policy name matches autopol.*updated regexp
					// if yes then update the autopol policy with this policy's spec
					if matched, _ := regexp.MatchString("autopol.*updated", ksp.Name); matched {
						polName := strings.TrimSuffix(ksp.Name, "-updated")
						js, _ := json.Marshal(ksp.Spec)
						patchData := fmt.Sprintf(`{"spec":%s}`, js)
						patchByte := []byte(patchData)
						res, err := Client.KSPClient.SecurityV1().KubeArmorPolicies(ksp.Namespace).Patch(context.TODO(), polName, patchTypes.MergePatchType, patchByte, metav1.PatchOptions{})
						if err != nil {
							log.Error().Msgf("Error patching the ksp: %s", polName)
							return
						}
						log.Info().Msgf("Updated ksp %s ", res.Name)
						// and delete the autopol.*updated policy
						err = Client.KSPClient.SecurityV1().KubeArmorPolicies(ksp.Namespace).Delete(context.TODO(), ksp.Name, metav1.DeleteOptions{})
						if err != nil {
							log.Error().Msgf("Error deleting discovered policy %s", ksp.Name)
						}
						log.Info().Msgf("Deleted policy %s", ksp.Name)
					}

				}
			}
		},
		DeleteFunc: func(obj interface{}) {},
	}); err != nil {
		log.Error().Msgf("Couldn't Start Watching Discovered KSP")
		return
	}
	go factory.Start(wait.NeverStop)
	factory.WaitForCacheSync(wait.NeverStop)
	log.Info().Msg("Started Watching Discovered KSPs")
}

func init() {
	Client = ConnectK8sClient()
}
