package smoke_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"

	opb "github.com/accuknox/auto-policy-discovery/src/protobuf/v1/observability"
	wpb "github.com/accuknox/auto-policy-discovery/src/protobuf/v1/worker"
	"github.com/accuknox/auto-policy-discovery/src/types"
	"github.com/kubearmor/discovery-engine/tests/util"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	nv1 "k8s.io/api/networking/v1"
)

var stopChan chan struct{}

var grpcClient *grpc.ClientConn

var (
	expectedFilePaths = []string{
		"/dev/urandom",
		"/etc/ld.so.cache",
	}
	expectedFileDirs = []string{
		"/lib/x86_64-linux-gnu/",
		"/var/www/html/",
		"/usr/src/wordpress/",
	}
	expectedProcessPaths = []string{
		"/usr/sbin/apache2",
		"/usr/local/bin/php",
	}
	expectedProcessDir = []string{
		"/bin/",
		"/usr/bin/",
	}
	expectedEgressRule = map[string]string{
		"port":     "3306",
		"protocol": "TCP",
	}
	expectedIngressRule = map[string]string{
		"port":     "3306",
		"protocol": "TCP",
	}
)
var foundRule = map[string]bool{}

// getMatchPath returns a string based on the provided KubeArmor policy and input string.
func getMatchRules(policy types.KubeArmorPolicy) int {
	found := map[string]bool{}
	filePaths := policy.Spec.File.MatchPaths
	fileDirs := policy.Spec.File.MatchDirectories
	processPaths := policy.Spec.Process.MatchPaths
	processDirs := policy.Spec.Process.MatchDirectories

	for _, str := range expectedFilePaths {
		for _, filePath := range filePaths {
			if strings.HasPrefix(filePath.Path, str) {
				found[str] = true
			}
		}
	}
	for _, str := range expectedFileDirs {
		for _, dirPath := range fileDirs {
			if strings.HasPrefix(dirPath.Dir, str) {
				found[str] = true
			}
		}
	}
	for _, str := range expectedProcessPaths {
		for _, processPath := range processPaths {
			if strings.HasPrefix(processPath.Path, str) {
				found[str] = true
			}
		}
	}

	for _, str := range expectedProcessDir {
		for _, processDir := range processDirs {
			if strings.HasPrefix(processDir.Dir, str) {
				found[str] = true
			}
		}
	}

	log.Info().Msgf("Number of rules found: %v", len(found))
	log.Info().Msgf("Found the following rules: %v", found)

	return len(found)
}

// checkSysPolicyRules checks the system policy rules against the given KubeArmor policy.
func checkSysPolicyRules(policy types.KubeArmorPolicy) int {
	return getMatchRules(policy)
}

// checkNetworkPolicyRules checks the network policy rules for the given array of network policies.
func checkNetworkPolicyRules(policies []nv1.NetworkPolicy) (int, int) {
	egressFlag := 0
	ingressFlag := 0

	

	for _, policy := range policies {
		if policy.Spec.PodSelector.MatchLabels["app"] == "wordpress" {
			if policy.Spec.Egress != nil {
				egressFlag = checkEgressRules(policy.Spec.Egress)
			}
		} else if policy.Spec.PodSelector.MatchLabels["app"] == "mysql" {
			if policy.Spec.Ingress != nil {
				ingressFlag = checkIngressRules(policy.Spec.Ingress)
			}
		}
		if egressFlag == 1 && ingressFlag == 1 {
			log.Info().Msgf("Found ingress %v communication on %v port of mysql pod", expectedIngressRule["protocol"], expectedIngressRule["port"])
			log.Info().Msgf("Found egress %v communication on %v port of wordpress pod", expectedEgressRule["protocol"], expectedEgressRule["port"])
			break
		}
	}

	return egressFlag, ingressFlag
}

// checkEgressRules returns 1 if any egress rule has a valid port and protocol, otherwise returns 0.
func checkEgressRules(egress []nv1.NetworkPolicyEgressRule) int {
	for _, rule := range egress {
		port := rule.Ports[0]
		if port.Port != nil && port.Protocol != nil {
			if string(*port.Protocol) == expectedEgressRule["protocol"] && port.Port.String() == expectedEgressRule["port"] {
				foundRule[string(*port.Protocol)+"_"+port.Port.String()] = true
				break
			}
		}
	}
	return len(foundRule)
}

// checkIngressRules checks the ingress rules against the given protocol and port.
func checkIngressRules(ingress []nv1.NetworkPolicyIngressRule) int {
	for _, rule := range ingress {
		rulePort := rule.Ports[0]
		if rulePort.Protocol == nil {
			continue
		}
		if rulePort.Port != nil && string(*rulePort.Protocol) == expectedIngressRule["protocol"] && rulePort.Port.String() == expectedIngressRule["port"] {
			foundRule[string(*rulePort.Protocol)+"_"+rulePort.Port.String()] = true
			break
		}
	}
	return len(foundRule)
}

// findProcessOrFileData is a function that searches through an array of SysProcFileSummaryData to find a matching data entry based on the provided source, destination, and dataType. It returns true if a match is found, and false otherwise.
func findProcessOrFileData(procFileData []*opb.SysProcFileSummaryData, source, destination, dataType string) bool {
	for _, data := range procFileData {
		if data.Source == source && data.Destination == destination && data.Status == "Allow" {
			return true
		}
	}
	return false
}

// verifyProcessOrFileData verifies the process or file data.
func verifyProcessOrFileData(procFileData []*opb.SysProcFileSummaryData, data map[string]string, dataType string) error {
	for destination, source := range data {
		flag := findProcessOrFileData(procFileData, source, destination, dataType)
		if !flag {
			return fmt.Errorf("%s data is not correct for source: %v, destination: %v", dataType, source, destination)
		}
	}
	return nil
}

// enablePortForward enable port forwarding for a given pod in a namespace
func enablePortForward(namespace, podPrefix string, localPort, remotePort int) error {

	pods, err := util.K8sGetPods(podPrefix, namespace, nil, 0)
	if err != nil {
		log.Printf("could not get %v pods assuming process mode", podPrefix)
		return nil
	}
	if len(pods) != 1 {
		log.Error().Msgf("len(pods)=%d", len(pods))
		return errors.New("expecting one " + podPrefix + " pod only")
	}
	log.Printf("found %s pod:[%s]", podPrefix, pods[0])
	c, err := util.K8sPortForward(util.PortForwardOpt{
		LocalPort:   localPort,
		RemotePort:  remotePort,
		ServiceName: pods[0],
		Namespace:   namespace})
	if err != nil {
		log.Error().Msgf("could not do %v port-forward Error=%s", podPrefix, err.Error())
		return err
	}
	stopChan = c
	return nil
}

// disablePortForward stops port forwarding
func disablePortForward() {
	if stopChan != nil {
		close(stopChan)
		stopChan = nil
	}
}

func createGRPCClient(address string) (*grpc.ClientConn, error) {
	log.Info().Msgf("creating grpc client for discovery engine, address: %v", address)
	// creates a client connection and waits for 5 minute to get the connection otherwise throws error
	connection, err := grpc.Dial(address, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())
	if err != nil {
		errStr := "error while creating grpc client for server at address: " + address
		log.Error().Msg(err.Error())
		return connection, errors.New(errStr)
	}
	log.Info().Msg("grpc client created for discovery engine")
	return connection, nil
}

// checkPod checks if a pod exists with the given name, annotation, and namespace.
func checkPod(name, ant, ns string) {
	pods, err := util.K8sGetPods(name, ns, []string{ant}, 60)
	Expect(err).To(BeNil())
	Expect(len(pods)).To(Equal(1))
}

var _ = BeforeSuite(func() {
	// install discovery-engine
	_, err := util.Kubectl("apply -f https://raw.githubusercontent.com/kubearmor/discovery-engine/dev/deployments/k8s/deployment.yaml")
	Expect(err).To(BeNil())
	// check discovery-engine pod status
	checkPod("discovery-engine-",
		"container.apparmor.security.beta.kubernetes.io/discovery-engine: localhost/kubearmor-accuknox-agents-discovery-engine-discovery-engine", "accuknox-agents")

	//install wordpress-mysql app
	err = util.K8sApply([]string{"res/wordpress-mysql-deployment.yaml"})
	Expect(err).To(BeNil())
	//check wordpress pod status
	checkPod("wordpress-",
		"container.apparmor.security.beta.kubernetes.io/wordpress: localhost/kubearmor-wordpress-mysql-wordpress-wordpress", "wordpress-mysql")
	//check mysql pod status
	checkPod("mysql-",
		"container.apparmor.security.beta.kubernetes.io/mysql: localhost/kubearmor-wordpress-mysql-mysql-mysql", "wordpress-mysql")

	// delete all KSPs
	err = util.DeleteAllKsp()
	Expect(err).To(BeNil())

	// enable kubearmor port forwarding
	err = util.KubearmorPortForward()
	Expect(err).To(BeNil())

	// enable wordpress port forwarding
	err = enablePortForward("wordpress-mysql", "wordpress", 8000, 80)
	Expect(err).To(BeNil())

	// enable DiscoveryEngine port forwarding
	enablePortForward("accuknox-agents", "discovery-engine", 9089, 9089)
	Expect(err).To(BeNil())

	grpcClient, err = createGRPCClient("localhost:9089")
	Expect(err).To(BeNil())

})

var _ = AfterSuite(func() {
	disablePortForward()
})

// discoverSysPolicy retrieves the system policy for a given namespace and match labels.
func discoverSysPolicy(namespace string, matchLabels string) ([]types.KubeArmorPolicy, int, error) {
	policies := []types.KubeArmorPolicy{}

	deClient := wpb.NewWorkerClient(grpcClient)
	policyRequest := &wpb.WorkerRequest{
		Namespace:  namespace,
		Labels:     matchLabels,
		Policytype: "KubearmorSecurityPolicy",
	}
	var response *wpb.WorkerResponse

	response, err := deClient.Convert(context.Background(), policyRequest)
	if err != nil {
		return policies, 0, errors.New("could not connect to the server. Possible troubleshooting:\n- Check if discovery engine is running\n- kubectl get po -n accuknox-agents")
	}
 

	if len(response.Kubearmorpolicy) > 0 {
		for _, val := range response.Kubearmorpolicy {
			policy := types.KubeArmorPolicy{}
			err = json.Unmarshal(val.Data, &policy)
			if err != nil {
				log.Error().Msg(err.Error())
				return policies, 0, err
			}
			totalRules := len(expectedFileDirs) + len(expectedFilePaths) + len(expectedProcessPaths) + len(expectedProcessDir)
			log.Info().Msgf("Total number of rules to check: %v", totalRules)
			found := checkSysPolicyRules(policy)
			if found == totalRules {
				policies = append(policies, policy)
				return policies, found, nil
			}
		}
	}

	return nil, 0, err
}

// discoverNetworkPolicy returns the network policies discovered in the given namespace up to a maximum count.
func discoverNetworkPolicy(namespace, matchLabels string) ([]nv1.NetworkPolicy, error) {
	policies := []nv1.NetworkPolicy{}

	deClient := wpb.NewWorkerClient(grpcClient)
	policyRequest := &wpb.WorkerRequest{
		Namespace:  namespace,
		Labels:     matchLabels,
		Policytype: "NetworkPolicy",
	}
	var response *wpb.WorkerResponse
	egressFlag, ingressFlag := 0, 0

	response, err := deClient.Convert(context.Background(), policyRequest)
	if err != nil {
		return policies, errors.New("could not connect to the server. Possible troubleshooting:\n- Check if discovery engine is running\n- kubectl get po -n accuknox-agents")
	}
	log.Info().Msg("connecting to discovery engine for policy data")

	if len(response.K8SNetworkpolicy) > 0 {
		for _, val := range response.K8SNetworkpolicy {
			policy := nv1.NetworkPolicy{}
			err = json.Unmarshal(val.Data, &policy)
			if err != nil {
				log.Error().Msg(err.Error())
				return nil, err
			}

			policies = append(policies, policy)
		}

		egressFlag, ingressFlag = checkNetworkPolicyRules(policies)
		if egressFlag == 1 && ingressFlag == 1 {
			return policies, err
		}

		if egressFlag == 0 || ingressFlag == 0 {
			time.Sleep(10 * time.Second)
		}
	}

	return []nv1.NetworkPolicy{}, err
}

// getSysSummary retrieves the system summary for a given pod name and maximum count.
func getSysSummary(podPrefix, namespace string) (*opb.Response, error) {
	var err error

	podName, _ := util.K8sGetPods(podPrefix, namespace, []string{}, 60)

	client := opb.NewObservabilityClient(grpcClient)

	summary, err := client.Summary(context.Background(), &opb.Request{
		PodName:   podName[0],
		NameSpace: namespace,
		Type:      "process,file,network",
	})
	if err != nil {
		return nil, err
	}

	if strings.Contains(summary.PodName, podPrefix) {
		if podPrefix == "wordpress" {
			processData := map[string]string{
				"/usr/local/bin/php": "/bin/bash",
				"/usr/bin/sha1sum":   "/bin/bash",
			}
			err := verifyProcessOrFileData(summary.ProcessData, processData, "Process")
			if err != nil {
				return nil, err
			}
			log.Info().Msgf("Summary data found for process: %v", processData)
			fileData := map[string]string{
				"/etc/hosts":                         "/usr/local/bin/php",
				"/lib/x86_64-linux-gnu/libc-2.19.so": "/bin/sed",
			}
			err = verifyProcessOrFileData(summary.FileData, fileData, "File")
			if err != nil {
				return nil, err
			}
			log.Info().Msgf("Summary data found for file: %v", fileData)
			flag := 0
			egressData := map[string]string{
				"protocol":  "TCP",
				"command":   "/usr/local/bin/php",
				"ip":        "svc/mysql",
				"port":      "3306",
				"labels":    "app=mysql",
				"namespace": "wordpress-mysql",
			}
			for _, e := range summary.EgressConnection {
				if e.Protocol == egressData["protocol"] && e.Command == egressData["command"] && e.IP == egressData["ip"] && e.Port == egressData["port"] && e.Labels == egressData["labels"] && e.Namespace == egressData["namespace"] {
					flag = 1
					break
				}
			}
			if flag == 0 {
				return nil, err
			}
			log.Info().Msgf("Summary data found for egress: %v", egressData)
			return summary, nil
		} else if podPrefix == "mysql" {
			processData := map[string]string{
				"/bin/date":      "/bin/bash",
				"/usr/bin/mysql": "/bin/bash",
			}
			err := verifyProcessOrFileData(summary.ProcessData, processData, "Process")
			if err != nil {
				return nil, err
			}
			log.Info().Msgf("Summary data found for process: %v", processData)
			fileData := map[string]string{
				"/run/mysqld/mysqld.pid":                          "/usr/sbin/mysqld",
				"/var/lib/mysql/mysql/servers.frm": "/usr/sbin/mysqld",
			}
			err = verifyProcessOrFileData(summary.FileData, fileData, "File")
			if err != nil {
				return nil, err
			}
			log.Info().Msgf("Summary data found for file: %v", fileData)
			flag := 0
			ingressData := map[string]string{
				"protocol":  "TCP",
				"command":   "/usr/sbin/mysqld",
				"ip":        "wordpress",
				"port":      "3306",
				"labels":    "app=wordpress",
				"namespace": "wordpress-mysql",
			}
			for _, i := range summary.IngressConnection {
				if strings.Contains(i.Protocol, ingressData["protocol"]) && i.Command == ingressData["command"] && strings.Contains(i.IP, ingressData["ip"]) && i.Port == ingressData["port"] && i.Namespace == ingressData["namespace"] && i.Labels == ingressData["labels"] {
					flag = 1
					break
				}
			}
			if flag == 0 {
				return nil, err
			}
			log.Info().Msgf("Summary data found for ingress: %v", ingressData)
			flag = 0
			bindData := map[string]string{
				"protocol": "AF_UNIX",
				"command": "/usr/sbin/mysqld",
				"bind":    "/var/run/mysqld/mysqld.sock",
			}
			for _, b := range summary.BindConnection {
				if b.Command == bindData["command"] && b.BindAddress == bindData["bind"] && b.Protocol == bindData["protocol"] {
					flag = 1
					break
				}
			}
			if flag == 0 {
				return nil, err
			}
			log.Info().Msgf("Summary data found for bind: %v", bindData)
			return summary, nil
		}
	}

	return nil, err
}

var _ = Describe("Smoke", func() {

	BeforeEach(func() {
		//
	})

	AfterEach(func() {
		util.KarmorLogStop()
		//
	})
	count := 0

	Describe("Discovery Engine Test", func() {
		It("Testing for system policy", func() {

			log.Info().Msg("Initiating system policy discovery")

			// policy specific rules

			for count = 0; count < 10; count++ {
				foundRule = map[string]bool{}
				policies, found, err := discoverSysPolicy("wordpress-mysql", "app=wordpress")
				if len(policies) < 1 {
					// Sleep for 30 seconds
					time.Sleep(30 * time.Second)
					continue
				}
				Expect(err).To(BeNil())
				totalRules := len(expectedFileDirs) + len(expectedFilePaths) + len(expectedProcessPaths) + len(expectedProcessDir)
				Expect(found).To(Equal(totalRules))
				for _, policy := range policies {
					Expect(policy.APIVersion).To(Equal("security.kubearmor.com/v1"))
					Expect(policy.Kind).To(Equal("KubeArmorPolicy"))
					Expect(policy.Metadata["namespace"]).To(Equal("wordpress-mysql"))
					Expect(policy.Spec.Action).To(Equal("Allow"))
					Expect(policy.Spec.Selector.MatchLabels["app"]).To(Equal("wordpress"))
					Expect(policy.Spec.Severity).To(Equal(1))
				}
				if len(policies) > 0 {
					break
				}
			}
			Expect(count).ToNot(Equal(10), "Failed to discover system policies")

		})
		It("Testing for network policy", func() {

			log.Info().Msg("Initiating network policy discovery")

			for count = 0; count < 10; count++ {
				foundRule = map[string]bool{}
				// Check whether the WordPress service is running or not using the curl command
				_, err := exec.Command("curl", "-d", `WORDPRESS_DB_HOST="mysql"`, "-d", `WORDPRESS_DB_PASSWORD="root-password"`, "-d", `wp-submit="Log In"`, "-d", `redirect_to="http://localhost:8000/wp-admin/"`, "-d", "testcookie=1", "http://localhost:8000/wp-admin/install.php").Output()
				if err != nil {
					log.Error().Msgf("Failed to apply curl command: %v", err)
				}

				time.Sleep(10 * time.Second)

				// Discover network policies for the WordPress MySQL pod
				policies, err := discoverNetworkPolicy("wordpress-mysql", "app=wordpress")
				if len(policies) < 1 {
					// Sleep for 30 seconds before checking again
					time.Sleep(30 * time.Second)
					continue
				}

				Expect(err).To(BeNil())

				// Validate the discovered network policies
				for _, policy := range policies {
					Expect(policy.TypeMeta.Kind).To(Equal("NetworkPolicy"))
					Expect(policy.TypeMeta.APIVersion).To(Equal("networking.k8s.io/v1"))
					Expect(policy.ObjectMeta.Namespace).To(Equal("wordpress-mysql"))
				}

				if len(policies) > 0 {
					break
				}
			}
			Expect(count).ToNot(Equal(10), "Failed to discover network policies")

		})
		It("Testing summary output for wordpress pod", func() {

			log.Info().Msg("Initiating summary output for wordpress pod")
			summary, err := getSysSummary("wordpress", "wordpress-mysql")
			Expect(err).To(BeNil())

			Expect(summary).NotTo(BeNil())
			Expect(summary.ClusterName).To(Equal("default"))
			Expect(summary.Namespace).To(Equal("wordpress-mysql"))
			Expect(summary.Label).To(Equal("app=wordpress"))
			Expect(summary.ContainerName).To(Equal("wordpress"))

		})
		It("Testing summary output for mysql pod", func() {
			log.Info().Msg("Initiating summary output for mysql pod")
			summary, err := getSysSummary("mysql", "wordpress-mysql")
			Expect(err).To(BeNil())
			Expect(summary).NotTo(BeNil())
			Expect(summary.ClusterName).To(Equal("default"))
			Expect(summary.Namespace).To(Equal("wordpress-mysql"))
			Expect(summary.Label).To(Equal("app=mysql"))
			Expect(summary.ContainerName).To(Equal("mysql"))

		})
	})
})
