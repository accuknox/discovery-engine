package smoke_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"

	opb "github.com/accuknox/auto-policy-discovery/src/protobuf/v1/observability"
	"github.com/accuknox/auto-policy-discovery/src/types"
	"github.com/kubearmor/KubeArmor/tests/util"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/rs/zerolog/log"
	nv1 "k8s.io/api/networking/v1"
	"sigs.k8s.io/yaml"
)

var stopChan chan struct{}

func checkPath(mp []types.KnoxMatchPaths, str string) string {
	for i := range mp {
		if mp[i].Path == str {
			return str
		}
	}
	return ""
}

func getMatchPath(policy types.KubeArmorPolicy, str string) string {
	return checkPath(policy.Spec.Process.MatchPaths, str)
}

func checksyspolicyrules(rules []string, policy types.KubeArmorPolicy) int {
	flag := 0
	for _, rule := range rules {
		value := getMatchPath(policy, rule)
		if value == rule {
			flag = 1
		} else {
			flag = 0
			break
		}
	}
	return flag
}

func checkntwpolicyrules(policies []nv1.NetworkPolicy) (int, int) {
	flag := 0
	flag_i := 0
	for i := range policies {
		var p string
		var port int
		if policies[i].Spec.PodSelector.MatchLabels["app"] == "wordpress" {
			flag = 0
			for _, e := range policies[i].Spec.Egress {
				if e.Ports[0].Port != nil {
					if e.Ports[0].Protocol != nil {
						p = (string(*e.Ports[0].Protocol))
					}
					port = e.Ports[0].Port.IntValue()
					if p == "TCP" && port == 3306 {
						flag = 1
					}
				}
			}
		} else if policies[i].Spec.PodSelector.MatchLabels["app"] == "mysql" {
			flag_i = 0
			for _, i := range policies[i].Spec.Ingress {
				if i.Ports[0].Port != nil {
					if i.Ports[0].Protocol != nil {
						p = (string(*i.Ports[0].Protocol))
					}
					port = i.Ports[0].Port.IntValue()
					if p == "TCP" && port == 3306 {
						flag_i = 1
					}
				}
			}
		}
		if flag == 1 && flag_i == 1 {
			return flag, flag_i
		}
	}
	return flag, flag_i
}

func findProcessORFileData(ProcFiledata []*opb.SysProcFileSummaryData, source, destination string, dataType string) bool {
	if dataType == "Process" {
		for _, p := range ProcFiledata {
			if p.Source == source && p.Destination == destination && p.Status == "Allow" {
				return true
			}
		}
	}
	if dataType == "File" {
		for _, f := range ProcFiledata {
			if f.Source == source && f.Destination == destination && f.Status == "Allow" {
				return true
			}
		}
	}
	return false
}

func verifyProcessORFileData(ProcFileData []*opb.SysProcFileSummaryData, data map[string]string, dataType string) error {
	if dataType == "Process" {
		for destination, source := range data {
			flag := findProcessORFileData(ProcFileData, source, destination, dataType)
			if !flag {
				return fmt.Errorf("process data is not correct for source : %v, destination : %v", source, destination)
			}
		}
	}
	if dataType == "File" {
		for destination, source := range data {
			flag := findProcessORFileData(ProcFileData, source, destination, dataType)
			if !flag {
				return fmt.Errorf("file data is not correct for source : %v, destination : %v", source, destination)
			}
		}
	}
	return nil
}

// WordpressPortForward enable port forwarding for wordpress
func WordpressPortForward() error {
	if stopChan != nil {
		log.Error().Msgf("wordpress port forward is already in progress")
		return errors.New("wordpress port forward is already in progress")
	}
	ns := "wordpress-mysql"
	pods, err := util.K8sGetPods("^wordpress-..........-.....$", ns, nil, 0)
	if err != nil {
		log.Printf("could not get wordpress pods assuming process mode")
		return nil
	}
	if len(pods) != 1 {
		log.Error().Msgf("len(pods)=%d", len(pods))
		return errors.New("expecting one wordpress pod only")
	}
	log.Printf("found wordpress pod:[%s]", pods[0])
	c, err := util.K8sPortForward(util.PortForwardOpt{
		LocalPort:   8000,
		RemotePort:  80,
		ServiceName: pods[0],
		Namespace:   ns})
	if err != nil {
		log.Error().Msgf("could not do wordpress portforward Error=%s", err.Error())
		return err
	}
	stopChan = c
	return nil
}

// WordpressPortForwardStop stop wordpress port forwarding
func WordpressPortForwardStop() {
	if stopChan == nil {
		return
	}
	close(stopChan)
	stopChan = nil
}

func checkPod(name string, ant string, ns string) {
	pods, err := util.K8sGetPods(name, ns, []string{ant}, 60)
	Expect(err).To(BeNil())
	Expect(len(pods)).To(Equal(1))
}

var _ = BeforeSuite(func() {
	// install discovery-engine
	_, err := util.Kubectl(fmt.Sprintf("apply -f https://raw.githubusercontent.com/kubearmor/discovery-engine/dev/deployments/k8s/deployment.yaml"))
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
	err = WordpressPortForward()
	Expect(err).To(BeNil())

})

var _ = AfterSuite(func() {
	util.KubearmorPortForwardStop()
	WordpressPortForwardStop()
})

func discoversyspolicy(ns string, l string, rules []string, maxcnt int) (types.KubeArmorPolicy, error) {
	policy := types.KubeArmorPolicy{}
	var err error
	for cnt := 0; cnt < maxcnt; cnt++ {
		cmd, err := exec.Command("karmor", "discover", "-n", ns, "-l", l, "-f", "json").Output()
		if err != nil {
			log.Error().Msgf("Failed to apply the `karmor discover` command : %v", err)
		}
		err = json.Unmarshal(cmd, &policy)
		if err != nil {
			log.Error().Msgf("Failed to unmarshal the system policy : %v", err)
		}

		flag := checksyspolicyrules(rules, policy)
		if flag == 1 {
			return policy, err
		}
		time.Sleep(10 * time.Second)
	}
	return types.KubeArmorPolicy{}, err
}

func discovernetworkpolicy(ns string, maxcnt int) ([]nv1.NetworkPolicy, error) {
	policies := []nv1.NetworkPolicy{}
	var err error
	for cnt := 0; cnt < maxcnt; cnt++ {
		flag := 0
		flag_i := 0
		cmd, err := exec.Command("karmor", "discover", "-n", ns, "--policy", "NetworkPolicy", "-f", "yaml").Output()
		if err != nil {
			log.Error().Msgf("Failed to apply the `karmor discover` command : %v", err)
		}

		yamls := strings.Split(string(cmd), "---")
		fmt.Println("=========>value", yamls)
		if len(yamls) > 0 {
			yamls = yamls[:len(yamls)-1]
		}

		for _, yamlobject := range yamls {
			policy := &nv1.NetworkPolicy{}
			err = yaml.Unmarshal([]byte(yamlobject), policy)
			if err != nil {
				log.Error().Msgf("Failed to unmarshal the network policy : %v", err)
			}
			policies = append(policies, *policy)
		}
		flag, flag_i = checkntwpolicyrules(policies)
		if flag == 1 && flag_i == 1 {
			return policies, err
		}
		if flag == 0 || flag_i == 0 {
			time.Sleep(10 * time.Second)
		}
	}
	return []nv1.NetworkPolicy{}, err
}

func getsummary(podName string) *opb.Response {
	res := []*opb.Response{}
	summary, err := exec.Command("karmor", "summary", "-o", "json").Output()
	if err != nil {
		log.Error().Msgf("Failed to apply the `karmor summary` command : %v", err)
	}
	err = json.Unmarshal(summary, &res)
	if err != nil {
		log.Error().Msgf("Failed to unmarshal the command output : %v", err)
	}
	fmt.Println(res)
	for _, summary := range res {
		if strings.Contains(summary.PodName, podName) {
			return summary
		}
	}
	return nil
}

var _ = Describe("Smoke", func() {

	BeforeEach(func() {
		//
	})

	AfterEach(func() {
		util.KarmorLogStop()
	})

	Describe("Auto Policy Discovery", func() {
		It("testing for system policy", func() {
			// policy specific rules
			rules := []string{"/usr/local/bin/php", "/usr/sbin/apache2"}
			policy, err := discoversyspolicy("wordpress-mysql", "app=wordpress", rules, 10)
			Expect(err).To(BeNil())

			Expect(policy.APIVersion).To(Equal("security.kubearmor.com/v1"))
			Expect(policy.Kind).To(Equal("KubeArmorPolicy"))
			Expect(policy.Metadata["namespace"]).To(Equal("wordpress-mysql"))
			Expect(policy.Spec.Action).To(Equal("Allow"))
			Expect(policy.Spec.Selector.MatchLabels["app"]).To(Equal("wordpress"))
			Expect(policy.Spec.Severity).To(Equal(1))
		})
		It("testing for network policy", func() {
			// check whether wordpress service is running or not using curl command
			for i := 0; i <= 30; i++ {
				curl, err := exec.Command("curl", "-d", `WORDPRESS_DB_HOST="mysql"`, "-d", `WORDPRESS_DB_PASSWORD="root-password"`, "-d", `wp-submit="Log In"`, "-d", `redirect_to="http://localhost:8000/wp-admin/"`, "-d", "testcookie=1", "http://localhost:8000/wp-admin/install.php").Output()
				if err != nil {
					log.Error().Msgf("Failed to apply curl command : %v", err)
				}
				if curl != nil {
					break
				}
				time.Sleep(10 * time.Second)
			}
			policy, err := discovernetworkpolicy("wordpress-mysql", 30)
			Expect(err).To(BeNil())
			Expect(len(policy)).NotTo(Equal(0))
			for i := range policy {
				Expect(policy[i].TypeMeta.Kind).To(Equal("NetworkPolicy"))
				Expect(policy[i].TypeMeta.APIVersion).To(Equal("networking.k8s.io/v1"))
				Expect(policy[i].ObjectMeta.Namespace).To(Equal("wordpress-mysql"))
			}
		})
		It("testing summary output for wordpress pod", func() {
			summary := getsummary("wordpress")
			Expect(summary).NotTo(BeNil())
			Expect(summary.ClusterName).To(Equal("default"))
			Expect(summary.Namespace).To(Equal("wordpress-mysql"))
			Expect(summary.Label).To(Equal("app=wordpress"))
			Expect(summary.ContainerName).To(Equal("wordpress"))

			processData := map[string]string{
				"/usr/local/bin/php": "/bin/bash",
				"/usr/bin/head":      "/bin/bash",
			}
			err := verifyProcessORFileData(summary.ProcessData, processData, "Process")
			Expect(err).To(BeNil())

			fileData := map[string]string{
				"/usr/lib/x86_64-linux-gnu/libp11-kit.so.0.0.0": "/usr/local/bin/php",
				"/var/www/html/sedKYTnN1":                       "/bin/sed",
				"/etc/ld.so.cache":                              "/usr/bin/sha1sum",
			}
			err = verifyProcessORFileData(summary.ProcessData, fileData, "File")
			Expect(err).To(BeNil())

			flag := 0
			for _, e := range summary.EgressConnection {
				if e.Protocol == "TCP" && e.Command == "/usr/local/bin/php" && e.IP == "svc/mysql" && e.Port == "3306" && e.Labels == "app=mysql" && e.Namespace == "wordpress-mysql" {
					flag = 1
					break
				}
			}
			Expect(flag).NotTo(Equal(0))
		})
		It("testing summary output for mysql pod", func() {
			summary := getsummary("mysql")
			Expect(summary).NotTo(BeNil())
			Expect(summary.ClusterName).To(Equal("default"))
			Expect(summary.Namespace).To(Equal("wordpress-mysql"))
			Expect(summary.Label).To(Equal("app=mysql"))
			Expect(summary.ContainerName).To(Equal("mysql"))

			processData := map[string]string{
				"/usr/sbin/mysqld": "/bin/bash",
				"/bin/date":        "/bin/bash",
			}
			err := verifyProcessORFileData(summary.ProcessData, processData, "Process")
			Expect(err).To(BeNil())

			fileData := map[string]string{
				"/dev/null":        "/bin/bash",
				"/etc/ld.so.cache": "/bin/cat",
				"/dev/fd/63":       "/usr/bin/mysql",
			}
			err = verifyProcessORFileData(summary.ProcessData, fileData, "File")
			Expect(err).To(BeNil())

			flag := 0
			for _, e := range summary.EgressConnection {
				if e.Protocol == "AF_UNIX" && e.Command == "/usr/bin/mysqladmin" && e.IP == "/var/run/mysqld/mysqld.sock" && e.Port == "0" && e.Labels == "app=mysql" {
					flag = 1
					break
				}
			}
			Expect(flag).To(Equal(1))
			flag = 0

			for _, i := range summary.IngressConnection {
				if i.Protocol == "TCPv6" && i.Command == "/usr/sbin/mysqld" && strings.Contains(i.IP, "wordpress") && i.Port == "3306" && i.Labels == "app=wordpress" && i.Namespace == "wordpress-mysql" {
					flag = 1
					break
				}
			}
			Expect(flag).To(Equal(1))
			flag = 0

			for _, b := range summary.BindConnection {
				if b.Protocol == "AF_INET6" && b.Command == "/usr/sbin/mysqld" && b.BindPort == "3306" {
					flag = 1
					break
				}
			}
			Expect(flag).To(Equal(1))
		})
	})
})
