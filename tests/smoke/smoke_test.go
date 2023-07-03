package smoke_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/accuknox/auto-policy-discovery/src/types"
	"github.com/kubearmor/discovery-engine/tests/util"
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
		if policies[i].Spec.PodSelector.MatchLabels["app"] == "wordpress" && flag != 1 {
			flag = 0
			for _, e := range policies[i].Spec.Egress {
				if e.Ports[0].Port != nil {
					if e.Ports[0].Protocol != nil {
						p := (string(*e.Ports[0].Protocol))

						port := e.Ports[0].Port.IntValue()
						if p == "TCP" && port == 3306 {
							flag = 1
						}
					}
				}
			}
		} else if policies[i].Spec.PodSelector.MatchLabels["app"] == "mysql" && flag_i != 1 {
			flag_i = 0
			for _, i := range policies[i].Spec.Ingress {
				if i.Ports[0].Port != nil {
					if i.Ports[0].Protocol != nil {
						p := (string(*i.Ports[0].Protocol))

						port := i.Ports[0].Port.IntValue()
						if p == "TCP" && port == 3306 {
							flag_i = 1
						}
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
	// check discovery-engine pod status
	checkPod("discovery-engine-",
		"container.apparmor.security.beta.kubernetes.io/discovery-engine: localhost/kubearmor-accuknox-agents-discovery-engine-discovery-engine", "accuknox-agents")

	//install wordpress-mysql app
	err := util.K8sApply([]string{"res/wordpress-mysql-deployment.yaml"})
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

		fmt.Println("KubeArmor Security Policy :\n", string(cmd))
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

		fmt.Println("Network Policies : \n", yamls)
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

var _ = Describe("Smoke", func() {

	BeforeEach(func() {
		//
	})

	AfterEach(func() {
		util.KarmorLogStop()
		//
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
			// checking whether wordpress service is running or not using curl command
			for i := 0; i < 10; i++ {
				_, err := exec.Command("curl", "-X", "POST", "-d", `WORDPRESS_DB_HOST="mysql"`, "-d", `WORDPRESS_DB_PASSWORD="root-password"`, "-d", `wp-submit="Log In"`, "-d", `redirect_to="http://localhost:30080/wp-admin/"`, "-d", `"testcookie=1"`, "http://localhost:30080/wp-admin/install.php").Output()
				if err != nil {
					log.Error().Msgf("Failed to apply curl command : %v", err)
				} else {
					log.Info().Msgf("curl successful")
				}
				if err == nil {
					break
				}
				time.Sleep(10 * time.Second)
			}
			policy, err := discovernetworkpolicy("wordpress-mysql", 10)
			Expect(err).To(BeNil())
			Expect(len(policy)).NotTo(Equal(0))
			for i := range policy {
				Expect(policy[i].TypeMeta.Kind).To(Equal("NetworkPolicy"))
				Expect(policy[i].TypeMeta.APIVersion).To(Equal("networking.k8s.io/v1"))
				Expect(policy[i].ObjectMeta.Namespace).To(Equal("wordpress-mysql"))
			}
		})
	})
})
