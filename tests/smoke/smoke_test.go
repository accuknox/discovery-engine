package smoke_test

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/accuknox/auto-policy-discovery/src/types"
	"github.com/kubearmor/KubeArmor/tests/util"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/rs/zerolog/log"
	nv1 "k8s.io/api/networking/v1"
)

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

func checkPod(name string, ant string, ns string) {
	pods, err := util.K8sGetPods(name, ns, []string{ant}, 60)
	Expect(err).To(BeNil())
	Expect(len(pods)).To(Equal(1))
}

var _ = BeforeSuite(func() {
	// install discovery-engine
	_, err := util.Kubectl(fmt.Sprintf("apply -f https://raw.githubusercontent.com/kubearmor/discovery-engine/dev/deployments/k8s/deployment.yaml"))
	Expect(err).To(BeNil())
	checkPod("discovery-engine-",
		"container.apparmor.security.beta.kubernetes.io/discovery-engine: localhost/kubearmor-accuknox-agents-discovery-engine-discovery-engine", "accuknox-agents")

	//install wordpress-mysql app
	err = util.K8sApply([]string{"res/wordpress-mysql-deployment.yaml"})
	Expect(err).To(BeNil())
	checkPod("wordpress-",
		"container.apparmor.security.beta.kubernetes.io/wordpress: localhost/kubearmor-wordpress-mysql-wordpress-wordpress", "wordpress-mysql")
	checkPod("mysql-",
		"container.apparmor.security.beta.kubernetes.io/mysql: localhost/kubearmor-wordpress-mysql-mysql-mysql", "wordpress-mysql")

	// delete all KSPs
	err = util.DeleteAllKsp()
	Expect(err).To(BeNil())

	// enable kubearmor port forwarding
	err = util.KubearmorPortForward()
	Expect(err).To(BeNil())
})

var _ = AfterSuite(func() {
	util.KubearmorPortForwardStop()
})

func discoversyspolicy(ns string, l string, rules []string, maxcnt int) (types.KubeArmorPolicy, error) {
	policy := types.KubeArmorPolicy{}
	var err error
	for cnt := 0; cnt < maxcnt; cnt++ {
		flag := 0
		cmd, err := exec.Command("karmor", "discover", "-n", ns, "-l", l, "-f", "json").Output()
		if err != nil {
			log.Error().Msgf("Failed to apply the `karmor discover` command : %v", err)
		}
		err = json.Unmarshal(cmd, &policy)
		if err != nil {
			log.Error().Msgf("Failed to unmarshal the policy : %v", err)
		}
		for _, rule := range rules {
			value := getMatchPath(policy, rule)
			if value == rule {
				flag = 1
			} else {
				flag = 0
				break
			}
		}
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
		cmd, err := exec.Command("karmor", "discover", "-n", ns, "--policy", "NetworkPolicy", "-f", "json").Output()
		if err != nil {
			log.Error().Msgf("Failed to apply the `karmor discover` command : %v", err)
		}
		jsonObjects := strings.Split(string(cmd), "}\n{")
		fmt.Println("=========>value", jsonObjects)
		for i, jsonObject := range jsonObjects {
			policy := &nv1.NetworkPolicy{}

			if i > 0 {
				jsonObject = "{" + jsonObject
			}
			if i < len(jsonObjects)-1 {
				jsonObject = jsonObject + "}"
			}
			err = json.Unmarshal([]byte(jsonObject), policy)
			if err != nil {
				log.Error().Msgf("Failed to unmarshal the policy : %v", err)
			}
			policies = append(policies, *policy)
		}
		for i := range policies {
			var p string
			var port int
			if policies[i].Spec.PodSelector.MatchLabels["app"] == "wordpress" {
				for _, e := range policies[i].Spec.Egress {
					if e.Ports[0].Port != nil {
						p = (string(*e.Ports[0].Protocol))
						port = e.Ports[0].Port.IntValue()
						if p == "TCP" && port == 3306 {
							flag += 1
						}
					} else {
						p = (string(*e.Ports[0].Protocol))
						if p == "UDP" {
							flag += 1
						}
					}
				}
				if flag == 0 || flag == 1 {
					time.Sleep(10 * time.Second)
					break
				}
			} else if policies[i].Spec.PodSelector.MatchLabels["app"] == "mysql" {
				for _, i := range policies[i].Spec.Ingress {
					if i.Ports[0].Port != nil {
						p = (string(*i.Ports[0].Protocol))
						port = i.Ports[0].Port.IntValue()
						if p == "UDP" && port == 3306 {
							flag_i += 1
						}
					} else {
						p = (string(*i.Ports[0].Protocol))
						if p == "UDP" {
							flag_i += 1
						}
					}
				}
				if flag_i == 0 {
					time.Sleep(10 * time.Second)
					break
				}
			}
		}
		fmt.Printf("flag : %v", flag)
		fmt.Printf("flag_i : %v", flag_i)
		if flag == 2 && flag_i > 0 {
			return policies, err
		}
	}
	return []nv1.NetworkPolicy{}, err
}

var _ = Describe("Smoke", func() {

	BeforeEach(func() {

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
			policy, err := discovernetworkpolicy("wordpress-mysql", 10)
			test, _ := json.Marshal(policy)
			fmt.Println("=========>value", string(test))
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
