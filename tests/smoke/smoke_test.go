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
	// if sys == "file" {
	// 	return checkPath(policy.Spec.File.MatchPaths, str)
	// }
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
		cmd, err := exec.Command("karmor", "discover", "-n", ns, "-l", l, "-f", "json").Output()
		if err != nil {
			log.Error().Msgf("Failed to apply the `karmor discover` command : %v", err)
		}
		err = json.Unmarshal(cmd, &policy)
		if err != nil {
			log.Error().Msgf("Failed to unmarshal the policy : %v", err)
		}
		test, _ := json.Marshal(policy)
		fmt.Println("=========>value", string(test))
		for _, rule := range rules {
			value := getMatchPath(policy, rule)
			if value == rule {
				return policy, err
			} else {
				break
			}
		}
		time.Sleep(10 * time.Second)
	}
	return policy, err
}

func discovernetworkpolicy(ns string, maxcnt int) ([]nv1.NetworkPolicy, error) {
	policies := []nv1.NetworkPolicy{}
	var err error
	for cnt := 0; cnt < maxcnt; cnt++ {
		flag := 0
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
			for i := range policies {
				if policies[i].Spec.PodSelector.MatchLabels["app"] == "wordpress" {
					if policies[i].Spec.Egress != nil {
						var p string
						if policies[i].Spec.Egress[0].Ports[0].Port != nil {
							p = (string(*policies[i].Spec.Egress[0].Ports[0].Protocol))
							if p == "TCP" {
								flag = 1
								return policies, err
							}
						} else {
							p = (string(*policies[i].Spec.Egress[0].Ports[0].Protocol))
							if p == "UDP" {
								flag = 1
								return policies, err
							}
						}
					}
				}
			}
			if flag == 0 {
				time.Sleep(10 * time.Second)
				break
			}
		}
	}
	return policies, err
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
			rules := []string{"/usr/local/bin/php", "/usr/local/bin/apache2-foreground"}
			policy, err := discoversyspolicy("wordpress-mysql", "app=wordpress", rules, 10)
			Expect(err).To(BeNil())

			Expect(policy.APIVersion).To(Equal("security.kubearmor.com/v1"))
			Expect(policy.Kind).To(Equal("KubeArmorPolicy"))
			Expect(policy.Metadata["namespace"]).To(Equal("wordpress-mysql"))
			Expect(policy.Spec.Action).To(Equal("Allow"))
			Expect(policy.Spec.Selector.MatchLabels["app"]).To(Equal("wordpress"))

			value := getMatchPath(policy, "/usr/local/bin/php")
			Expect(value).To(Equal("/usr/local/bin/php"))

			value = getMatchPath(policy, "/usr/local/bin/apache2-foreground")
			Expect(value).To(Equal("/usr/local/bin/apache2-foreground"))

			Expect(policy.Spec.Severity).To(Equal(1))
		})
		It("testing for network policy", func() {
			policy, err := discovernetworkpolicy("wordpress-mysql", 10)
			test, _ := json.Marshal(policy)
			fmt.Println("=========>value", string(test))
			Expect(err).To(BeNil())
			for i := range policy {
				Expect(policy[i].TypeMeta.Kind).To(Equal("NetworkPolicy"))
				Expect(policy[i].TypeMeta.APIVersion).To(Equal("networking.k8s.io/v1"))
				Expect(policy[i].ObjectMeta.Namespace).To(Equal("wordpress-mysql"))

				if policy[i].Spec.PodSelector.MatchLabels["app"] == "wordpress" {
					if policy[i].Spec.Egress != nil {
						pt := string(policy[i].Spec.PolicyTypes[0])
						Expect(pt).To(Equal("Egress"))

						if policy[i].Spec.Egress[0].Ports[0].Port != nil {
							p := "TCP"
							Expect(p).To(Equal("TCP"))
						} else {
							p := "UDP"
							Expect(p).To(Equal("UDP"))
						}
					} else {
						pt := string(policy[i].Spec.PolicyTypes[0])
						Expect(pt).To(Equal("Ingress"))

						if policy[i].Spec.Ingress[0].Ports[0].Port != nil {
							p := "TCP"
							Expect(p).To(Equal("TCP"))
						} else {
							p := "UDP"
							Expect(p).To(Equal("UDP"))
						}
					}
				} else if policy[i].Spec.Egress != nil {
					pt := string(policy[i].Spec.PolicyTypes[0])
					Expect(pt).To(Equal("Egress"))
					var p string
					if policy[i].Spec.Egress[0].Ports[0].Port != nil {
						p = "TCP"
						Expect(p).To(Equal("TCP"))
					} else {
						p = "UDP"
						Expect(p).To(Equal("UDP"))
					}
				} else if policy[i].Spec.Ingress != nil {
					pt := string(policy[i].Spec.PolicyTypes[0])
					Expect(pt).To(Equal("Ingress"))
					var p string
					if policy[i].Spec.Ingress[0].Ports[0].Port != nil {
						p = "TCP"
						Expect(p).To(Equal("TCP"))
					} else {
						p = "UDP"
						Expect(p).To(Equal("UDP"))
					}
				}
			}
		})
	})
})
