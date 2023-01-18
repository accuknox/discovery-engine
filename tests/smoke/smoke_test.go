package smoke_test

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"github.com/accuknox/auto-policy-discovery/src/types"
	"github.com/kubearmor/KubeArmor/tests/util"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/rs/zerolog/log"
	nv1 "k8s.io/api/networking/v1"
)

func checkDir(mp []types.KnoxMatchDirectories, str string) string {
	for i := range mp {
		if mp[i].Dir == str {
			return str
		}
	}
	return ""
}

func checkPath(mp []types.KnoxMatchPaths, str string) string {
	for i := range mp {
		if mp[i].Path == str {
			return str
		}
	}
	return ""
}

func getMatchDir(policy types.KubeArmorPolicy, sys string, str string) string {
	if sys == "file" {
		return checkDir(policy.Spec.File.MatchDirectories, str)
	}
	return checkDir(policy.Spec.Process.MatchDirectories, str)
}

func getMatchPath(policy types.KubeArmorPolicy, sys string, str string) string {
	if sys == "file" {
		return checkPath(policy.Spec.File.MatchPaths, str)
	}
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
	//time.Sleep(20 * time.Second)
	checkPod("discovery-engine-",
		"container.apparmor.security.beta.kubernetes.io/discovery-engine: localhost/kubearmor-accuknox-agents-discovery-engine-discovery-engine", "accuknox-agents")

	//install wordpress-mysql app
	err = util.K8sApply([]string{"res/wordpress-mysql-deployment.yaml"})
	Expect(err).To(BeNil())
	//time.Sleep(25 * time.Second)
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

func discoversyspolicy(ns string, l string) (types.KubeArmorPolicy, error) {
	policy := types.KubeArmorPolicy{}
	cmd, err := exec.Command("karmor", "discover", "-n", ns, "-l", l, "-f", "json").Output()
	if err != nil {
		log.Error().Msgf("Failed to apply the `karmor discover` command : %v", err)
	}
	err = json.Unmarshal(cmd, &policy)
	if err != nil {
		log.Error().Msgf("Failed to unmarshal the policy : %v", err)
	}
	return policy, err
}

func discovernetworkpolicy(ns string) ([]nv1.NetworkPolicy, error) {
	policies := []nv1.NetworkPolicy{}
	cmd, err := exec.Command("karmor", "discover", "-n", ns, "--policy", "NetworkPolicy", "-f", "json").Output()
	if err != nil {
		log.Error().Msgf("Failed to apply the `karmor discover` command : %v", err)
	}
	jsonObjects := strings.Split(string(cmd), "}\n{")
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
			policy, err := discoversyspolicy("wordpress-mysql", "app=wordpress")
			Expect(err).To(BeNil())
			Expect(policy.APIVersion).To(Equal("security.kubearmor.com/v1"))
			Expect(policy.Kind).To(Equal("KubeArmorPolicy"))
			Expect(policy.Metadata["namespace"]).To(Equal("wordpress-mysql"))
			Expect(policy.Spec.Action).To(Equal("Allow"))
			Expect(policy.Spec.Selector.MatchLabels["app"]).To(Equal("wordpress"))

			value := getMatchDir(policy, "file", "/tmp/")
			Expect(value).To(Equal("/tmp/"))

			value = getMatchPath(policy, "file", "/dev/urandom")
			Expect(value).To(Equal("/dev/urandom"))

			value = getMatchPath(policy, "process", "/usr/local/bin/php")
			Expect(value).To(Equal("/usr/local/bin/php"))

			Expect(policy.Spec.Severity).To(Equal(1))
		})
		It("testing for network policy", func() {
			policy, err := discovernetworkpolicy("wordpress-mysql")
			test, _ := json.Marshal(policy)
			fmt.Println("=========>value", string(test))
			Expect(err).To(BeNil())
			for i := range policy {
				Expect(policy[i].TypeMeta.Kind).To(Equal("NetworkPolicy"))
				Expect(policy[i].TypeMeta.APIVersion).To(Equal("networking.k8s.io/v1"))
				Expect(policy[i].ObjectMeta.Namespace).To(Equal("wordpress-mysql"))

				if policy[i].Spec.PodSelector.MatchLabels["app"] == "wordpress" {
					if policy[i].Spec.Ingress != nil {
						pt := string(policy[i].Spec.PolicyTypes[0])
						Expect(pt).To(Equal("Ingress"))
						p := string(*policy[i].Spec.Ingress[0].Ports[0].Protocol)
						Expect(p).To(Equal("TCP"))
						port := int(policy[i].Spec.Ingress[0].Ports[0].Port.IntVal)
						Expect(port).To(Equal(3306))
						from := policy[i].Spec.Ingress[0].From[0].PodSelector.MatchLabels["app"]
						Expect(from).To(Equal("mysql"))
					} else {
						pt := string(policy[i].Spec.PolicyTypes[0])
						Expect(pt).To(Equal("Egress"))
						p := string(*policy[i].Spec.Egress[0].Ports[0].Protocol)
						Expect(p).To(Equal("UDP"))
						p = string(*policy[i].Spec.Egress[1].Ports[0].Protocol)
						Expect(p).To(Equal("TCP"))
						port := int(policy[i].Spec.Egress[1].Ports[0].Port.IntVal)
						Expect(port).To(Equal(3306))
					}
				} else if policy[i].Spec.Ingress != nil {
					pt := string(policy[i].Spec.PolicyTypes[0])
					Expect(pt).To(Equal("Ingress"))
					p := string(*policy[i].Spec.Ingress[0].Ports[0].Protocol)
					Expect(p).To(Equal("UDP"))
				} else {
					pt := string(policy[i].Spec.PolicyTypes[0])
					Expect(pt).To(Equal("Egress"))
					p := string(*policy[i].Spec.Egress[0].Ports[0].Protocol)
					Expect(p).To(Equal("UDP"))
					p = string(*policy[i].Spec.Egress[1].Ports[0].Protocol)
					Expect(p).To(Equal("TCP"))
					port := int(policy[i].Spec.Egress[1].Ports[0].Port.IntVal)
					Expect(port).To(Equal(3306))
					to := policy[i].Spec.Egress[1].To[0].PodSelector.MatchLabels["app"]
					Expect(to).To(Equal("wordpress"))
				}
			}
		})
	})
})
