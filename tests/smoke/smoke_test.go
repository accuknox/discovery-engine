package smoke_test

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"time"

	"github.com/accuknox/auto-policy-discovery/src/types"
	"github.com/kubearmor/KubeArmor/tests/util"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/rs/zerolog/log"
)

func getMatchDir(policy types.KubeArmorPolicy, sys string, str string) string {
	if sys == "file" {
		for i := range policy.Spec.File.MatchDirectories {
			if policy.Spec.File.MatchDirectories[i].Dir == str {
				value := str
				return value
			}
		}
	} else {
		for i := range policy.Spec.Process.MatchDirectories {
			if policy.Spec.Process.MatchDirectories[i].Dir == str {
				value := str
				return value
			}
		}
	}
	return ""
}

func getMatchPath(policy types.KubeArmorPolicy, sys string, str string) string {
	if sys == "file" {
		for i := range policy.Spec.File.MatchPaths {
			if policy.Spec.File.MatchPaths[i].Path == str {
				value := str
				return value
			}
		}
	} else {
		for i := range policy.Spec.Process.MatchPaths {
			if policy.Spec.Process.MatchPaths[i].Path == str {
				value := str
				return value
			}
		}
	}
	return ""
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
	time.Sleep(5 * time.Second)

	//install wordpress-mysql app
	err = util.K8sApply([]string{"res/wordpress-mysql-deployment.yaml"})
	Expect(err).To(BeNil())
	time.Sleep(5 * time.Second)

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

func discover(ns string, l string) (types.KubeArmorPolicy, error) {
	Policy := types.KubeArmorPolicy{}
	Cmd, err := exec.Command("karmor", "discover", "-n", ns, "-l", l, "-f", "json").Output()
	//log.Printf("Cmd : %q", Cmd)
	fmt.Println(json.Valid([]byte(Cmd)))
	if err != nil {
		log.Error().Msgf("Failed to apply the `karmor discover` command : %v", err)
	}
	err = json.Unmarshal(Cmd, &Policy)
	if err != nil {
		log.Error().Msgf("Failed to unmarshal the policy : %v", err)
	}
	//log.Printf("policy : %v", policy)
	return Policy, err
}

var _ = Describe("Smoke", func() {

	BeforeEach(func() {
		checkPod("wordpress-",
			"container.apparmor.security.beta.kubernetes.io/wordpress: localhost/kubearmor-wordpress-mysql-wordpress-wordpress", "wordpress-mysql")
		checkPod("mysql-",
			"container.apparmor.security.beta.kubernetes.io/mysql: localhost/kubearmor-wordpress-mysql-mysql-mysql", "wordpress-mysql")
		checkPod("discovery-engine-",
			"container.apparmor.security.beta.kubernetes.io/discovery-engine: localhost/kubearmor-accuknox-agents-discovery-engine-discovery-engine", "accuknox-agents")
	})

	AfterEach(func() {
		util.KarmorLogStop()
		err := util.DeleteAllKsp()
		Expect(err).To(BeNil())
		// wait for policy deletion
		time.Sleep(5 * time.Second)
	})

	Describe("Auto Policy Discovery", func() {
		It("test", func() {
			policy, err := discover("wordpress-mysql", "app=wordpress")
			Expect(err).To(BeNil())
			Expect(policy.APIVersion).To(Equal("security.kubearmor.com/v1"))
			Expect(policy.Kind).To(Equal("KubeArmorPolicy"))
			Expect(policy.Metadata["namespace"]).To(Equal("wordpress-mysql"))
			Expect(policy.Spec.Action).To(Equal("Allow"))
			Expect(policy.Spec.Selector.MatchLabels["app"]).To(Equal("wordpress"))

			value := getMatchDir(policy, "file", "/etc/")
			Expect(value).To(Equal("/etc/"))

			value = getMatchPath(policy, "file", "/dev/urandom")
			Expect(value).To(Equal("/dev/urandom"))

			value = getMatchPath(policy, "process", "/usr/local/bin/php")
			Expect(value).To(Equal("/usr/local/bin/php"))

			Expect(policy.Spec.Severity).To(Equal(1))
		})
	})
})
