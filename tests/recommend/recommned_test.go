package recommend_test

import (
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/accuknox/auto-policy-discovery/src/cluster"
	"github.com/accuknox/auto-policy-discovery/src/recommendpolicy"
	"github.com/accuknox/auto-policy-discovery/src/types"
	"github.com/kubearmor/discovery-engine/tests/util"
	"github.com/rs/zerolog"
)

var log *zerolog.Logger

func GetPolicy() []types.KnoxSystemPolicy {
	nsNotFilter := []string{"kube-system"}

	deployments := cluster.GetDeploymentsFromK8sClient()
	if deployments == nil {
		log.Error().Msg("Error getting Deployments from k8s client.")
		return nil
	}
	replicaSets := cluster.GetReplicaSetsFromK8sClient()
	if replicaSets == nil {
		log.Error().Msg("Error getting ReplicaSets from k8s client")
		return nil
	}
	statefulSets := cluster.GetStatefulSetsFromK8sClient()
	if statefulSets == nil {
		log.Error().Msg("Error getting StatefulSets from k8s client")
		return nil
	}
	daemonSets := cluster.GetDaemonSetsFromK8sClient()
	if daemonSets == nil {
		log.Error().Msg("Error getting DaemonSets from k8s client")
		return nil
	}

	policies := recommendpolicy.GetHardenPolicy(deployments, replicaSets, statefulSets, daemonSets, nsNotFilter)

	return policies
}

func checkPod(name string, ant string, ns string) {
	pods, err := util.K8sGetPods(name, ns, []string{ant}, 60)
	Expect(err).To(BeNil())
	Expect(len(pods)).To(Equal(1))
}

var _ = BeforeSuite(func() {

	// create namespace
	_, err := util.Kubectl(fmt.Sprintf("create namespace rs-demo"))
	Expect(err).To(BeNil())

	// install replicaset
	err = util.K8sApply([]string{"conf/replicaset.yaml"})
	Expect(err).To(BeNil())

	// check for replicaset pod
	checkPod("nginx-rs-",
		"container.apparmor.security.beta.kubernetes.io/nginx: localhost/kubearmor-rs-demo-nginx-rs-nginx", "rs-demo")

	// install statefulset
	err = util.K8sApply([]string{"conf/statefulset.yaml"})
	Expect(err).To(BeNil())

	// check for statefulset pod
	checkPod("my-statefulset-",
		"container.apparmor.security.beta.kubernetes.io/my-container: localhost/kubearmor-rs-demo-my-statefulset-my-container", "rs-demo")
})

var _ = AfterSuite(func() {

	// delete namespace
	_, err := util.Kubectl(fmt.Sprintf("delete namespace rs-demo"))
	Expect(err).To(BeNil())
})

var _ = Describe("Recommned", func() {

	Describe("Get hardening policy ", func() {
		It("for replicaset", func() {
			flag := false
			policy := GetPolicy()
			Expect(policy).NotTo(BeNil())
			Expect(len(policy)).NotTo(Equal(0))
			for _, p := range policy {
				if p.Metadata["namespace"] == "rs-demo" && p.Spec.Selector.MatchLabels["app"] == "replicaset-app" {
					flag = true
					break
				}
			}
			Expect(flag).To(Equal(true))
		})
		It("for statefulset", func() {
			flag := false
			policy := GetPolicy()
			Expect(policy).NotTo(BeNil())
			Expect(len(policy)).NotTo(Equal(0))
			for _, p := range policy {
				if p.Metadata["namespace"] == "rs-demo" && p.Spec.Selector.MatchLabels["app"] == "statefulset-app" {
					flag = true
					break
				}
			}
			Expect(flag).To(Equal(true))
		})
	})
})
