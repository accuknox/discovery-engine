package recommendpolicy

import (
	"context"

	"github.com/accuknox/auto-policy-discovery/src/admissioncontrollerpolicy"
	"github.com/accuknox/auto-policy-discovery/src/cluster"
	cfg "github.com/accuknox/auto-policy-discovery/src/config"
	logger "github.com/accuknox/auto-policy-discovery/src/logging"
	"github.com/accuknox/auto-policy-discovery/src/systempolicy"
	"github.com/accuknox/auto-policy-discovery/src/types"
	"github.com/robfig/cron"
	"github.com/rs/zerolog"
	v1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var log *zerolog.Logger

// ====================== //
// == Global Variables == //
// ====================== //

// RecommendWorkerStatus global worker
var RecommendWorkerStatus string

// RecommendCronJob for cron job
var RecommendCronJob *cron.Cron

// RecommendStopChan sync.WaitGroup
var RecommendStopChan chan struct{}

// const values
const (
	// operation mode
	opModeNoop    = 0
	opModeCronjob = 1

	// status
	statusRunning = "running"
	statusIdle    = "idle"
)

// CurrentVersion stores the current version of policy-template
var CurrentVersion string

// LatestVersion stores the latest version of policy-template
var LatestVersion string

// LabelMap is an alias for map[string]string
type LabelMap = map[string]string

// DeployNsName stores the identified deployments in a namespace
var DeployNsName []types.Deployment

// init Function
func init() {
	log = logger.GetInstance()
	RecommendWorkerStatus = statusIdle
	RecommendStopChan = make(chan struct{})
}

// StartRecommendWorker starts the recommended worker
func StartRecommendWorker() {
	if RecommendWorkerStatus != statusIdle {
		log.Info().Msg("There is no idle recommend policy worker")

		return
	}
	if cfg.GetCfgRecOperationMode() == opModeNoop { // Do not run the operation
		log.Info().Msg("Recommendation operation mode is NOOP ... NO RECOMMENDED POLICY")
	} else if cfg.GetCfgRecOperationMode() == opModeCronjob { // every time intervals
		DeployNsName = []types.Deployment{}
		log.Info().Msg("Recommended policy cron job started")
		RecommendPolicyMain()
		StartRecommendCronJob()
	} else { // one-time generation
		RecommendPolicyMain()
		log.Info().Msgf("Policy Recommendation onetime job done")
	}
}

// StopRecommendWorker stops the recommendation worker
func StopRecommendWorker() {
	if cfg.GetCfgRecOperationMode() == opModeCronjob { // every time intervals
		StopRecommendCronJob()
	} else {
		if RecommendWorkerStatus != statusRunning {
			log.Info().Msg("There is no running policy recommendation worker")
			return
		}
	}
}

// StartRecommendCronJob starts the recommendation cronjob
func StartRecommendCronJob() {
	// init cron job
	RecommendCronJob = cron.New()
	err := RecommendCronJob.AddFunc(cfg.GetCfgRecCronJobTime(), RecommendPolicyMain) // time interval
	if err != nil {
		log.Error().Msg(err.Error())
		return
	}
	RecommendCronJob.Start()

	go initDeploymentWatcher()

}

// StopRecommendCronJob stops the recommendation cronjob
func StopRecommendCronJob() {
	if RecommendCronJob != nil {
		log.Info().Msg("Got a signal to terminate the auto system policy discovery")

		close(RecommendStopChan)

		RecommendCronJob.Stop() // Stop the scheduler (does not stop any jobs already running).

		RecommendCronJob = nil
	}
}

// RecommendPolicyMain generates recommended policies from policy-template GH
func RecommendPolicyMain() {

	nsNotFilter := cfg.CurrentCfg.ConfigSysPolicy.NsNotFilter
	client := cluster.ConnectK8sClient()
	if client == nil {
		return
	}
	deployments, err := client.AppsV1().Deployments("").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		log.Error().Msg(err.Error())
		return
	}
	replicaSets, err := client.AppsV1().ReplicaSets("").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		log.Error().Msg("Error getting replicasets err=" + err.Error())
		return
	}
	statefulSets, err := client.AppsV1().StatefulSets("").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		log.Error().Msg("Error getting statefulsets err=" + err.Error())
		return
	}
	daemonsets, err := client.AppsV1().DaemonSets("").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		log.Error().Msg("Error getting daemonsets err=" + err.Error())
		return
	}

	systempolicy.InitSysPolicyDiscoveryConfiguration()
	policies := GetHardenPolicy(deployments, replicaSets, statefulSets, daemonsets, nsNotFilter)
	if policies == nil {
		log.Error().Msg("Error generating hardened policies")
		return
	}
	systempolicy.UpdateSysPolicies(policies)

	admissioncontrollerpolicy.InitAdmissionControllerPolicyDiscoveryConfiguration()

	nsNotFilterAdmissionControllerPolicy := cfg.CurrentCfg.ConfigAdmissionControllerPolicy.NsNotFilter
	nsFilterAdmissionControllerPolicy := cfg.CurrentCfg.ConfigAdmissionControllerPolicy.NsFilter
	recommendAdmissionControllerPolicy := cfg.GetCfgRecommendAdmissionControllerPolicy()

	for _, d := range deployments.Items {
		deploy := uniqueNsDeploy(d.Name, d.Namespace)

		if deploy != nil {
			DeployNsName = append(DeployNsName, *deploy)
		}

		for _, ns := range nsNotFilter {
			if d.Namespace != ns {
				generateHardenPolicy(d.Name, d.Namespace, d.Spec.Template.Labels)
			}
		}

		if recommendAdmissionControllerPolicy &&
			isNamespaceAllowed(d.Namespace, nsNotFilterAdmissionControllerPolicy, nsFilterAdmissionControllerPolicy) {
			generateAdmissionControllerPolicy(d.Name, d.Namespace, d.Spec.Template.Labels)
		}
	}

	if recommendAdmissionControllerPolicy {
		genericAdmissionControllerPolicyList := cfg.CurrentCfg.ConfigAdmissionControllerPolicy.GenericPolicyList
		generateGenericAdmissionControllerPolicy(genericAdmissionControllerPolicyList)
	}
}

func generateHardenPolicy(name, namespace string, labels LabelMap) []types.KnoxSystemPolicy {
	log.Info().Msgf("Generating hardening policy for: %v in namespace: %v", name, namespace)
	policies, err := generateKnoxSystemPolicy(name, namespace, labels)

	if err != nil {
		log.Error().Msg(err.Error())
		return nil
	}
	return policies
}

func generateAdmissionControllerPolicy(name, namespace string, labels LabelMap) {
	policies, policiesToBeDeleted := generateKyvernoPolicy(name, namespace, labels)
	admissioncontrollerpolicy.DeleteKyvernoPolicies(policiesToBeDeleted, namespace, labels)

	// labels need to be passed as argument because labels in policies are set as preconditions
	// deriving labels back from preconditions is error prone due to presence of other preconditions
	admissioncontrollerpolicy.UpdateOrInsertKyvernoPolicies(policies, labels, false)
}

func generateGenericAdmissionControllerPolicy(genericAdmissionControllerPolicyList []string) {
	policies := generateGenericKyvernoPolicy(genericAdmissionControllerPolicyList)
	admissioncontrollerpolicy.UpdateOrInsertKyvernoPolicies(policies, map[string]string{}, true)
}

func uniqueNsDeploy(deployName, deployNamespace string) *types.Deployment {

	deploy := types.Deployment{}
	found := false
	for _, data := range DeployNsName {
		if data.Name == deployName && data.Namespace == deployNamespace {
			found = true
			break
		}
	}
	if !found {
		deploy = types.Deployment{
			Name:      deployName,
			Namespace: deployNamespace,
		}
	}

	return &deploy
}

func GetHardenPolicy(deployments *v1.DeploymentList, replicaSets *v1.ReplicaSetList, statefulSets *v1.StatefulSetList, daemonSets *v1.DaemonSetList, nsNotFilter []string) []types.KnoxSystemPolicy {

	var policies []types.KnoxSystemPolicy
	if !isLatest() {
		version, err := DownloadAndUnzipRelease()
		if err != nil {
			log.Error().Msgf("Unable to download %v", err.Error())
			return nil
		}
		log.Info().Msgf("Downloaded version: %v", version)
	}
	for _, d := range deployments.Items {
		deploy := uniqueNsDeploy(d.Name, d.Namespace)

		if deploy != nil {
			DeployNsName = append(DeployNsName, *deploy)
		}

		for _, ns := range nsNotFilter {
			if d.Namespace != ns && len(d.ObjectMeta.OwnerReferences) == 0 {
				policies = append(policies, generateHardenPolicy(d.Name, d.Namespace, d.Spec.Template.Labels)...)
			}
		}
	}

	for _, r := range replicaSets.Items {
		for _, ns := range nsNotFilter {
			if r.Namespace != ns && len(r.ObjectMeta.OwnerReferences) == 0 {
				policies = append(policies, generateHardenPolicy(r.Name, r.Namespace, r.Spec.Template.Labels)...)
			}
		}
	}

	for _, s := range statefulSets.Items {
		for _, ns := range nsNotFilter {
			if s.Namespace != ns && len(s.ObjectMeta.OwnerReferences) == 0 {
				policies = append(policies, generateHardenPolicy(s.Name, s.Namespace, s.Spec.Template.Labels)...)
			}
		}
	}

	for _, ds := range daemonSets.Items {
		for _, ns := range nsNotFilter {
			if ds.Namespace != ns && len(ds.ObjectMeta.OwnerReferences) == 0 {
				policies = append(policies, generateHardenPolicy(ds.Name, ds.Namespace, ds.Spec.Template.Labels)...)
			}
		}
	}
	return policies
}
