package recommendpolicy

import (
	"context"

	"github.com/accuknox/auto-policy-discovery/src/cluster"
	cfg "github.com/accuknox/auto-policy-discovery/src/config"
	logger "github.com/accuknox/auto-policy-discovery/src/logging"
	"github.com/accuknox/auto-policy-discovery/src/systempolicy"
	"github.com/accuknox/auto-policy-discovery/src/types"
	"github.com/robfig/cron"
	"github.com/rs/zerolog"
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
	OP_MODE_NOOP    = 0
	OP_MODE_CRONJOB = 1
	OP_MODE_ONETIME = 2

	// status
	STATUS_RUNNING = "running"
	STATUS_IDLE    = "idle"
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
	RecommendWorkerStatus = STATUS_IDLE
	RecommendStopChan = make(chan struct{})
}

// StartRecommendWorker starts the recommended worker
func StartRecommendWorker() {
	if RecommendWorkerStatus != STATUS_IDLE {
		log.Info().Msg("There is no idle system policy discovery worker")

		return
	}
	if cfg.GetCfgRecOperationMode() == OP_MODE_NOOP { // Do not run the operation
		log.Info().Msg("Recommendation operation mode is NOOP ... NO RECOMMENDED POLICY")
	} else if cfg.GetCfgRecOperationMode() == OP_MODE_CRONJOB { // every time intervals
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
	if cfg.GetCfgSysOperationMode() == OP_MODE_CRONJOB { // every time intervals
		StopRecommendCronJob()
	} else {
		if RecommendWorkerStatus != STATUS_RUNNING {
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

	if !isLatest() {
		if _, err := DownloadAndUnzipRelease(); err != nil {
			log.Error().Msgf("Unable to download %v", err.Error())
		}
	}
	client := cluster.ConnectK8sClient()
	deployments, err := client.AppsV1().Deployments("").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		log.Error().Msg(err.Error())
		return
	}
	systempolicy.InitSysPolicyDiscoveryConfiguration()
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
	}
}

func generateHardenPolicy(name, namespace string, labels LabelMap) {
	log.Info().Msgf("Generating hardening policy for deployment: %v in namespace: %v", name, namespace)
	policies, err := generatePolicy(name, namespace, labels)
	if err != nil {
		log.Error().Msg(err.Error())
		return
	}
	systempolicy.UpdateSysPolicies(policies)
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
