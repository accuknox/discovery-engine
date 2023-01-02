package recommendpolicy

import (
	"context"

	"github.com/accuknox/auto-policy-discovery/src/cluster"
	cfg "github.com/accuknox/auto-policy-discovery/src/config"
	logger "github.com/accuknox/auto-policy-discovery/src/logging"
	"github.com/accuknox/auto-policy-discovery/src/systempolicy"
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

	log.Info().Msg("Recommended policy cron job started")

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

	if !isLatest() {
		if _, err := DownloadAndUnzipRelease(); err != nil {
			log.Error().Msgf("Unable to download %v", err.Error())
		}
	}
	client := cluster.ConnectK8sClient()
	deployments, err := client.AppsV1().Deployments("").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		log.Error().Msg(err.Error())
	}
	systempolicy.InitSysPolicyDiscoveryConfiguration()
	for _, d := range deployments.Items {
		if d.Namespace == "kube-system" {
			continue
		}
		policies, err := generatePolicy(d)
		if err != nil {
			log.Error().Msg(err.Error())
		}

		systempolicy.UpdateSysPolicies(policies)
	}
}
