package observability

import (
	"sync"

	cfg "github.com/accuknox/auto-policy-discovery/src/config"
	logger "github.com/accuknox/auto-policy-discovery/src/logging"
	"github.com/accuknox/auto-policy-discovery/src/types"
	"github.com/cilium/cilium/api/v1/flow"
	pb "github.com/kubearmor/KubeArmor/protobuf"
	"github.com/robfig/cron"
	"github.com/rs/zerolog"
)

// ====================== //
// == Global Variables == //
// ====================== //

var (
	CfgDB types.ConfigDB
	log   *zerolog.Logger
	// Kubearmor relay logs
	SystemLogs      []*pb.Log
	SystemLogsMutex *sync.Mutex
	// Hubble relay logs
	NetworkLogs      []*flow.Flow
	NetworkLogsMutex *sync.Mutex
	// for cron job
	ObservabilityCronJob *cron.Cron
)

// =================== //
// == Obs Functions == //
// =================== //

func configureCronJob() {
	ObservabilityCronJob = cron.New()

	err := ObservabilityCronJob.AddFunc(cfg.GetCfgObsCronJobTime(), ProcessSystemLogs) // time interval
	if err != nil {
		log.Error().Msg(err.Error())
		return
	}
	err = ObservabilityCronJob.AddFunc(cfg.GetCfgObsCronJobTime(), ProcessNetworkLogs) // time interval
	if err != nil {
		log.Error().Msg(err.Error())
		return
	}
	ObservabilityCronJob.Start()

	log.Info().Msg("Observability cron job started")

}

func InitObservability() {
	log = logger.GetInstance()
	CfgDB = cfg.GetCfgDB()

	if cfg.IsObservabilityEnabled() {
		// Init Mutex
		SystemLogsMutex = &sync.Mutex{}
		NetworkLogsMutex = &sync.Mutex{}

		configureCronJob()
	}
}
