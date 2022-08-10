package observability

import (
	"sync"

	"github.com/accuknox/auto-policy-discovery/src/config"
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
	SystemLogs []*pb.Log
	// Hubble relay logs
	NetworkLogs []*flow.Flow
	// Mutex
	SystemLogsMutex, NetworkLogsMutex, ObsMutex *sync.Mutex
	// Observability Cronjob
	ObsCronJob *cron.Cron
)

// =================== //
// == Obs Functions == //
// =================== //

func initMutex() {
	ObsMutex = &sync.Mutex{}
	if config.GetCfgObservabilitySysObsStatus() {
		SystemLogsMutex = &sync.Mutex{}
	}
	if config.GetCfgObservabilitySysObsStatus() {
		NetworkLogsMutex = &sync.Mutex{}
	}
}

func InitObservability() {
	log = logger.GetInstance()
	CfgDB = cfg.GetCfgDB()

	if cfg.GetCfgObservabilityEnable() {
		// Init mutex
		initMutex()

		ObsCronJob = cron.New()
		err := ObsCronJob.AddFunc(cfg.GetCfgObservabilityCronJobTime(), ObservabilityCronJob) // time interval
		if err != nil {
			log.Error().Msg(err.Error())
			return
		}
	}
	ObsCronJob.Start()
	log.Info().Msg("Observability cron job started")
}

func ObservabilityCronJob() {
	if config.GetCfgObservabilitySysObsStatus() {
		ProcessSystemLogs()
	}
	if config.GetCfgObservabilityNetObsStatus() {
		ProcessNetworkLogs()
	}
}
