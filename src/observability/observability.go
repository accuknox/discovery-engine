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
	SystemLogs []*pb.Log
	// Hubble relay logs
	NetworkLogs []*flow.Flow
	// Mutex
	SystemLogsMutex, NetworkLogsMutex, SysObsMutex, NetObsMutex *sync.Mutex
	// for cron job
	ObservabilityCronJob *cron.Cron
)

// =================== //
// == Obs Functions == //
// =================== //

func StartObservability() {
	SystemLogsMutex = &sync.Mutex{}
	NetworkLogsMutex = &sync.Mutex{}

	SysObsMutex = &sync.Mutex{}
	NetObsMutex = &sync.Mutex{}

	ObservabilityCronJob = cron.New()

	err := ObservabilityCronJob.AddFunc(cfg.GetCfgObsCronJobTime(), ProcessObsLogs) // time interval
	if err != nil {
		log.Error().Msg(err.Error())
		return
	}
	ObservabilityCronJob.Start()
	log.Info().Msg("Observability cron job started")
}

func ProcessObsLogs() {
	if cfg.CurrentCfg.ConfigSysPolicy.OperationMode == 1 {
		ProcessSystemLogs()
	}
	if cfg.CurrentCfg.ConfigNetPolicy.OperationMode == 1 {
		ProcessNetworkLogs()
	}
}

func InitObservability() {
	log = logger.GetInstance()
	CfgDB = cfg.GetCfgDB()

	if cfg.IsObservabilityEnabled() {
		StartObservability()
	}
}
