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
	SystemLogsMutex, NetworkLogsMutex, SysObsMutex, NetObsMutex *sync.Mutex
	// for cron job
	SysObsCronJob, NetObsCronJob *cron.Cron
)

// =================== //
// == Obs Functions == //
// =================== //

func StartSystemObservability() {
	SystemLogsMutex = &sync.Mutex{}
	SysObsMutex = &sync.Mutex{}
	SysObsCronJob = cron.New()

	err := SysObsCronJob.AddFunc(cfg.GetCfgObsCronJobTime(), ProcessSystemLogs) // time interval
	if err != nil {
		log.Error().Msg(err.Error())
		return
	}
	SysObsCronJob.Start()
	log.Info().Msg("System observability cron job started")
}

func StartNetworkObservability() {
	NetworkLogsMutex = &sync.Mutex{}
	NetObsMutex = &sync.Mutex{}
	NetObsCronJob = cron.New()

	err := NetObsCronJob.AddFunc(cfg.GetCfgObsCronJobTime(), ProcessNetworkLogs) // time interval
	if err != nil {
		log.Error().Msg(err.Error())
		return
	}
	NetObsCronJob.Start()
	log.Info().Msg("Network observability cron job started")
}

func InitObservability() {
	log = logger.GetInstance()
	CfgDB = cfg.GetCfgDB()

	if cfg.IsObservabilityEnabled() {
		if config.CurrentCfg.ConfigSysPolicy.OperationMode == 1 {
			StartSystemObservability()
		}
		if config.CurrentCfg.ConfigNetPolicy.OperationMode == 1 {
			StartNetworkObservability()
		}
	}
}
