package systempolicy

import (
	"sync"

	cfg "github.com/accuknox/knoxAutoPolicy/src/config"
	"github.com/accuknox/knoxAutoPolicy/src/libs"
	logger "github.com/accuknox/knoxAutoPolicy/src/logging"
	"github.com/accuknox/knoxAutoPolicy/src/plugin"
	types "github.com/accuknox/knoxAutoPolicy/src/types"
	"github.com/rs/zerolog"

	"github.com/robfig/cron"
)

var log *zerolog.Logger

func init() {
	log = logger.GetInstance()
}

// const values
const (
	// operation mode
	OP_MODE_CRONJOB = 1
	OP_MODE_ONETIME = 2

	// status
	STATUS_RUNNING = "running"
	STATUS_IDLE    = "idle"
)

// ====================== //
// == Gloabl Variables == //
// ====================== //

// SystemWorkerStatus global worker
var SystemWorkerStatus string

// for cron job
var SystemCronJob *cron.Cron
var SystemWaitG sync.WaitGroup
var SystemStopChan chan struct{} // for hubble

// init Function
func init() {
	SystemWorkerStatus = STATUS_IDLE
	SystemStopChan = make(chan struct{})
	SystemWaitG = sync.WaitGroup{}
}

// ================ //
// == System Log == //
// ================ //

// getSystemLogs function
func getSystemLogs() []types.KnoxSystemLog {
	systemLogs := []types.KnoxSystemLog{}

	// =============== //
	// == Database  == //
	// =============== //
	if cfg.GetCfgSystemLogFrom() == "db" {
		log.Info().Msg("Get network flow from the database")

		// get system logs from db
		sysLogs := libs.GetSystemLogsFromDB(cfg.GetCfgDB(), cfg.GetCfgOneTime())
		if len(sysLogs) == 0 {
			return nil
		}

		// convert kubearmor system logs -> knox system logs
		systemLogs = plugin.ConvertKubeArmorSystemLogsToKnoxSystemLogs(cfg.GetCfgDB().DBDriver, sysLogs)
	} else {
		log.Error().Msgf("System log source not correct: %s", cfg.GetCfgSystemLogFrom())
		return nil
	}

	return systemLogs
}

// ============================== //
// == Discover System Policy  == //
// ============================== //

// DiscoverSystemPolicyMain function
func DiscoverSystemPolicyMain() {
	if SystemWorkerStatus == STATUS_RUNNING {
		return
	} else {
		SystemWorkerStatus = STATUS_RUNNING
	}

	defer func() {
		SystemWorkerStatus = STATUS_IDLE
	}()

	// // get system logs
	// allSystemkLogs := getSystemkLogs()
	// if allNetworkLogs == nil {
	// 	return
	// }
}

// ==================================== //
// == System Policy Discovery Worker == //
// ==================================== //

// StartSystemCronJob function
func StartSystemCronJob() {
	// init cron job
	SystemCronJob = cron.New()
	err := SystemCronJob.AddFunc(cfg.GetCfgCronJobTime(), DiscoverSystemPolicyMain) // time interval
	if err != nil {
		log.Error().Msg(err.Error())
		return
	}
	SystemCronJob.Start()

	log.Info().Msg("Auto system policy discovery cron job started")
}

// StopSystemCronJob function
func StopSystemCronJob() {
	if SystemCronJob != nil {
		log.Info().Msg("Got a signal to terminate the auto system policy discovery")

		close(SystemStopChan)
		SystemWaitG.Wait()

		SystemCronJob.Stop() // Stop the scheduler (does not stop any jobs already running).

		SystemCronJob = nil
	}
}

// StartSystemWorker function
func StartSystemWorker() {
	if SystemWorkerStatus != STATUS_IDLE {
		log.Info().Msg("There is no idle system policy discovery worker")
		return
	}

	if cfg.GetCfgOperationMode() == OP_MODE_CRONJOB { // every time intervals
		StartSystemCronJob()
	} else { // one-time generation
		DiscoverSystemPolicyMain()
		log.Info().Msgf("Auto system policy discovery onetime job done")
	}
}

// StopSystemWorker function
func StopSystemWorker() {
	if cfg.GetCfgOperationMode() == OP_MODE_CRONJOB { // every time intervals
		StopSystemCronJob()
	} else {
		if SystemWorkerStatus != STATUS_RUNNING {
			log.Info().Msg("There is no running system policy discovery worker")
			return
		}
	}
}
