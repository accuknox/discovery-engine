package core

import (
	"sync"

	"github.com/robfig/cron"
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

}

// ==================================== //
// == System Policy Discovery Worker == //
// ==================================== //

// StartSystemCronJob function
func StartSystemCronJob() {
	// init cron job
	SystemCronJob = cron.New()
	err := SystemCronJob.AddFunc(Cfg.CronJobTimeInterval, DiscoverSystemPolicyMain) // time interval
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

	if Cfg.OperationMode == OP_MODE_CRONJOB { // every time intervals
		StartSystemCronJob()
	} else { // one-time generation
		DiscoverSystemPolicyMain()
		log.Info().Msgf("Auto system policy discovery onetime job done")
	}
}

// StopSystemWorker function
func StopSystemWorker() {
	if Cfg.OperationMode == OP_MODE_CRONJOB { // every time intervals
		StopSystemCronJob()
	} else {
		if SystemWorkerStatus != STATUS_RUNNING {
			log.Info().Msg("There is no running system policy discovery worker")
			return
		}
	}
}
