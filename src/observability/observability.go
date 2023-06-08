package observability

import (
	"errors"
	"sync"

	"github.com/accuknox/auto-policy-discovery/src/common"
	cfg "github.com/accuknox/auto-policy-discovery/src/config"
	"github.com/accuknox/auto-policy-discovery/src/libs"
	logger "github.com/accuknox/auto-policy-discovery/src/logging"
	opb "github.com/accuknox/auto-policy-discovery/src/protobuf/v1/observability"
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
	SystemLogs []*pb.Alert
	// Hubble relay logs
	NetworkLogs []*flow.Flow
	// Mutex
	SystemLogsMutex, NetworkLogsMutex, ObsMutex, PublisherMutex *sync.Mutex
	// Cronjobs
	ObsCronJob, PublisherCronJob *cron.Cron
	//Kubearmor log map
	KubeArmorLogMap map[types.KubeArmorLog]int
	ProcFileMap     map[types.SysObsProcFileMapKey]types.SysObsProcFileMapValue
	// Memory maps for summary
	PublisherMap, SummarizerMap map[types.SystemSummary]types.SysSummaryTimeCount
)

// =================== //
// == Obs Functions == //
// =================== //

func initMutex() {
	ObsMutex = &sync.Mutex{}
	if cfg.GetCfgObservabilitySysObsStatus() {
		SystemLogsMutex = &sync.Mutex{}
	}
	if cfg.GetCfgObservabilitySysObsStatus() {
		NetworkLogsMutex = &sync.Mutex{}
	}
}

func initMap() {
	KubeArmorLogMap = make(map[types.KubeArmorLog]int)
	ProcFileMap = make(map[types.SysObsProcFileMapKey]types.SysObsProcFileMapValue)
	SummarizerMap = make(map[types.SystemSummary]types.SysSummaryTimeCount)
}

func InitObservability() {
	log = logger.GetInstance()
	CfgDB = cfg.GetCfgDB()

	if cfg.GetCfgObservabilityEnable() {
		// Init mutex
		initMutex()

		// Init Variables
		initMap()

		ObsCronJob = cron.New()
		err := ObsCronJob.AddFunc(cfg.GetCfgObservabilityCronJobTime(), ObservabilityCronJob) // time interval
		if err != nil {
			log.Error().Msg(err.Error())
			return
		}
		ObsCronJob.Start()
		log.Info().Msg("Observability cron job started")
	}

	if cfg.GetCfgPublisherEnable() {
		// Init mutex
		PublisherMutex = &sync.Mutex{}

		// Define memory map
		PublisherMap = make(map[types.SystemSummary]types.SysSummaryTimeCount)

		// Define cron job
		PublisherCronJob = cron.New()
		err := PublisherCronJob.AddFunc(cfg.GetCfgPublisherCronJobTime(), ProcessSystemSummary) // time interval
		if err != nil {
			log.Error().Msg(err.Error())
			return
		}
		PublisherCronJob.Start()
		log.Info().Msg("Publisher cron job started")
	}
}

func ObservabilityCronJob() {
	if cfg.GetCfgObservabilitySysObsStatus() {
		ProcessSystemLogs()
	}
	if cfg.GetCfgObservabilityNetObsStatus() {
		ProcessNetworkLogs()
	}
}

func GetPodNames(request *opb.Request) (opb.PodNameResponse, error) {

	result, err := libs.GetPodNames(CfgDB, types.ObsPodDetail{
		PodName:       request.PodName,
		Namespace:     request.NameSpace,
		ClusterName:   request.ClusterName,
		ContainerName: request.ContainerName,
		Labels:        request.Label,
		DeployName:    request.DeployName,
	})
	if err != nil {
		return opb.PodNameResponse{}, err
	}

	result = common.StringDeDuplication(result)

	if len(result) <= 0 {
		return opb.PodNameResponse{}, errors.New("no pods matching the input request")
	}

	return opb.PodNameResponse{PodName: result}, nil
}

func GetDeployNames(request *opb.Request) (opb.DeployNameResponse, error) {

	result, err := libs.GetDeployNames(CfgDB, types.ObsPodDetail{
		PodName:       request.PodName,
		Namespace:     request.NameSpace,
		ClusterName:   request.ClusterName,
		ContainerName: request.ContainerName,
		Labels:        request.Label,
		DeployName:    request.DeployName,
	})
	if err != nil {
		return opb.DeployNameResponse{}, err
	}

	result = common.StringDeDuplication(result)

	if len(result) <= 0 {
		return opb.DeployNameResponse{}, errors.New("no pods matching the input request")
	}

	return opb.DeployNameResponse{DeployName: result}, nil
}
