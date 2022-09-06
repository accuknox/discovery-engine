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
	SystemLogs []*pb.Log
	// Hubble relay logs
	NetworkLogs []*flow.Flow
	// Mutex
	SystemLogsMutex, NetworkLogsMutex, ObsMutex *sync.Mutex
	// Observability Cronjob
	ObsCronJob *cron.Cron
	//Kubearmor log map
	KubeArmorLogMap map[types.KubeArmorLog]int
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
