package observability

import (
	"sync"

	"github.com/accuknox/auto-policy-discovery/src/cluster"
	cfg "github.com/accuknox/auto-policy-discovery/src/config"
	logger "github.com/accuknox/auto-policy-discovery/src/logging"
	"github.com/accuknox/auto-policy-discovery/src/types"
	"github.com/cilium/cilium/api/v1/flow"
	pb "github.com/kubearmor/KubeArmor/protobuf"
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
	// Pods
	Pods []types.Pod
)

// =================== //
// == Obs Functions == //
// =================== //

func InitObservability() {
	log = logger.GetInstance()
	CfgDB = cfg.GetCfgDB()

	// Init Mutex
	SystemLogsMutex = &sync.Mutex{}
	NetworkLogsMutex = &sync.Mutex{}

	// update pod list from existing pods
	pods := cluster.GetPodsFromK8sClient()
	for _, pod := range pods {
		if pod.IP != "" && pod.PodName != "" {
			addPodToList(pod)
		}
	}

	go WatchK8sPods()
}

func SystemLogCronJob() {
	ProcessSystemLogs()
}

func NetworkLogCronJob() {
	ProcessNetworkLogs()
}
