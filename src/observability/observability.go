package observability

import (
	"sync"

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
}

func SystemLogCronJob() {
	ProcessSystemLogs()
}

func NetworkLogCronJob() {
	ProcessNetworkLogs()
}
