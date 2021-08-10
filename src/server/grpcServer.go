package server

import (
	"context"
	"encoding/json"

	"github.com/gogo/protobuf/jsonpb"
	"github.com/rs/zerolog"

	cfg "github.com/accuknox/knoxAutoPolicy/src/config"
	core "github.com/accuknox/knoxAutoPolicy/src/config"
	"github.com/accuknox/knoxAutoPolicy/src/feedconsumer"
	logger "github.com/accuknox/knoxAutoPolicy/src/logging"
	networker "github.com/accuknox/knoxAutoPolicy/src/networkpolicy"
	sysworker "github.com/accuknox/knoxAutoPolicy/src/systempolicy"

	"github.com/accuknox/knoxAutoPolicy/src/libs"
	cpb "github.com/accuknox/knoxAutoPolicy/src/protobuf/v1/config"
	fpb "github.com/accuknox/knoxAutoPolicy/src/protobuf/v1/consumer"
	wpb "github.com/accuknox/knoxAutoPolicy/src/protobuf/v1/worker"
	"github.com/accuknox/knoxAutoPolicy/src/types"

	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"
)

const PortNumber = "9089"

var log *zerolog.Logger

func init() {
	log = logger.GetInstance()
}

// =========================== //
// == Configuration Service == //
// ========================== //

type configServer struct {
	cpb.ConfigStoreServer
}

func (s *configServer) Add(ctx context.Context, in *cpb.ConfigRequest) (*cpb.ConfigResponse, error) {
	log.Info().Msg("Add config called")

	m := jsonpb.Marshaler{OrigName: true}
	str, err := m.MarshalToString(in.GetConfig())
	if err != nil {
		return &cpb.ConfigResponse{Msg: err.Error()}, err
	}

	var config types.Configuration
	if err := json.Unmarshal([]byte(str), &config); err != nil {
		return &cpb.ConfigResponse{Msg: err.Error()}, err
	}

	if err := core.AddConfiguration(config); err != nil {
		return &cpb.ConfigResponse{Msg: err.Error()}, err
	}

	return &cpb.ConfigResponse{Msg: "ok"}, nil
}

func (s *configServer) Get(ctx context.Context, in *cpb.ConfigRequest) (*cpb.ConfigResponse, error) {
	log.Info().Msg("Get config called")

	results, err := core.GetConfigurations(in.GetConfigName())
	if err != nil {
		return &cpb.ConfigResponse{Msg: err.Error()}, nil
	}

	configs := []*cpb.Config{}

	for i := range results {
		var config cpb.Config
		if b, err := json.Marshal(&results[i]); err != nil {
			log.Error().Msg(err.Error())
			continue
		} else {
			if err := json.Unmarshal(b, &config); err != nil {
				log.Error().Msg(err.Error())
				continue
			}
		}

		configs = append(configs, &config)
	}

	return &cpb.ConfigResponse{Msg: "ok", Config: configs}, nil
}

func (s *configServer) Update(ctx context.Context, in *cpb.ConfigRequest) (*cpb.ConfigResponse, error) {
	log.Info().Msg("Update config called")

	m := jsonpb.Marshaler{OrigName: true}
	str, _ := m.MarshalToString(in.GetConfig())

	var config types.Configuration
	if err := json.Unmarshal([]byte(str), &config); err != nil {
		return &cpb.ConfigResponse{Msg: err.Error()}, err
	}

	err := core.UpdateConfiguration(in.GetConfigName(), config)
	if err != nil {
		return &cpb.ConfigResponse{Msg: err.Error()}, err
	}

	return &cpb.ConfigResponse{Msg: "ok"}, err
}

func (s *configServer) Delete(ctx context.Context, in *cpb.ConfigRequest) (*cpb.ConfigResponse, error) {
	log.Info().Msg("Delete config called")

	err := core.DeleteConfiguration(in.GetConfigName())
	if err != nil {
		return &cpb.ConfigResponse{Msg: err.Error()}, nil
	}

	return &cpb.ConfigResponse{Msg: "ok"}, nil
}

func (s *configServer) Apply(ctx context.Context, in *cpb.ConfigRequest) (*cpb.ConfigResponse, error) {
	log.Info().Msg("Apply config called")

	err := core.ApplyConfiguration(in.GetConfigName())
	if err != nil {
		return &cpb.ConfigResponse{Msg: err.Error()}, nil
	}

	return &cpb.ConfigResponse{Msg: "ok"}, nil
}

// ==================== //
// == Worker Service == //
// ==================== //

type workerServer struct {
	wpb.WorkerServer
}

func (s *workerServer) Start(ctx context.Context, in *wpb.WorkerRequest) (*wpb.WorkerResponse, error) {
	log.Info().Msg("Start worker called")

	if in.GetReq() == "dbclear" {
		libs.ClearDBTables(core.CurrentCfg.ConfigDB)
	}

	if in.GetLogfile() != "" {
		core.SetLogFile(in.GetLogfile())
	}

	if in.GetPolicytype() == "network" {
		networker.StartNetworkWorker()
	} else if in.GetPolicytype() == "system" {
		sysworker.StartSystemWorker()
	} else {
		return &wpb.WorkerResponse{Res: "No policy type, choose 'network' or 'system', not [" + in.GetPolicytype() + "]"}, nil
	}

	return &wpb.WorkerResponse{Res: "ok starting " + in.GetPolicytype() + " policy discovery"}, nil
}

func (s *workerServer) Stop(ctx context.Context, in *wpb.WorkerRequest) (*wpb.WorkerResponse, error) {
	log.Info().Msg("Stop worker called")

	if in.GetPolicytype() == "network" {
		networker.StopNetworkWorker()
	} else if in.GetPolicytype() == "system" {
		sysworker.StopSystemWorker()
	} else {
		return &wpb.WorkerResponse{Res: "No policy type, choose 'network' or 'system', not [" + in.GetPolicytype() + "]"}, nil
	}

	return &wpb.WorkerResponse{Res: "ok stopping " + in.GetPolicytype() + " policy discovery"}, nil
}

func (s *workerServer) GetWorkerStatus(ctx context.Context, in *wpb.WorkerRequest) (*wpb.WorkerResponse, error) {
	log.Info().Msg("Get worker status called")

	status := ""

	if in.GetPolicytype() == "network" {
		status = networker.NetworkWorkerStatus
	} else if in.GetPolicytype() == "system" {
		status = sysworker.SystemWorkerStatus
	} else {
		return &wpb.WorkerResponse{Res: "No policy type, choose 'network' or 'system', not [" + in.GetPolicytype() + "]"}, nil
	}

	return &wpb.WorkerResponse{Res: status}, nil
}

// ====================== //
// == Consumer Service == //
// ====================== //

type consumerServer struct {
	fpb.ConsumerServer
}

func (s *consumerServer) Start(ctx context.Context, in *fpb.ConsumerRequest) (*fpb.ConsumerResponse, error) {
	log.Info().Msg("Start consumer called")
	feedconsumer.StartConsumer()
	return &fpb.ConsumerResponse{Res: "ok"}, nil
}

func (s *consumerServer) Stop(ctx context.Context, in *fpb.ConsumerRequest) (*fpb.ConsumerResponse, error) {
	log.Info().Msg("Stop consumer called")
	feedconsumer.StopConsumer()
	return &fpb.ConsumerResponse{Res: "ok"}, nil
}

func (s *consumerServer) GetWorkerStatus(ctx context.Context, in *fpb.ConsumerRequest) (*fpb.ConsumerResponse, error) {
	log.Info().Msg("Get consumer status called")
	return &fpb.ConsumerResponse{Res: feedconsumer.Status}, nil
}

// ================= //
// == gRPC server == //
// ================= //

func GetNewServer() *grpc.Server {
	s := grpc.NewServer()
	grpc_health_v1.RegisterHealthServer(s, health.NewServer())

	reflection.Register(s)

	// create server instances
	configServer := &configServer{}
	workerServer := &workerServer{}
	consumerServer := &consumerServer{}

	// register gRPC servers
	cpb.RegisterConfigStoreServer(s, configServer)
	wpb.RegisterWorkerServer(s, workerServer)
	fpb.RegisterConsumerServer(s, consumerServer)

	if cfg.GetCurrentCfg().ConfigClusterMgmt.ClusterInfoFrom != "k8sclient" {
		// start consumer automatically
		feedconsumer.StartConsumer()

		// start net worker automatically
		networker.StartNetworkWorker()

		// start sys worker automatically
		sysworker.StartSystemWorker()
	}

	return s
}
