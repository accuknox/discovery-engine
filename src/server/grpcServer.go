package server

import (
	"context"
	"encoding/json"

	"github.com/gogo/protobuf/jsonpb"
	"github.com/rs/zerolog"

	core "github.com/accuknox/knoxAutoPolicy/src/core"
	"github.com/accuknox/knoxAutoPolicy/src/feedconsumer"
	logger "github.com/accuknox/knoxAutoPolicy/src/logging"

	"github.com/accuknox/knoxAutoPolicy/src/libs"
	cpb "github.com/accuknox/knoxAutoPolicy/src/protobuf/v1/config"
	fpb "github.com/accuknox/knoxAutoPolicy/src/protobuf/v1/consumer"
	wpb "github.com/accuknox/knoxAutoPolicy/src/protobuf/v1/worker"
	"github.com/accuknox/knoxAutoPolicy/src/types"

	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

var log *zerolog.Logger

func init() {
	log = logger.GetInstance()
}

// PortNumber ...
const PortNumber = "9089"

// =========================== //
// == Configuration Service == //
// ========================== //

type configServer struct {
	cpb.ConfigStoreServer
}

func (s *configServer) Add(ctx context.Context, in *cpb.ConfigRequest) (*cpb.ConfigResponse, error) {
	log.Info().Msg("Add config called")

	m := jsonpb.Marshaler{OrigName: true}
	str, _ := m.MarshalToString(in.GetConfig())

	var config types.Configuration
	json.Unmarshal([]byte(str), &config)

	err := core.AddConfiguration(config)
	if err != nil {
		return &cpb.ConfigResponse{Msg: err.Error()}, nil
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

	for _, result := range results {
		var config cpb.Config
		if b, err := json.Marshal(&result); err != nil {
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
	json.Unmarshal([]byte(str), &config)

	err := core.UpdateConfiguration(in.GetConfigName(), config)
	if err != nil {
		return &cpb.ConfigResponse{Msg: err.Error()}, nil
	}

	return &cpb.ConfigResponse{Msg: "ok"}, nil
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
		libs.ClearDBTables(core.Cfg.ConfigDB)
	}

	if in.GetLogfile() != "" {
		core.SetLogFile(in.GetLogfile())
	}

	core.StartWorker()
	return &wpb.WorkerResponse{Res: "ok"}, nil
}

func (s *workerServer) Stop(ctx context.Context, in *wpb.WorkerRequest) (*wpb.WorkerResponse, error) {
	log.Info().Msg("Stop worker called")
	core.StopWorker()
	return &wpb.WorkerResponse{Res: "ok"}, nil
}

func (s *workerServer) GetWorkerStatus(ctx context.Context, in *wpb.WorkerRequest) (*wpb.WorkerResponse, error) {
	log.Info().Msg("Get worker status called")
	return &wpb.WorkerResponse{Res: core.WorkerStatus}, nil
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

// GetNewServer ...
func GetNewServer() *grpc.Server {
	s := grpc.NewServer()

	reflection.Register(s)

	cpb.RegisterConfigStoreServer(s, &configServer{})
	wpb.RegisterWorkerServer(s, &workerServer{})
	fpb.RegisterConsumerServer(s, &consumerServer{})

	return s
}
