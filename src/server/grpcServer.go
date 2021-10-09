package server

import (
	"context"
	"fmt"

	"github.com/rs/zerolog"

	analyzer "github.com/accuknox/knoxAutoPolicy/src/analyzer"
	cfg "github.com/accuknox/knoxAutoPolicy/src/config"
	core "github.com/accuknox/knoxAutoPolicy/src/config"
	"github.com/accuknox/knoxAutoPolicy/src/feedconsumer"
	logger "github.com/accuknox/knoxAutoPolicy/src/logging"
	networker "github.com/accuknox/knoxAutoPolicy/src/networkpolicy"
	sysworker "github.com/accuknox/knoxAutoPolicy/src/systempolicy"

	"github.com/accuknox/knoxAutoPolicy/src/libs"
	apb "github.com/accuknox/knoxAutoPolicy/src/protobuf/v1/analyzer"
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

// ==================== //
// == Worker Service == //
// ==================== //

type workerServer struct {
	wpb.WorkerServer
}

func (s *workerServer) Start(ctx context.Context, in *wpb.WorkerRequest) (*wpb.WorkerResponse, error) {
	log.Info().Msg("Start worker called")

	response := ""

	if in.GetReq() == "dbclear" {
		libs.ClearDBTables(core.CurrentCfg.ConfigDB)
		response += "Cleared DB ,"
	}

	if in.GetLogfile() != "" {
		core.SetLogFile(in.GetLogfile())
		response += "Log File Set ,"
	}

	if in.GetPolicytype() != "" {
		if in.GetPolicytype() == "network" {
			networker.StartNetworkWorker()
		} else if in.GetPolicytype() == "system" {
			sysworker.StartSystemWorker()
		}
		response += "Starting " + in.GetPolicytype() + " policy discovery"
	} else {
		response += "No policy type provided, choose 'network' or 'system' to start policy discovery"
	}

	return &wpb.WorkerResponse{Res: response}, nil
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

func (s *workerServer) Convert(ctx context.Context, in *wpb.WorkerRequest) (*wpb.WorkerResponse, error) {
	if in.GetPolicytype() == "network" {
		log.Info().Msg("Convert network poolicy called")
		networker.InitNetPolicyDiscoveryConfiguration()
		networker.WriteNetworkPoliciesToFile("", "", []types.Service{})
	} else if in.GetPolicytype() == "system" {
		log.Info().Msg("Convert system poolicy called")
		sysworker.InitSysPolicyDiscoveryConfiguration()
		sysworker.WriteSystemPoliciesToFile("")
	} else {
		log.Info().Msg("Convert policy called, but no policy type")
	}

	return &wpb.WorkerResponse{Res: "ok"}, nil
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

// ====================== //
// == Analyzer Service == //
// ====================== //

type analyzerServer struct {
	apb.AnalyzerServer
}

func (s *analyzerServer) GetNetworkPolicies(ctx context.Context, in *apb.NetworkLogs) (*apb.NetworkPolicies, error) {
	fmt.Printf("\n RPC ENTRY -- : %v\n", in.GetNwLog())
	pbNetworkPolicies := apb.NetworkPolicies{}
	pbNetworkPolicies.NwPolicies = analyzer.GetNetworkPolicies(in.GetNwLog())
	return &pbNetworkPolicies, nil
}

func (s *analyzerServer) GetSystemPolicies(ctx context.Context, in *apb.SystemLogs) (*apb.SystemPolicies, error) {
	fmt.Printf("\n RPC ENTRY -- : %v\n", in.GetSysLog())
	pbSystemPolicies := apb.SystemPolicies{}
	pbSystemPolicies.SysPolicies = analyzer.GetSystemPolicies(in.GetSysLog())
	return &pbSystemPolicies, nil
}

// ================= //
// == gRPC server == //
// ================= //

func GetNewServer() *grpc.Server {
	s := grpc.NewServer()
	grpc_health_v1.RegisterHealthServer(s, health.NewServer())

	reflection.Register(s)

	// create server instances
	workerServer := &workerServer{}
	consumerServer := &consumerServer{}
	analyzerServer := &analyzerServer{}

	// register gRPC servers
	wpb.RegisterWorkerServer(s, workerServer)
	fpb.RegisterConsumerServer(s, consumerServer)
	apb.RegisterAnalyzerServer(s, analyzerServer)

	if cfg.GetCurrentCfg().ConfigClusterMgmt.ClusterInfoFrom != "k8sclient" {
		// start consumer automatically
		feedconsumer.StartConsumer()
	}

	// start net worker automatically
	networker.StartNetworkWorker()

	// start sys worker automatically
	sysworker.StartSystemWorker()

	return s
}
