package main

import (
	"github.com/accuknox/auto-policy-discovery/src/report"
	"math/rand"
	"net"
	"net/http"
	"net/http/pprof"
	"os"
	"time"

	"github.com/accuknox/auto-policy-discovery/src/cluster"
	"github.com/accuknox/auto-policy-discovery/src/config"
	"github.com/accuknox/auto-policy-discovery/src/libs"
	"github.com/accuknox/auto-policy-discovery/src/license"
	logger "github.com/accuknox/auto-policy-discovery/src/logging"
	grpcserver "github.com/accuknox/auto-policy-discovery/src/server"
	"github.com/rs/zerolog"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
)

var cfg cluster.Config

var log *zerolog.Logger

// ==================== //
// == Initialization == //
// ==================== //

func init() {
	// 1. load configurations
	libs.LoadConfigurationFile()
	config.LoadConfigFromFile()

	// 2. setup logger
	logger.SetLogLevel(viper.GetString("logging.level"))
	log = logger.GetInstance()

	//Get pprof flag
	if viper.GetBool("pprof") {
		// Server for pprof
		go func() {
			log.Info().Msgf("pprof enabled on :6060\n")
			http.Handle("/debug/pprof/", http.HandlerFunc(pprof.Index))
			http.Handle("/debug/pprof/cmdline", http.HandlerFunc(pprof.Cmdline))
			http.Handle("/debug/pprof/profile", http.HandlerFunc(pprof.Profile))
			http.Handle("/debug/pprof/symbol", http.HandlerFunc(pprof.Symbol))
			http.Handle("/debug/pprof/trace", http.HandlerFunc(pprof.Trace))

			server := &http.Server{
				Addr:              ":6060",
				ReadHeaderTimeout: 5 * time.Second,
			}

			if err := server.ListenAndServe(); err != nil {
				log.Error().Msgf("failed to serve : %+v", err.Error())
			}
		}()
	}

	log.Info().Msgf("NETWORK-POLICY: %+v", config.GetCfgNet())
	log.Info().Msgf("CILIUM: %+v", config.GetCfgCiliumHubble())
	log.Info().Msgf("SYSTEM-POLICY: %+v", config.GetCfgSys())
	log.Info().Msgf("KUBEARMOR: %+v", config.GetCfgKubeArmor())

	// 3. setup the tables in db
	libs.CreateTablesIfNotExist(config.GetCfgDB())

	// 4. Seed random number generator
	rand.Seed(time.Now().UnixNano())

	cfg.K8sClient = cluster.ConnectK8sClient()
	license.InitializeConfig(cfg.K8sClient)
	report.InitializeConfig()
}

// ========== //
// == Main == //
// ========== //

func main() {

	lis, server := CreateListenerAndGrpcServer()

	if license.LCfg.Enabled {
		// add license server
		server = grpcserver.AddLicenseServer(server)

		// check for license secret, if exist then validate
		err := license.CheckLicenseSecret()

		if err != nil {
			log.Error().Msgf("error while validating license secrets for discovery engine, error: %s", err.Error())
			go serve(lis, server)
			_ = license.LCfg.WatchFeatures()
			os.Exit(1)
		}

		go license.LCfg.WatchLicenseValidity()
	}

	server = grpcserver.AddServers(server)
	serve(lis, server)

}

// CreateListenerAndGrpcServer - Creates a new connection and listens on a given port
func CreateListenerAndGrpcServer() (net.Listener, *grpc.Server) {
	// create server
	lis, err := net.Listen("tcp", ":"+grpcserver.PortNumber)
	if err != nil {
		log.Error().Msgf("gRPC server failed to listen: %v", err)
		os.Exit(1)
	}

	// starts grpc server
	server := grpcserver.StartGrpcServer()

	return lis, server
}

func serve(lis net.Listener, server *grpc.Server) {
	if err := server.Serve(lis); err != nil {
		log.Error().Msgf("Failed to serve: %v", err)
	}
}
