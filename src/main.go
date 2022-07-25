package main

import (
	"net"
	"os"

	"github.com/accuknox/auto-policy-discovery/src/config"
	libs "github.com/accuknox/auto-policy-discovery/src/libs"
	logger "github.com/accuknox/auto-policy-discovery/src/logging"
	grpcserver "github.com/accuknox/auto-policy-discovery/src/server"

	"github.com/rs/zerolog"
	"github.com/spf13/viper"
)

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

	log.Info().Msgf("NETWORK-POLICY: %+v", config.GetCfgNet())
	log.Info().Msgf("CILIUM: %+v", config.GetCfgCiliumHubble())
	log.Info().Msgf("SYSTEM-POLICY: %+v", config.GetCfgSys())
	log.Info().Msgf("KUBEARMOR: %+v", config.GetCfgKubeArmor())

	// 3. setup the tables in db
	libs.InitDB(config.GetCfgDB())
	libs.CreateTablesIfNotExist(config.GetCfgDB())
}

// ========== //
// == Main == //
// ========== //

func main() {
	// create server
	lis, err := net.Listen("tcp", ":"+grpcserver.PortNumber)
	if err != nil {
		log.Error().Msgf("gRPC server failed to listen: %v", err)
		os.Exit(1)
	}
	server := grpcserver.GetNewServer()

	// start autopolicy service
	log.Info().Msgf("gRPC server on %s port started", grpcserver.PortNumber)
	if err := server.Serve(lis); err != nil {
		log.Error().Msgf("Failed to serve: %v", err)
	}
}
