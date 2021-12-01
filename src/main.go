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
	config.LoadDefaultConfig()

	// 2. setup logger
	logLevel := viper.GetString("logging.level")
	logger.SetLogLevel(logLevel)
	log = logger.GetInstance()

	// 3. setup the tables in db
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
