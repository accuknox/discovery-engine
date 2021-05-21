package main

import (
	"flag"
	"net"
	"os"

	"github.com/accuknox/knoxAutoPolicy/src/config"
	libs "github.com/accuknox/knoxAutoPolicy/src/libs"
	logger "github.com/accuknox/knoxAutoPolicy/src/logging"
	grpcserver "github.com/accuknox/knoxAutoPolicy/src/server"

	"github.com/rs/zerolog"
	"github.com/spf13/viper"
)

var configFilePath *string

var log *zerolog.Logger

// ==================== //
// == Initialization == //
// ==================== //

func init() {
	// 1. load configurations
	configFilePath = flag.String("config-path", "conf/", "conf/")
	flag.Parse()

	viper.SetConfigName(libs.GetEnv("CONF_FILE_NAME", "conf"))
	viper.SetConfigType("yaml")
	viper.AddConfigPath(*configFilePath)
	if err := viper.ReadInConfig(); err != nil {
		if readErr, ok := err.(viper.ConfigFileNotFoundError); ok {
			var log *zerolog.Logger = logger.GetInstance()
			log.Panic().Msgf("No config file found at %s\n", *configFilePath)
		} else {
			var log *zerolog.Logger = logger.GetInstance()
			log.Panic().Msgf("Error reading config file: %s\n", readErr)
		}
	}
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
		log.Error().Msgf("KnoxAutoPolicy gRPC server failed to listen: %v", err)
		os.Exit(1)
	}
	server := grpcserver.GetNewServer()

	// start autopolicy service
	log.Info().Msgf("KnoxAutoPolicy gRPC server on %s port started", grpcserver.PortNumber)
	if err := server.Serve(lis); err != nil {
		log.Error().Msgf("failed to serve: %s", err)
	}
}
