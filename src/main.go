package main

import (
	"flag"
	"net"
	"os"

	"github.com/accuknox/knoxAutoPolicy/src/core"
	"github.com/accuknox/knoxAutoPolicy/src/libs"
	logger "github.com/accuknox/knoxAutoPolicy/src/logging"
	gserver "github.com/accuknox/knoxAutoPolicy/src/server"

	"github.com/rs/zerolog"
	"github.com/spf13/viper"
)

var configFilePath *string

// setupLogger
func setupLogger() {
	logLevel := viper.GetString("logging.level")
	logger.SetLogLevel(logLevel)
}

// loadConfig - Load the config parameters
func loadConfig() {
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

	core.LoadDefaultConfig()
}

// setup db table
func setupDB() {
	libs.CreateTablesIfNotExist(core.Cfg.ConfigDB)
}

// ========== //
// == Main == //
// ========== //

func main() {
	// csetup onfiguration
	configFilePath = flag.String("config-path", "conf/", "conf/")
	flag.Parse()
	loadConfig()

	// setup logger
	setupLogger()
	var log *zerolog.Logger = logger.GetInstance()

	// db setup
	setupDB()

	// server listen
	lis, err := net.Listen("tcp", ":"+gserver.PortNumber)
	if err != nil {
		log.Error().Msgf("KnoxAutoPolicy gRPC server failed to listen: %v", err)
		os.Exit(1)
	}

	server := gserver.GetNewServer()

	// service start
	log.Info().Msgf("KnoxAutoPolicy gRPC server on %s port started", gserver.PortNumber)
	if err := server.Serve(lis); err != nil {
		log.Error().Msgf("failed to serve: %s", err)
	}
}
