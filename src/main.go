package main

import (
	"fmt"
	"net"
	"os"

	"github.com/accuknox/knoxAutoPolicy/src/config"
	libs "github.com/accuknox/knoxAutoPolicy/src/libs"
	logger "github.com/accuknox/knoxAutoPolicy/src/logging"
	grpcserver "github.com/accuknox/knoxAutoPolicy/src/server"

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

	// 4. add default config
	if err := libs.AddConfiguration(config.GetCfgDB(), config.GetCurrentCfg()); err != nil {
		log.Error().Msg(err.Error())
	}
}

// ========== //
// == Main == //
// ========== //

func main() {
	cnp := make(chan func(), 50)
	cnp <- func() {
		fmt.Println("HERE")
	}

	for i := 0; i < 4; i++ {
		go func() {
			for f := range cnp {
				f()
			}
		}()
	}

	fmt.Println("vim-go")

	latestPolicies := libs.GetSystemPolicies(config.GetCfgDB(), "multiubuntu", "latest")

	libs.WriteKubeArmorPolicyToYamlFile("", latestPolicies)

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
		log.Error().Msgf("Failed to serve: %v", err)
	}
}
