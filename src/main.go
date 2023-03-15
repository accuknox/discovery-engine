package main

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/accuknox/auto-policy-discovery/src/config"
	libs "github.com/accuknox/auto-policy-discovery/src/libs"
	logger "github.com/accuknox/auto-policy-discovery/src/logging"
	grpcserver "github.com/accuknox/auto-policy-discovery/src/server"
	"github.com/accuknox/go-spiffe/v2/workloadapi"

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
	libs.CreateTablesIfNotExist(config.GetCfgDB())

	// 4. Seed random number generator
	rand.Seed(time.Now().UnixNano())
}

// ========== //
// == Main == //
// ========== //

func main() {
	// The context is used to inform the getSource, that it has 5 seconds to finish
	// the request it is currently handling
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	source, err := getSource(ctx)
	if err != nil {
		log.Fatal().Msgf("not able to get the Source: %s\n", err)
	}
	defer source.Close()
	// create server
	lis, err := net.Listen("tcp", ":"+grpcserver.PortNumber)
	if err != nil {
		log.Error().Msgf("gRPC server failed to listen: %v", err)
		os.Exit(1)
	}
	server := grpcserver.GetNewServer(source)

	// start autopolicy service
	log.Info().Msgf("gRPC server on %s port started", grpcserver.PortNumber)
	if err := server.Serve(lis); err != nil {
		log.Error().Msgf("Failed to serve: %v", err)
	}
}

func getSource(ctx context.Context) (*workloadapi.X509Source, error) {

	serviceAccountPath := viper.GetString("spire.serviceaccount-token-path")
	saToken, err := os.ReadFile(filepath.Clean(serviceAccountPath))
	if err != nil {
		return nil, fmt.Errorf("Failed to open serviceaccount token file: %v", err)
	}

	meta := map[string]string{
		"sa_token": string(saToken),
	}

	//Getting kubernetes service IP
	ip, err := net.LookupIP(viper.GetString("spire.basePath"))
	if err != nil {
		return nil, err
	}

	//making socketPath based on the IP and PORT
	socketPath := "tcp://" + ip[0].String() + ":" + viper.GetString("spire.basePort")
	log.Debug().Msgf("SocketPath: %v", socketPath)

	// Create a `workloadapi.X509Source`, it will connect to Workload API using provided socket path
	// If socket path is not defined using `workloadapi.SourceOption`, value from environment variable `SPIFFE_ENDPOINT_SOCKET` is used.
	source, err := workloadapi.NewX509Source(ctx, meta, workloadapi.WithClientOptions(workloadapi.WithAddr(socketPath)))
	if err != nil {
		return nil, fmt.Errorf("unable to create X509Source: %w", err)
	}
	log.Debug().Msg("Workload Attested Successfully")
	return source, nil
}
