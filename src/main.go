package main

import (
	"net"
	"os"

	gserver "github.com/accuknox/knoxAutoPolicy/src/server"
	"github.com/rs/zerolog/log"
)

func main() {
	lis, err := net.Listen("tcp", ":"+gserver.PortNumber)
	if err != nil {
		log.Error().Msgf("KnoxAutoPolicy failed to listen: %v", err)
		os.Exit(1)
	}

	server := gserver.GetNewServer()

	log.Info().Msgf("KnoxAutoPolicy gRPC server on %s port started", gserver.PortNumber)
	if err := server.Serve(lis); err != nil {
		log.Error().Msgf("failed to serve: %s", err)
	}
}
