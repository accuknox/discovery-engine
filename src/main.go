package main

import (
	"net"

	gs "github.com/accuknox/knoxAutoPolicy/src/server"
	"github.com/rs/zerolog/log"
)

func main() {
	lis, err := net.Listen("tcp", ":"+gs.PortNumber)
	if err != nil {
		log.Info().Msgf("KnoxAutoPolicy failed to listen: %v", err)
		return
	}

	server := gs.GetNewServer()

	log.Info().Msgf("KnoxAutoPolicy gRPC server on %s port started", gs.PortNumber)
	if err := server.Serve(lis); err != nil {
		log.Error().Msgf("failed to serve: %s", err)
	}
}
