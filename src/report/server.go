package report

import (
	"context"
	"errors"
	rpb "github.com/accuknox/auto-policy-discovery/src/protobuf/v1/report"
	"github.com/accuknox/auto-policy-discovery/src/types"
	"github.com/rs/zerolog/log"
)

type Server struct {
	rpb.UnimplementedReportServer
}

// GetReport generate report and return it
func (s *Server) GetReport(ctx context.Context, req *rpb.ReportRequest) (*rpb.ReportResponse, error) {
	log.Info().Msgf("request received to generate report")
	if req == nil {
		log.Error().Msgf("error while processing request for report grpc,error: invalid request")
		return nil, errors.New("invalid request")
	}
	log.Info().Msgf("request: %s", req)
	o := getOptions(req)
	if req.MetaData != nil {
		o.options.MetaData = &types.MetaData{
			Label:         req.MetaData.Label,
			ContainerName: req.MetaData.ContainerName,
		}
	}
	report, err := o.GetReport()
	if err != nil {
		log.Error().Msgf("error while getting report for grpc request,error: %s", err.Error())
		return nil, err
	}
	log.Info().Msgf("grpc report request processed successfully")
	return report, nil
}

func getOptions(req *rpb.ReportRequest) *Options {
	return &Options{options: &types.ReportOptions{
		Clusters:     req.Clusters,
		Namespaces:   req.Namespaces,
		ResourceType: req.ResourceType,
		ResourceName: req.ResourceName,
		Operation:    req.Operation,
		PodName:      req.PodName,
		Source:       req.Source,
		Destination:  req.Destination,
	},
	}
}
