package license

import (
	"context"
	"errors"
	"fmt"
	ipb "github.com/accuknox/auto-policy-discovery/src/protobuf/v1/license"
	"github.com/rs/zerolog/log"
	"time"
)

type Server struct {
	ipb.UnimplementedLicenseServer
}

// InstallLicense Implementation of grpc server code. Function to install license when grpc request is made
func (ls *Server) InstallLicense(ctx context.Context, lr *ipb.LicenseInstallRequest) (*ipb.LicenseInstallResponse, error) {
	log.Info().Msgf("request received to install license for user-id: %s", lr.UserId)
	if lr.UserId == "" || lr.Key == "" {
		return &ipb.LicenseInstallResponse{
			Res:     -1,
			Message: "error while validating license",
		}, fmt.Errorf("invalid request body")
	}
	l := &License{
		UserId: lr.UserId,
		Key:    lr.Key,
	}
	err := l.ValidateLicense()
	if err != nil {
		return &ipb.LicenseInstallResponse{
			Res:     -1,
			Message: "error while validating license",
		}, err
	}
	return &ipb.LicenseInstallResponse{
		Res:     0,
		Message: "license installed successfully",
	}, nil
}

// GetLicenseStatus Implementation of grpc server code. Function to get status of license
func (ls *Server) GetLicenseStatus(ctx context.Context, lr *ipb.LicenseStatusRequest) (*ipb.LicenseStatusResponse, error) {
	log.Info().Msgf("request received to fetch the status of license")
	if LCfg.Lcs == nil || LCfg.Tkn == nil {
		return nil, errors.New("error while fetching status, no license secrets exists")
	}

	iAt, err := LCfg.Tkn.claims.RegisteredClaims.GetIssuedAt()
	if err != nil {
		log.Error().Msgf("error while getting issued time for license, error: %s", err.Error())
		return nil, err
	}

	exp, err := LCfg.Tkn.claims.RegisteredClaims.GetExpirationTime()
	if err != nil {
		log.Error().Msgf("error while getting expiration time for license, error: %s", err.Error())
		return nil, err
	}

	features, err := LCfg.Tkn.getFeatures()
	if err != nil || features == nil {
		log.Error().Msgf("error while getting features that are supported in license, error: %s", err.Error())
		return nil, err

	}

	var status string
	if exp.After(time.Now()) {
		status = "Active"
	} else {
		status = "Expired"
	}

	return &ipb.LicenseStatusResponse{
		Key:          LCfg.Lcs.Key,
		UserId:       LCfg.Lcs.UserId,
		PlatformUUID: LCfg.Lcs.PlatformUUID,
		IssuedAt:     iAt.String(),
		Expiration:   exp.String(),
		Features:     features,
		Status:       status,
	}, nil
}
