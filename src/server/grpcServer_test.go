package server

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetNewServer(t *testing.T) {
	assert.NotNil(t, AddServers(AddLicenseServer(StartGrpcServer())))
}
