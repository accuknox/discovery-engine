package server

import (
	"testing"

	"github.com/accuknox/go-spiffe/v2/workloadapi"
	"github.com/stretchr/testify/assert"
)

func TestGetNewServer(t *testing.T) {
	server := GetNewServer(&workloadapi.X509Source{})
	assert.NotNil(t, server)
}
