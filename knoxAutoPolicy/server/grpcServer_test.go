package server

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetNewServer(t *testing.T) {
	server := GetNewServer()
	assert.NotNil(t, server)
}
