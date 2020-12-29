package main

import (
	"github.com/accuknox/knoxAutoPolicy/src/core"
	"github.com/accuknox/knoxAutoPolicy/src/libs"
)

func main() {
	operationMode := libs.GetEnv("OPERATION_MODE", "cronjob")
	if operationMode == "cronjob" { // timer
		core.StartCronJob()
	} else { // one-time generation
		core.StartToDiscoverNetworkPolicies()
	}
}
