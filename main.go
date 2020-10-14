package main

import (
	"github.com/seungsoo-lee/knoxAutoPolicy/libs"
	"github.com/seungsoo-lee/knoxAutoPolicy/test"
	"github.com/seungsoo-lee/knoxAutoPolicy/types"
)

func main() {
	// for test usage
	trafficList, _ := test.Qurey()

	networkLogs := []types.NetworkLog{}
	for _, traffic := range trafficList {
		if traffic.TraceObservationPoint == 4 {
			continue
		}

		networkLogs = append(networkLogs, libs.TrafficToLog(traffic))
	}

	// services := test.GetK8sServicesDummy()

}
