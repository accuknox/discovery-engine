package observability

import (
	"strings"
	"sync"
	"time"

	"github.com/accuknox/auto-policy-discovery/src/common"
	cfg "github.com/accuknox/auto-policy-discovery/src/config"
	"github.com/accuknox/auto-policy-discovery/src/types"
)

func ProcessSystemSummary() {

	if len(SummarizerMap) == 0 {
		return
	}

	SummarizerMapMutex.Lock()
	tempSummarizerMap := common.MoveMap(SummarizerMap)
	SummarizerMapMutex.Unlock()

	aggregateSummaryMap(tempSummarizerMap)

	if cfg.GetCfgObservabilityWriteToDB() {
		var ProcessSystemSummaryWg sync.WaitGroup
		ProcessSystemSummaryWg.Add(1)
		go UpsertSummaryCronJob(tempSummarizerMap, &ProcessSystemSummaryWg)
		ProcessSystemSummaryWg.Wait()
	}

	if cfg.GetCfgPublisherEnable() {
		PublisherMutex.Lock()
		initTime := time.Now()

		//aggregateSummaryMap(tempSummarizerMap)

		log.Info().Msgf("Events to publish after aggregation: [%v]", len(tempSummarizerMap))
		count := 0

		// publish summary map in GRPC
		for sysSummary, summaryTimeCount := range tempSummarizerMap {
			count++
			var locSummary types.SystemSummary = sysSummary

			// update count/time
			locSummary.Count = summaryTimeCount.Count
			locSummary.UpdatedTime = summaryTimeCount.UpdatedTime

			// publish data to feeder grpc
			SysSummary.Publish(&locSummary)

			// clear each published entry from data map
			delete(tempSummarizerMap, sysSummary)
		}
		log.Info().Msgf("Published %v events in %v", count, time.Since(initTime))
		PublisherMutex.Unlock()
	}

}

func aggregateSummaryMap(summaryMap map[types.SystemSummary]types.SysSummaryTimeCount) {

	podFilePaths := make(map[string][]string)
	aggPodFilePaths := make(map[string][]common.SysPath)
	fileSummarizerMap := make(map[types.SystemSummary]types.SysSummaryTimeCount)

	log.Info().Msgf("Events before aggregation: [%v]", len(summaryMap))
	for sysSummary, summaryTimeCount := range summaryMap {
		if sysSummary.Operation == types.FileOperation {
			key := sysSummary.PodName + "_" + sysSummary.Source
			podFilePaths[key] = append(podFilePaths[key], sysSummary.Destination)
			fileSummarizerMap[sysSummary] = summaryTimeCount
			delete(summaryMap, sysSummary)
		}
	}

	for key, files := range podFilePaths {
		aggPodFilePaths[key] = common.AggregatePaths(files)
		log.Info().Msgf("Got %v aggregated file paths for key [%v]", len(aggPodFilePaths[key]), key)
	}

	for sysSummary, summaryTimeCount := range fileSummarizerMap {
		key := sysSummary.PodName + "_" + sysSummary.Source
		files := aggPodFilePaths[key]
		for _, path := range files {
			if strings.HasPrefix(sysSummary.Destination, path.Path) && (len(sysSummary.Destination) == len(path.Path) || sysSummary.Destination[len(strings.TrimSuffix(path.Path, "/"))] == '/') {
				sysSummary.Destination = path.Path
				break
			}
		}
		if timeCount, ok := summaryMap[sysSummary]; ok {
			timeCount.Count += summaryTimeCount.Count
			if summaryTimeCount.UpdatedTime > timeCount.UpdatedTime {
				timeCount.UpdatedTime = summaryTimeCount.UpdatedTime
			}
			summaryMap[sysSummary] = timeCount
		} else {
			summaryMap[sysSummary] = summaryTimeCount
		}

	}
}
