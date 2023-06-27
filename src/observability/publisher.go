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

	var ProcessSystemSummaryWg sync.WaitGroup

	if cfg.GetCfgObservabilityWriteToDB() {
		ProcessSystemSummaryWg.Add(1)
		go UpsertSummaryCronJob(tempSummarizerMap, &ProcessSystemSummaryWg)
	}

	if cfg.GetCfgPublisherEnable() {
		PublisherMutex.Lock()
		timeVar := time.Now()
		tempSummarizerMap = getAggregatedSummaryMap(tempSummarizerMap)

		log.Info().Msgf("Events to publish after aggregation: [%v]", len(tempSummarizerMap))
		count := 0

		// publish summary map in GRPC
		for ss, sstc := range tempSummarizerMap {
			count++
			var locSummary types.SystemSummary = ss

			// update count/time
			locSummary.Count = sstc.Count
			locSummary.UpdatedTime = sstc.UpdatedTime

			// publish data to feeder grpc
			SysSummary.Publish(&locSummary)

			// clear each published entry from data map
			delete(tempSummarizerMap, ss)
		}
		log.Info().Msgf("Published %v events in %v", count, time.Since(timeVar))
		PublisherMutex.Unlock()
	}
	ProcessSystemSummaryWg.Wait()
}

func getAggregatedSummaryMap(tempSummarizerMap map[types.SystemSummary]types.SysSummaryTimeCount) map[types.SystemSummary]types.SysSummaryTimeCount {

	var fileArr []string
	log.Info().Msgf("Events before aggregation: [%v]", len(tempSummarizerMap))

	fileSumMap := make(map[types.SystemSummary]types.SysSummaryTimeCount)
	updatedSummarizerMap := make(map[types.SystemSummary]types.SysSummaryTimeCount)
	for tss, tsstc := range tempSummarizerMap {
		if tss.Operation == types.FileOperation {
			fileArr = append(fileArr, tss.Destination)
			fileSumMap[tss] = tsstc
		} else {
			updatedSummarizerMap[tss] = tsstc
		}
	}
	tempSummarizerMap = updatedSummarizerMap

	aggregatedFilePaths := common.AggregatePaths(fileArr)

	log.Info().Msgf("Aggregated file paths: [%v]", len(aggregatedFilePaths))
	for ss, sstc := range fileSumMap {
		for _, path := range aggregatedFilePaths {
			if strings.HasPrefix(ss.Destination, path.Path) && (len(ss.Destination) == len(path.Path) || ss.Destination[len(strings.TrimSuffix(path.Path, "/"))] == '/') {
				ss.Destination = path.Path
				break
			}
		}

		if existingSstc, ok := tempSummarizerMap[ss]; ok {
			existingSstc.Count += sstc.Count
			if sstc.UpdatedTime > existingSstc.UpdatedTime {
				existingSstc.UpdatedTime = sstc.UpdatedTime
			}
			tempSummarizerMap[ss] = existingSstc
		} else {
			tempSummarizerMap[ss] = sstc
		}

	}

	return tempSummarizerMap
}
