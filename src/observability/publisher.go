package observability

import (
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

	//var ProcessSystemSummaryWg sync.WaitGroup

	if cfg.GetCfgObservabilityWriteToDB() {
		//ProcessSystemSummaryWg.Add(1)
		UpsertSummaryCronJob(tempSummarizerMap)
	}

	if cfg.GetCfgPublisherEnable() {
		PublisherMutex.Lock()
		// publish summary map in GRPC
		for ss, sstc := range tempSummarizerMap {
			var locSummary types.SystemSummary = ss

			// update count/time
			locSummary.Count = sstc.Count
			locSummary.UpdatedTime = sstc.UpdatedTime

			// publish data to feeder grpc
			SysSummary.Publish(&locSummary)

			// clear each published entry from data map
			delete(tempSummarizerMap, ss)
		}
		PublisherMutex.Unlock()
	}
	//ProcessSystemSummaryWg.Wait()
}
