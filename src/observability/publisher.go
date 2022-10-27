package observability

import (
	"github.com/accuknox/auto-policy-discovery/src/types"
)

func ProcessSystemSummary() {
	if len(PublisherMap) <= 0 {
		return
	}

	PublisherMutex.Lock()
	// publish summary map in GRPC
	for ss, sstc := range PublisherMap {
		var locSummary types.SystemSummary = ss

		// update count/time
		locSummary.Count = sstc.Count
		locSummary.UpdatedTime = sstc.UpdatedTime

		// publish data to feeder grpc
		SysSummary.Publish(&locSummary)

		// clear each published entry from data map
		delete(PublisherMap, ss)
	}
	PublisherMutex.Unlock()
}

func updatePublisherMap() {
	for ss, sstc := range SummarizerMap {
		PublisherMap[ss] = types.SysSummaryTimeCount{
			Count:       PublisherMap[ss].Count + sstc.Count,
			UpdatedTime: sstc.UpdatedTime,
		}
		delete(SummarizerMap, ss)
	}
}
