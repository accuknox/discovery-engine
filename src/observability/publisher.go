package observability

import (
	"github.com/accuknox/auto-policy-discovery/src/types"
)

func ProcessSystemSummary() {
	if len(PublisherMap) <= 0 {
		return
	}

	var locmap map[types.SystemSummary]types.SysSummaryTimeCount

	PublisherMutex.Lock()
	locmap = PublisherMap
	for ss := range PublisherMap {
		delete(PublisherMap, ss)
	}

	// publish summary map in GRPC
	for ss, sstc := range locmap {
		var locSummary types.SystemSummary = ss

		// update count/time
		locSummary.Count = sstc.Count
		locSummary.UpdatedTime = sstc.UpdatedTime

		// publish data to feeder grpc
		SysSummaryStore.Publish(&locSummary)

		// clear each published entry from data map
		delete(locmap, ss)
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
