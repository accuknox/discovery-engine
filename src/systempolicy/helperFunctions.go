package systempolicy

import (
	"strings"

	"github.com/accuknox/auto-policy-discovery/src/libs"
	types "github.com/accuknox/auto-policy-discovery/src/types"
)

// ========================== //
// == System Policy Filter == //
// ========================== //

func containLabelByConfiguration(igLabels []string, flowLabels []string) bool {
	for _, label := range igLabels {
		if !libs.ContainsElement(flowLabels, label) {
			return false
		}
	}

	return true
}

func getLabelsFromPod(podName string, pods []types.Pod) []string {
	for _, pod := range pods {
		if pod.PodName == podName {
			return pod.Labels
		}
	}

	return []string{}
}

func getHaveToCheckItems(filter types.SystemLogFilter) int {
	check := 0

	if filter.Namespace != "" {
		check = check | 1<<0 // 1
	}

	if len(filter.Labels) > 0 {
		check = check | 1<<1 // 2
	}

	if len(filter.FileFormats) > 0 {
		check = check | 1<<2 // 4
	}

	if len(filter.ProcessFormats) > 0 {
		check = check | 1<<3 // 8
	}

	if len(filter.FileDirs) > 0 {
		check = check | 1<<4 // 16
	}

	if len(filter.ProcessDirs) > 0 {
		check = check | 1<<5 // 32
	}

	return check
}

func containsFormat(filterFormats []string, logFormat string) bool {
	for _, filterFormat := range filterFormats {
		if strings.HasSuffix(logFormat, filterFormat) {
			return true
		}
	}
	return false
}

func containsDirectory(filterDirs []string, logDir string) bool {
	for _, filterDir := range filterDirs {
		if strings.HasPrefix(logDir, filterDir) {
			return true
		}
	}
	return false
}

func FilterSystemLogsByConfig(logs []types.KnoxSystemLog, pods []types.Pod) []types.KnoxSystemLog {
	filteredLogs := []types.KnoxSystemLog{}

	for _, log := range logs {
		filtered := false

		// basic check 1: if namespace or pod name is blank, skip
		if log.Namespace == "" || log.PodName == "" {
			continue
		}

		// basic check 2: if result is not Passed or Permission denied, skip
		if log.Result != "Passed" && log.Result != "Permission denied" && log.Result != "Operation now in progress" {
			continue
		}

		// basic check 3: if the source is not the absolute path, skip it
		if log.Operation != SYS_OP_NETWORK && !strings.HasPrefix(log.Resource, "/") {
			continue
		}

		if log.Operation == "File" && !strings.HasPrefix(log.Source, "/") {
			continue
		}

		for _, filter := range SystemLogFilters {
			checkItems := getHaveToCheckItems(filter)

			checkedItems := 0

			// 1. check namespace
			if (checkItems&1 > 0) && filter.Namespace == log.Namespace {
				checkedItems = checkedItems | 1<<0
			}

			// 2. check pod labels
			if (checkItems&2 > 0) && (log.Namespace == types.PolicyDiscoveryVMNamespace || log.Namespace == types.PolicyDiscoveryContainerNamespace || containLabelByConfiguration(filter.Labels, getLabelsFromPod(log.PodName, pods))) {
				checkedItems = checkedItems | 1<<1
			}

			// 3. check file formats
			if log.Operation == SYS_OP_FILE && (checkItems&4 > 0) && containsFormat(filter.FileFormats, log.Resource) {
				checkedItems = checkedItems | 1<<2
			}

			// 4. check process formats
			if log.Operation == SYS_OP_PROCESS && (checkItems&8 > 0) && containsFormat(filter.ProcessFormats, log.Resource) {
				checkedItems = checkedItems | 1<<3
			}

			// 5. check file dirs
			if log.Operation == SYS_OP_FILE && (checkItems&16 > 0) && containsDirectory(filter.FileDirs, log.Resource) {
				checkedItems = checkedItems | 1<<4
			}

			// 6. check process dirs
			if log.Operation == SYS_OP_PROCESS && (checkItems&32 > 0) && containsFormat(filter.ProcessDirs, log.Resource) {
				checkedItems = checkedItems | 1<<5
			}

			if checkItems == checkedItems {
				filtered = true
				break
			}
		}

		if !filtered {
			filteredLogs = append(filteredLogs, log)
		}
	}

	return filteredLogs
}

func GetWPFSSources() []string {
	res, _, err := libs.GetWorkloadProcessFileSet(CfgDB, types.WorkloadProcessFileSet{})
	if err != nil {
		log.Error().Msgf("could not fetch WPFS err=%s", err.Error())
		return nil
	}

	if res == nil {
		return nil
	}

	var fromSource []string

	for wpfs := range res {
		if wpfs.FromSource != "" && wpfs.Namespace == types.PolicyDiscoveryVMNamespace {
			fromSource = append(fromSource, wpfs.FromSource)
		}
	}

	return fromSource
}
