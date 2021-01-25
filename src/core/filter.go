package core

import (
	"strconv"
	"strings"

	"github.com/accuknox/knoxAutoPolicy/src/libs"
	types "github.com/accuknox/knoxAutoPolicy/src/types"
)

// ====================== //
// == Helper Functions == //
// ====================== //

// getHaveToCheckItems func
func getHaveToCheckItems(igFlows types.IgnoringFlows) int {
	check := 0

	if igFlows.IgSourceNamespace != "" {
		check = check | 1<<0 // 1
	}

	if len(igFlows.IgSourceLabels) > 0 {
		check = check | 1<<1 // 2
	}

	if igFlows.IgDestinationNamespace != "" {
		check = check | 1<<2 // 4
	}

	if len(igFlows.IgDestinationLabels) > 0 {
		check = check | 1<<3 // 8
	}

	if igFlows.IgProtocol != "" {
		check = check | 1<<4 // 16
	}

	if igFlows.IgPortNumber != "" {
		check = check | 1<<5 // 32
	}

	return check
}

func getLabelsFromPod(podName string, pods []types.Pod) []string {
	for _, pod := range pods {
		if pod.PodName == podName {
			return pod.Labels
		}
	}

	return []string{}
}

// containLabels func
func containLabels(cni string, igLabels []string, flowLabels []string) bool {
	prefix := ""

	if cni == "cilium" {
		prefix = "k8s:"
	}

	for _, label := range igLabels {
		label = prefix + label

		if !libs.ContainsElement(flowLabels, label) {
			return false
		}
	}

	return true
}

// ========================= //
// == Network Log Filter  == //
// ========================= //

// FilterNetworkLogsByConfig func
func FilterNetworkLogsByConfig(logs []types.KnoxNetworkLog, pods []types.Pod) []types.KnoxNetworkLog {
	filteredLogs := []types.KnoxNetworkLog{}

	for _, log := range logs {
		ignored := false

		for _, igFlow := range Cfg.IgnoringFlows {
			checkItems := getHaveToCheckItems(igFlow)

			checkedItems := 0

			// 1. check src namespace
			if (checkItems&1 > 0) && igFlow.IgSourceNamespace == log.SrcNamespace {
				checkedItems = checkedItems | 1<<0
			}

			// 2. check src pod labels
			if (checkItems&2 > 0) && containLabels("cilium", igFlow.IgSourceLabels, getLabelsFromPod(log.SrcPodName, pods)) {
				checkedItems = checkedItems | 1<<1
			}

			// 3. check dest namespace
			if (checkItems&4 > 0) && igFlow.IgDestinationNamespace == log.DstNamespace {
				checkedItems = checkedItems | 1<<2
			}

			// 4. check dest pod labels
			if (checkItems&8 > 0) && containLabels("cilium", igFlow.IgDestinationLabels, getLabelsFromPod(log.DstPodName, pods)) {
				checkedItems = checkedItems | 1<<3
			}

			// 5. check protocol
			if (checkItems&16 > 0) && libs.GetProtocol(log.Protocol) == strings.ToLower(igFlow.IgProtocol) {
				checkedItems = checkedItems | 1<<4
			}

			// 6. check port number (src or dst)
			if checkItems&32 > 0 {
				if strconv.Itoa(log.SrcPort) == igFlow.IgPortNumber || strconv.Itoa(log.DstPort) == igFlow.IgPortNumber {
					checkedItems = checkedItems | 1<<5
				}
			}

			if checkItems == checkedItems {
				ignored = true
				break
			}
		}

		if !ignored {
			filteredLogs = append(filteredLogs, log)
		}
	}

	return filteredLogs
}

// FilterNetworkLogsByNamespace function
func FilterNetworkLogsByNamespace(targetNamespace string, logs []types.KnoxNetworkLog) []types.KnoxNetworkLog {
	filteredLogs := []types.KnoxNetworkLog{}

	for _, log := range logs {
		if log.SrcNamespace != targetNamespace && log.DstNamespace != targetNamespace {
			continue
		}

		filteredLogs = append(filteredLogs, log)
	}

	return filteredLogs
}
