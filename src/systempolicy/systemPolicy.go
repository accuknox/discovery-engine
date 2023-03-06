package systempolicy

import (
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/clarketm/json"
	"k8s.io/utils/strings/slices"
	"sigs.k8s.io/yaml"

	"github.com/accuknox/auto-policy-discovery/src/cluster"
	"github.com/accuknox/auto-policy-discovery/src/common"
	cfg "github.com/accuknox/auto-policy-discovery/src/config"
	fc "github.com/accuknox/auto-policy-discovery/src/feedconsumer"
	"github.com/accuknox/auto-policy-discovery/src/libs"
	logger "github.com/accuknox/auto-policy-discovery/src/logging"
	"github.com/accuknox/auto-policy-discovery/src/plugin"
	wpb "github.com/accuknox/auto-policy-discovery/src/protobuf/v1/worker"
	types "github.com/accuknox/auto-policy-discovery/src/types"

	"github.com/rs/zerolog"

	"github.com/robfig/cron"
)

var log *zerolog.Logger
var kubearmorRelayURL types.ConfigKubeArmorRelay

func init() {
	log = logger.GetInstance()
}

// const values
const (
	// operation mode
	OP_MODE_NOOP    = 0
	OP_MODE_CRONJOB = 1
	OP_MODE_ONETIME = 2

	// status
	STATUS_RUNNING = "running"
	STATUS_IDLE    = "idle"
)

const (
	SYS_OP_PROCESS = "Process"
	SYS_OP_FILE    = "File"
	SYS_OP_NETWORK = "Network"

	SYS_OP_PROCESS_INT = 1
	SYS_OP_FILE_INT    = 2
	SYS_OP_NETWORK_INT = 4

	SOURCE_ALL = "/ALL" // for fromSource 'off'
)

// ====================== //
// == Global Variables == //
// ====================== //

var CfgDB types.ConfigDB

// SystemWorkerStatus global worker
var SystemWorkerStatus string

// for cron job
var SystemCronJob *cron.Cron

var SystemStopChan chan struct{} // for hubble
var OperationTrigger int

var SystemLogLimit int
var SystemLogFrom string
var SystemLogFile string
var SystemPolicyTo string

var SystemPolicyTypes int

var SystemLogFilters []types.SystemLogFilter

var ProcessFromSource bool
var FileFromSource bool

// init Function
func init() {
	SystemWorkerStatus = STATUS_IDLE
	SystemStopChan = make(chan struct{})
}

// ====================== //
// == Internal Testing == //
// ====================== //

func ReplaceMultiubuntuPodName(logs []types.KnoxSystemLog, pods []types.Pod) {
	var pod1Name, pod2Name, pod3Name, pod4Name, pod5Name string

	for _, pod := range pods {
		if strings.Contains(pod.PodName, "ubuntu-1-deployment") {
			pod1Name = pod.PodName
		}

		if strings.Contains(pod.PodName, "ubuntu-2-deployment") {
			pod2Name = pod.PodName
		}

		if strings.Contains(pod.PodName, "ubuntu-3-deployment") {
			pod3Name = pod.PodName
		}

		if strings.Contains(pod.PodName, "ubuntu-4-deployment") {
			pod4Name = pod.PodName
		}

		if strings.Contains(pod.PodName, "ubuntu-5-deployment") {
			pod5Name = pod.PodName
		}
	}

	for i, log := range logs {
		if strings.Contains(log.PodName, "ubuntu-1-deployment") {
			logs[i].PodName = pod1Name
		}

		///

		if strings.Contains(log.PodName, "ubuntu-2-deployment") {
			logs[i].PodName = pod2Name
		}

		///

		if strings.Contains(log.PodName, "ubuntu-3-deployment") {
			logs[i].PodName = pod3Name
		}

		///

		if strings.Contains(log.PodName, "ubuntu-4-deployment") {
			logs[i].PodName = pod4Name
		}

		///

		if strings.Contains(log.PodName, "ubuntu-5-deployment") {
			logs[i].PodName = pod5Name
		}
	}
}

// ========================== //
// == Inner Structure Type == //
// ========================== //

// SysLogKey Structure
type SysLogKey struct {
	Namespace string
	PodName   string
}

// ================ //st
// == System Log == //
// ================ //

func getSystemLogs() []types.KnoxSystemLog {
	systemLogs := []types.KnoxSystemLog{}

	if SystemLogFrom == "file" {
		// =============================== //
		// == File (.json) for testing  == //
		// =============================== //

		jsonLogs := []map[string]interface{}{}
		log.Info().Msg("Get system logs from the json file : " + SystemLogFile)

		// Opens jsonFile
		logFile, err := os.Open(filepath.Clean(SystemLogFile))
		if err != nil {
			log.Error().Msg(err.Error())
			if err := logFile.Close(); err != nil {
				log.Error().Msg(err.Error())
			}
			return nil
		}

		byteValue, err := ioutil.ReadAll(logFile)
		if err != nil {
			log.Error().Msg(err.Error())
		}

		if err := json.Unmarshal(byteValue, &jsonLogs); err != nil {
			log.Error().Msg(err.Error())
			return nil
		}

		// raw json --> knoxSystemLog
		if CfgDB.DBDriver == "mysql" {
			systemLogs = plugin.ConvertMySQLKubeArmorLogsToKnoxSystemLogs(jsonLogs)
		} else if CfgDB.DBDriver == "sqlite3" {
			systemLogs = plugin.ConvertSQLiteKubeArmorLogsToKnoxSystemLogs(jsonLogs)
		}

		// replace the pod names in prepared-logs with the working pod names
		pods := cluster.GetPodsFromK8sClient()
		ReplaceMultiubuntuPodName(systemLogs, pods)

		if err := logFile.Close(); err != nil {
			log.Error().Msg(err.Error())
		}
	} else if SystemLogFrom == "kubearmor" {
		// ================================ //
		// ===		KubeArmor Relay		=== //
		// ================================ //

		// get system logs from kuberarmor relay
		relayLogs := plugin.GetSystemAlertsFromKubeArmorRelay(OperationTrigger)
		if len(relayLogs) == 0 || len(relayLogs) < OperationTrigger {
			return nil
		}

		// convert kubearmor relay logs -> knox system logs
		for _, relayLog := range relayLogs {
			log, err := plugin.ConvertKubeArmorLogToKnoxSystemLog(relayLog)
			if err == nil {
				systemLogs = append(systemLogs, log)
			}
		}
	} else if SystemLogFrom == "feed-consumer" {
		log.Info().Msg("Get system log from feed-consumer")

		// get system logs from kafka/pulsar
		sysLogs := plugin.GetSystemLogsFromFeedConsumer(OperationTrigger)
		if len(sysLogs) == 0 || len(sysLogs) < OperationTrigger {
			return nil
		}

		// convert kubearmor system logs -> knox system logs
		for _, sysLog := range sysLogs {
			systemLogs = append(systemLogs, *sysLog)
		}
	} else {
		log.Error().Msgf("System log from not correct: %s", SystemLogFrom)
		return nil
	}

	return systemLogs
}

func populateKnoxSysPolicyFromWPFSDb(namespace, clustername, labels, fromsource string) []types.KnoxSystemPolicy {
	wpfs := types.WorkloadProcessFileSet{
		Namespace:   namespace,
		ClusterName: clustername,
		Labels:      labels,
		FromSource:  fromsource,
	}
	res, pnMap, err := libs.GetWorkloadProcessFileSet(CfgDB, wpfs)
	if err != nil {
		log.Error().Msgf("could not fetch WPFS err=%s", err.Error())
		return nil
	}
	log.Info().Msgf("found %d WPFS records", len(res))
	return ConvertWPFSToKnoxSysPolicy(res, pnMap)
}

func WriteSystemPoliciesToFile_Ext(namespace, clustername, labels, fromsource string, includeNetwork bool) {
	kubearmorK8SPolicies := extractK8SSystemPolicies(namespace, clustername, labels, fromsource, includeNetwork)
	for _, pol := range kubearmorK8SPolicies {
		fname := "kubearmor_policies_" + pol.Metadata["clusterName"] + "_" + pol.Metadata["namespace"] + "_" + pol.Metadata["containername"] + "_" + pol.Metadata["name"]
		libs.WriteKubeArmorPolicyToYamlFile(fname, []types.KubeArmorPolicy{pol})
	}

	kubearmorVMPolicies, sources := extractVMSystemPolicies(types.PolicyDiscoveryVMNamespace, clustername, labels, fromsource)
	for index, pol := range kubearmorVMPolicies {
		locSrc := strings.ReplaceAll(sources[index], "/", "-")
		fname := "kubearmor_policies_" + pol.Metadata["namespace"] + "_" + pol.Metadata["containername"] + locSrc
		libs.WriteKubeArmorPolicyToYamlFile(fname, []types.KubeArmorPolicy{pol})
	}
}

func WriteSystemPoliciesToFile(namespace, clustername, labels, fromsource string, includeNetwork bool) {
	latestPolicies := libs.GetSystemPolicies(CfgDB, namespace, "latest")
	if len(latestPolicies) > 0 {
		kubeArmorPolicies := plugin.ConvertKnoxSystemPolicyToKubeArmorPolicy(latestPolicies)
		libs.WriteKubeArmorPolicyToYamlFile("kubearmor_policies", kubeArmorPolicies)
	}
	WriteSystemPoliciesToFile_Ext(namespace, clustername, labels, fromsource, includeNetwork)
}

func GetSysPolicy(namespace, clustername, labels, fromsource string, includeNetwork bool) *wpb.WorkerResponse {

	kubearmorK8SPolicies := extractK8SSystemPolicies(namespace, clustername, labels, fromsource, includeNetwork)
	kubearmorVMPolicies, _ := extractVMSystemPolicies(types.PolicyDiscoveryVMNamespace, clustername, labels, fromsource)

	var response wpb.WorkerResponse

	// system policy for k8s
	for i := range kubearmorK8SPolicies {
		kubearmorpolicy := wpb.Policy{}

		val, err := json.Marshal(&kubearmorK8SPolicies[i])
		if err != nil {
			log.Error().Msgf("kubearmorK8SPolicy json marshal failed err=%v", err.Error())
		}
		kubearmorpolicy.Data = val

		response.Kubearmorpolicy = append(response.Kubearmorpolicy, &kubearmorpolicy)
	}

	// system policy for VM
	for i := range kubearmorVMPolicies {
		kubearmorpolicy := wpb.Policy{}

		val, err := json.Marshal(&kubearmorVMPolicies[i])
		if err != nil {
			log.Error().Msgf("kubearmorVMPolicy json marshal failed err=%v", err.Error())
		}
		kubearmorpolicy.Data = val

		response.Kubearmorpolicy = append(response.Kubearmorpolicy, &kubearmorpolicy)
	}

	response.Res = "OK"
	response.Ciliumpolicy = nil

	return &response
}

func extractK8SSystemPolicies(namespace, clustername, labels, fromsource string, includeNetwork bool) []types.KubeArmorPolicy {
	sysPols := populateKnoxSysPolicyFromWPFSDb(namespace, clustername, labels, fromsource)
	policies := plugin.ConvertKnoxSystemPolicyToKubeArmorPolicy(sysPols)

	var result []types.KubeArmorPolicy
	for _, pol := range policies {
		if pol.Metadata["namespace"] != types.PolicyDiscoveryVMNamespace {
			if !includeNetwork {
				pol.Spec.Network = types.NetworkRule{}
			}

			for i := range pol.Spec.Process.MatchPaths {
				if len(pol.Spec.Process.MatchPaths[i].FromSource) != 0 {
					pol.Spec.Process.MatchPaths[i].FromSource = []types.KnoxFromSource{}
				}
			}

			for i := range pol.Spec.Process.MatchDirectories {
				if len(pol.Spec.Process.MatchDirectories[i].FromSource) != 0 {
					pol.Spec.Process.MatchDirectories[i].FromSource = []types.KnoxFromSource{}
				}
			}

			// if a binary is a global binary, convert file access to global
			globalbinaries := []string{}
			for _, binary := range pol.Spec.Process.MatchPaths {
				if len(binary.FromSource) == 0 && !slices.Contains(globalbinaries, binary.Path) {
					globalbinaries = append(globalbinaries, binary.Path)
				}
			}

			// add global binaries to file access list
			for _, binary := range globalbinaries {
				pol.Spec.File.MatchPaths = append(pol.Spec.File.MatchPaths, types.KnoxMatchPaths{
					Path:     binary,
					ReadOnly: true,
				})
			}

			for i, matchpath := range pol.Spec.File.MatchPaths {
				for _, binary := range matchpath.FromSource {
					if slices.Contains(globalbinaries, binary.Path) {
						pol.Spec.File.MatchPaths[i].FromSource = []types.KnoxFromSource{}
						break
					}
				}
			}

			for i, matchDir := range pol.Spec.File.MatchDirectories {
				for _, binary := range matchDir.FromSource {
					if slices.Contains(globalbinaries, binary.Path) {
						pol.Spec.File.MatchDirectories[i].FromSource = []types.KnoxFromSource{}
						break
					}
				}
			}

			for i, netRule := range pol.Spec.Network.MatchProtocols {
				for _, binary := range netRule.FromSource {
					if slices.Contains(globalbinaries, binary.Path) {
						pol.Spec.Network.MatchProtocols[i].FromSource = []types.KnoxFromSource{}
						break
					}
				}
			}

			result = append(result, pol)
		}
	}
	return result
}

func extractVMSystemPolicies(namespace, clustername, labels, fromSource string) ([]types.KubeArmorPolicy, []string) {

	var frmSrcSlice []string
	var resFromSrc []string

	if fromSource == "" {
		frmSrcSlice = GetWPFSSources()
	} else {
		frmSrcSlice = append(frmSrcSlice, fromSource)
	}

	var result []types.KubeArmorPolicy

	for _, fromSource := range frmSrcSlice {
		sysPols := populateKnoxSysPolicyFromWPFSDb(namespace, clustername, labels, fromSource)
		policies := plugin.ConvertKnoxSystemPolicyToKubeArmorPolicy(sysPols)

		for _, pol := range policies {
			if pol.Metadata["namespace"] == types.PolicyDiscoveryVMNamespace {
				result = append(result, pol)
				resFromSrc = append(resFromSrc, fromSource)
			}
		}
	}
	return result, resFromSrc
}

// ============================= //
// == Discover System Policy  == //
// ============================= //

func clusteringSystemLogsByCluster(logs []types.KnoxSystemLog) map[string][]types.KnoxSystemLog {
	results := map[string][]types.KnoxSystemLog{} // key: cluster name - val: system logs

	for _, log := range logs {
		results[log.ClusterName] = append(results[log.ClusterName], log)
	}

	return results
}

func clusteringSystemLogsByNamespacePod(logs []types.KnoxSystemLog) map[SysLogKey][]types.KnoxSystemLog {
	results := map[SysLogKey][]types.KnoxSystemLog{} // key: cluster name - val: system logs

	for _, log := range logs {
		key := SysLogKey{
			Namespace: log.Namespace,
			PodName:   log.PodName,
		}

		results[key] = append(results[key], log)
	}

	return results
}

func systemLogDeduplication(logs []types.KnoxSystemLog) []types.KnoxSystemLog {
	results := []types.KnoxSystemLog{}

	for _, log := range logs {
		if libs.ContainsElement(results, log) {
			continue
		}

		// if source == resource, skip
		if log.Source == log.Resource {
			continue
		}

		// if pod name or namespace == ""
		if log.PodName == "" || log.Namespace == "" {
			continue
		}

		results = append(results, log)
	}

	return results
}

func getOperationLogs(operation string, logs []types.KnoxSystemLog) []types.KnoxSystemLog {
	results := []types.KnoxSystemLog{}

	for _, log := range logs {
		// operation can be : Process, File, Network
		if log.Operation == operation {
			results = append(results, log)
		}
	}

	return results
}

func discoverFileOperationPolicy(results []types.KnoxSystemPolicy, pod types.Pod, logs []types.KnoxSystemLog) []types.KnoxSystemPolicy {
	// step 1: [system logs] -> {source: []destination(resource)}
	srcToDest := map[string][]string{}

	// file spec is appended?
	appended := false

	for _, log := range logs {
		if !FileFromSource {
			log.Source = SOURCE_ALL
		}

		if val, ok := srcToDest[log.Source]; ok {
			if !libs.ContainsElement(val, log.Resource) {
				srcToDest[log.Source] = append(srcToDest[log.Source], log.Resource)
			}
		} else {
			srcToDest[log.Source] = []string{log.Resource}
		}
	}

	// step 2: build file operation
	policy := buildSystemPolicy()
	policy.Metadata["type"] = SYS_OP_FILE
	policy.Spec.File = types.KnoxSys{}

	// step 3: aggregate file paths
	for src, filePaths := range srcToDest {
		aggregatedFilePaths := common.AggregatePaths(filePaths)

		// step 4: append spec to the policy
		for _, filePath := range aggregatedFilePaths {
			appended = true
			policy = updateSysPolicySpec(SYS_OP_FILE, policy, src, filePath)
		}
	}

	if appended {
		results = append(results, policy)
	}

	return results
}

func discoverProcessOperationPolicy(results []types.KnoxSystemPolicy, pod types.Pod, logs []types.KnoxSystemLog) []types.KnoxSystemPolicy {
	// step 1: [system logs] -> {source: []destination(resource)}
	srcToDest := map[string][]string{}

	// process spec is appended?
	appended := false

	for _, log := range logs {
		if !ProcessFromSource {
			log.Source = SOURCE_ALL
		}

		if val, ok := srcToDest[log.Source]; ok {
			if !libs.ContainsElement(val, log.Resource) {
				srcToDest[log.Source] = append(srcToDest[log.Source], log.Resource)
			}
		} else {
			srcToDest[log.Source] = []string{log.Resource}
		}
	}

	// step 2: build process operation
	policy := buildSystemPolicy()
	policy.Metadata["type"] = SYS_OP_PROCESS
	policy.Spec.Process = types.KnoxSys{}

	// step 3: aggregate process paths
	for src, processPaths := range srcToDest {
		aggregatedProcessPaths := common.AggregatePaths(processPaths)

		// step 4: append spec to the policy
		for _, processPath := range aggregatedProcessPaths {
			appended = true
			policy = updateSysPolicySpec(SYS_OP_PROCESS, policy, src, processPath)
		}
	}

	if appended {
		results = append(results, policy)
	}

	return results
}

func checkIfMetadataMatches(pin types.KnoxSystemPolicy, hay []types.KnoxSystemPolicy) int {
	for idx, v := range hay {
		if pin.Metadata["clusterName"] == v.Metadata["clusterName"] &&
			pin.Metadata["namespace"] == v.Metadata["namespace"] &&
			pin.Metadata["containername"] == v.Metadata["containername"] &&
			pin.Metadata["labels"] == v.Metadata["labels"] {
			return idx
		}
	}
	return -1
}

func cmpGenPathDir(p1 string, p1fs []types.KnoxFromSource, p2 string, p2fs []types.KnoxFromSource) bool {
	if len(p1fs) > 0 {
		for _, v := range p1fs {
			p1 = p1 + v.Path
		}
	}

	if len(p2fs) > 0 {
		for _, v := range p2fs {
			p2 = p2 + v.Path
		}
	}
	return p1 < p2
}

func cmpPaths(p1 types.KnoxMatchPaths, p2 types.KnoxMatchPaths) bool {
	return cmpGenPathDir(p1.Path, p1.FromSource, p2.Path, p2.FromSource)
}

func cmpProts(p1 types.KnoxMatchProtocols, p2 types.KnoxMatchProtocols) bool {
	return cmpGenPathDir(p1.Protocol, p1.FromSource, p2.Protocol, p2.FromSource)
}

func cmpDirs(p1 types.KnoxMatchDirectories, p2 types.KnoxMatchDirectories) bool {
	return cmpGenPathDir(p1.Dir, p1.FromSource, p2.Dir, p2.FromSource)
}

func sortFromSource(fs *[]types.KnoxFromSource) {
	if len(*fs) <= 1 {
		return
	}
	sort.Slice(*fs, func(x, y int) bool {
		return (*fs)[x].Path+(*fs)[x].Dir < (*fs)[y].Path+(*fs)[y].Dir
	})
}

func mergeFromSourceMatchPaths(pmp []types.KnoxMatchPaths, mp *[]types.KnoxMatchPaths) {
	for _, pp := range pmp {
		match := false
		for i := range *mp {
			rp := &(*mp)[i]
			if pp.Path == (*rp).Path {
				(*rp).FromSource = append((*rp).FromSource, pp.FromSource...)
				//remove dups
				match = true
			}
			sortFromSource(&(*rp).FromSource)
		}
		if !match {
			*mp = append(*mp, pp)
		}
	}
}

func mergeFromSourceMatchDirs(pmp []types.KnoxMatchDirectories, mp *[]types.KnoxMatchDirectories) {
	for _, pp := range pmp {
		match := false
		for i := range *mp {
			rp := &(*mp)[i]
			if pp.Dir == (*rp).Dir {
				(*rp).FromSource = append((*rp).FromSource, pp.FromSource...)
				//remove dups
				match = true
			}
			sortFromSource(&(*rp).FromSource)
		}
		if !match {
			*mp = append(*mp, pp)
		}
	}
}

func mergeFromSourceMatchProt(pmp []types.KnoxMatchProtocols, mp *[]types.KnoxMatchProtocols) {
	for _, pp := range pmp {
		match := false
		for i := range *mp {
			rp := &(*mp)[i]
			if pp.Protocol == (*rp).Protocol {
				(*rp).FromSource = append((*rp).FromSource, pp.FromSource...)
				//remove dups
				match = true
			}
			sortFromSource(&(*rp).FromSource)
		}
		if !match {
			*mp = append(*mp, pp)
		}
	}
}

/*
The aim of the foll API is to merge multiple fromSources within the same policy.

For e.g.,
---[Input]---

	matchPaths:
	- path: /etc/ld.so.cache
	  fromSource:
	  - path: /bin/ls
	- path: /etc/ld.so.cache
	  fromSource:
	  - path: /bin/sleep

---

---[Expected Output]---

	matchPaths:
	- path: /etc/ld.so.cache
	  fromSource:
	  - path: /bin/ls
	  - path: /bin/sleep

---
*/
func mergeFromSource(pols []types.KnoxSystemPolicy) []types.KnoxSystemPolicy {
	/*
		Logic:
		1. For every pol
		2. Check if pol matches any policy in res
			If no, Create new res (with metadata), without any MatchPath, MatchDir, Network
			If yes,
		3.
				a. For every MatchPath in pol,
					check if Path matches with any Path in res[i]
					if Yes,
						copy pol.MatchPath[I].FromSource to pol.MatchPath[J].FromSource
						remove pol.MatchPath[J]
					if No,
						Append pol.MatchPath[i] -> res.MatchPath
				b. Similarly for every MatchDirectories
			If No,

				a. For every MatchPath in pol,
					check if Path

	*/
	var results []types.KnoxSystemPolicy
	for _, pol := range pols {
		checked := false
	check:
		i := checkIfMetadataMatches(pol, results)
		if i < 0 {
			if checked {
				/* If a policy is not present in results, we create metadata
				* for the newpol based on pol and reset Process/Network/File
				* structure info. The aim is the checkIfMetadaMatches should
				* return valid index of the newly appended newpol. */
				// Ideally, this condition should never be hit.
				log.Error().Msgf("assumptions went wrong. some policies wont work %+v", pol)
				continue
			}
			newpol := pol
			newpol.Spec.Process = types.KnoxSys{}
			newpol.Spec.File = types.KnoxSys{}
			newpol.Spec.Network = types.NetworkRule{}
			results = append(results, newpol)
			checked = true
			goto check
		}

		mergeFromSourceMatchPaths(pol.Spec.File.MatchPaths, &results[i].Spec.File.MatchPaths)
		mergeFromSourceMatchDirs(pol.Spec.File.MatchDirectories, &results[i].Spec.File.MatchDirectories)

		mergeFromSourceMatchPaths(pol.Spec.Process.MatchPaths, &results[i].Spec.Process.MatchPaths)
		mergeFromSourceMatchDirs(pol.Spec.Process.MatchDirectories, &results[i].Spec.Process.MatchDirectories)

		mergeFromSourceMatchProt(pol.Spec.Network.MatchProtocols, &results[i].Spec.Network.MatchProtocols)
	}
	return results
}

func mergeSysPolicies(pols []types.KnoxSystemPolicy) []types.KnoxSystemPolicy {
	var results []types.KnoxSystemPolicy
	for _, pol := range pols {
		pol.Metadata["name"] = "autopol-system-" +
			strconv.FormatUint(uint64(common.HashInt(pol.Metadata["labels"]+
				pol.Metadata["namespace"]+pol.Metadata["clustername"]+pol.Metadata["containername"])), 10)
		i := checkIfMetadataMatches(pol, results)
		if i < 0 {
			results = append(results, pol)
			continue
		}

		if len(pol.Spec.File.MatchPaths) > 0 {
			mp := &results[i].Spec.File.MatchPaths
			*mp = append(*mp, pol.Spec.File.MatchPaths...)
		}
		if len(pol.Spec.File.MatchDirectories) > 0 {
			mp := &results[i].Spec.File.MatchDirectories
			*mp = append(*mp, pol.Spec.File.MatchDirectories...)
		}
		if len(pol.Spec.Process.MatchPaths) > 0 {
			mp := &results[i].Spec.Process.MatchPaths
			*mp = append(*mp, pol.Spec.Process.MatchPaths...)
		}
		if len(pol.Spec.Process.MatchDirectories) > 0 {
			mp := &results[i].Spec.Process.MatchDirectories
			*mp = append(*mp, pol.Spec.Process.MatchDirectories...)
		}
		if len(pol.Spec.Network.MatchProtocols) > 0 {
			mp := &results[i].Spec.Network.MatchProtocols
			*mp = append(*mp, pol.Spec.Network.MatchProtocols...)
		}
		results[i].Metadata["name"] = pol.Metadata["name"]
	}

	results = mergeFromSource(results)

	// merging and sorting all the rules at MatchPaths, MatchDirs, MatchProtocols level
	// sorting is needed so that the rules are placed consistently in the
	// same order everytime the policy is generated
	for _, pol := range results {
		if len(pol.Spec.File.MatchPaths) > 0 {
			mp := &pol.Spec.File.MatchPaths
			sort.Slice(*mp, func(x, y int) bool {
				return cmpPaths((*mp)[x], (*mp)[y])
			})
		}
		if len(pol.Spec.File.MatchDirectories) > 0 {
			mp := &pol.Spec.File.MatchDirectories
			sort.Slice(*mp, func(x, y int) bool {
				return cmpDirs((*mp)[x], (*mp)[y])
			})
		}
		if len(pol.Spec.Process.MatchPaths) > 0 {
			mp := &pol.Spec.Process.MatchPaths
			sort.Slice(*mp, func(x, y int) bool {
				return cmpPaths((*mp)[x], (*mp)[y])
			})
		}
		if len(pol.Spec.Process.MatchDirectories) > 0 {
			mp := &pol.Spec.Process.MatchDirectories
			sort.Slice(*mp, func(x, y int) bool {
				return cmpDirs((*mp)[x], (*mp)[y])
			})
		}
		if len(pol.Spec.Network.MatchProtocols) > 0 {
			mp := &pol.Spec.Network.MatchProtocols
			sort.Slice(*mp, func(x, y int) bool {
				return cmpProts((*mp)[x], (*mp)[y])
			})
		}
	}
	log.Info().Msgf("Merged %d sys policies into %d policies", len(pols), len(results))
	return results
}

func ConvertWPFSToKnoxSysPolicy(wpfsSet types.ResourceSetMap, pnMap types.PolicyNameMap) []types.KnoxSystemPolicy {
	var results []types.KnoxSystemPolicy
	for wpfs, fsset := range wpfsSet {
		policy := buildSystemPolicy()
		policy.Metadata["type"] = wpfs.SetType

		for _, fpath := range fsset {
			path := common.SysPath{
				Path:  fpath,
				IsDir: strings.HasSuffix(fpath, "/"),
			}
			src := ""
			if wpfs.SetType == SYS_OP_NETWORK || strings.HasPrefix(wpfs.FromSource, "/") {
				src = wpfs.FromSource
			}
			policy = updateSysPolicySpec(wpfs.SetType, policy, src, path)
		}

		policy.Metadata["clusterName"] = wpfs.ClusterName
		policy.Metadata["namespace"] = wpfs.Namespace
		policy.Metadata["containername"] = wpfs.ContainerName
		policy.Metadata["labels"] = wpfs.Labels
		policy.Metadata["name"] = pnMap[wpfs]

		if wpfs.Labels != "" {
			labels := strings.Split(wpfs.Labels, ",")
			for _, label := range labels {
				k := strings.Split(label, "=")[0]
				v := strings.Split(label, "=")[1]
				policy.Spec.Selector.MatchLabels[k] = v
			}
		}

		results = append(results, policy)
	}

	results = mergeSysPolicies(results)

	return results
}

func getPodInstance(key SysLogKey, pods []types.Pod) (types.Pod, error) {
	for _, pod := range pods {
		if key.Namespace == pod.Namespace && key.PodName == pod.PodName {
			return pod, nil
		}
	}

	return types.Pod{}, errors.New("Not exist: " + key.Namespace + " " + key.PodName)
}

// ============================ //
// == Building System Policy == //
// ============================ //

func buildSystemPolicy() types.KnoxSystemPolicy {
	return types.KnoxSystemPolicy{
		APIVersion: "v1",
		Kind:       "KnoxSystemPolicy",
		Metadata:   map[string]string{},
		Spec: types.KnoxSystemSpec{
			Severity: 1, // by default
			Selector: types.Selector{
				MatchLabels: map[string]string{}},
			Action: "Allow",
		},
	}
}

func updateSysPolicySpec(opType string, policy types.KnoxSystemPolicy, src string, pathSpec common.SysPath) types.KnoxSystemPolicy {
	if opType == SYS_OP_NETWORK {
		matchProtocols := types.KnoxMatchProtocols{
			Protocol: pathSpec.Path,
		}
		matchProtocols.FromSource = []types.KnoxFromSource{
			{
				Path: src,
			},
		}
		policy.Metadata["fromSource"] = src
		policy.Spec.Network.MatchProtocols = append(policy.Spec.Network.MatchProtocols, matchProtocols)
		return policy
	}
	// matchDirectories
	if pathSpec.IsDir {
		path := pathSpec.Path
		if !strings.HasSuffix(path, "/") {
			path = path + "/"
		}
		matchDirs := types.KnoxMatchDirectories{
			Dir:       path,
			Recursive: true,
		}

		if opType == SYS_OP_FILE {
			if FileFromSource {
				if src != "" {
					matchDirs.FromSource = []types.KnoxFromSource{
						{
							Path: src,
						},
					}
				}
				policy.Metadata["fromSource"] = src
			}

			policy.Spec.File.MatchDirectories = append(policy.Spec.File.MatchDirectories, matchDirs)
		} else if opType == SYS_OP_PROCESS {
			if ProcessFromSource {
				if src != "" {
					matchDirs.FromSource = []types.KnoxFromSource{
						{
							Path: src,
						},
					}
				}
				policy.Metadata["fromSource"] = src
			}

			policy.Spec.Process.MatchDirectories = append(policy.Spec.Process.MatchDirectories, matchDirs)
		}
	} else {
		// matchPaths
		matchPaths := types.KnoxMatchPaths{
			Path: pathSpec.Path,
		}

		if opType == SYS_OP_FILE {
			if FileFromSource {
				if src != "" {
					matchPaths.FromSource = []types.KnoxFromSource{
						{
							Path: src,
						},
					}
				}
				policy.Metadata["fromSource"] = src
			}

			policy.Spec.File.MatchPaths = append(policy.Spec.File.MatchPaths, matchPaths)
		} else if opType == SYS_OP_PROCESS {
			if ProcessFromSource {
				if src != "" {
					matchPaths.FromSource = []types.KnoxFromSource{
						{
							Path: src,
						},
					}
				}
				policy.Metadata["fromSource"] = src
			}

			policy.Spec.Process.MatchPaths = append(policy.Spec.Process.MatchPaths, matchPaths)
		}
	}

	return policy
}

func updateSysPolicySelector(clusterName string, pod types.Pod, policies []types.KnoxSystemPolicy) []types.KnoxSystemPolicy {
	results := []types.KnoxSystemPolicy{}

	for _, policy := range policies {
		policy.Metadata["clusterName"] = clusterName
		policy.Metadata["namespace"] = pod.Namespace

		for _, label := range pod.Labels {
			k := strings.Split(label, "=")[0]
			v := strings.Split(label, "=")[1]
			policy.Spec.Selector.MatchLabels[k] = v
		}

		results = append(results, policy)
	}

	return results
}

// UpdateSysPolicies updates system policy
func UpdateSysPolicies(wpfsPolicies []types.KnoxSystemPolicy) {

	var locSysPolicies []types.KnoxSystemPolicy
	var isPolicyExist bool

	if len(wpfsPolicies) < 1 {
		wpfsPolicies = populateKnoxSysPolicyFromWPFSDb("", "", "", "")
	}

	InsertSysPoliciesYamlToDB(wpfsPolicies)

	for _, wpfsPolicy := range wpfsPolicies {
		isPolicyExist = false
		sysPoliciesDb := libs.GetSystemPolicies(CfgDB, "", "")

		for _, sysPolicyDb := range sysPoliciesDb {
			if sysPolicyDb.Metadata["name"] == wpfsPolicy.Metadata["name"] {
				libs.UpdateSystemPolicy(CfgDB, wpfsPolicy)
				isPolicyExist = true
				break
			}
		}

		if !isPolicyExist {
			locSysPolicies = append(locSysPolicies, wpfsPolicy)
		}
	}

	libs.InsertSystemPolicies(CfgDB, locSysPolicies)
}

// ============================= //
// == Discover System Policy  == //
// ============================= //

func InitSysPolicyDiscoveryConfiguration() {
	CfgDB = cfg.GetCfgDB()

	OperationTrigger = cfg.GetCfgSysOperationTrigger()

	SystemLogLimit = cfg.GetCfgSysLimit()
	SystemLogFrom = cfg.GetCfgSystemLogFrom()
	SystemLogFile = cfg.GetCfgSystemLogFile()
	SystemPolicyTo = cfg.GetCfgSystemPolicyTo()

	SystemPolicyTypes = cfg.GetCfgSystemkPolicyTypes()

	SystemLogFilters = cfg.GetCfgSystemLogFilters()

	ProcessFromSource = cfg.GetCfgSystemProcFromSource()
	FileFromSource = cfg.GetCfgSystemFileFromSource()
}

func PopulateSystemPoliciesFromSystemLogs(sysLogs []types.KnoxSystemLog) []types.KnoxSystemPolicy {

	discoveredSystemPolicies := []types.KnoxSystemPolicy{}

	// delete duplicate logs
	sysLogs = systemLogDeduplication(sysLogs)

	// get cluster names, iterate each cluster
	clusteredLogs := clusteringSystemLogsByCluster(sysLogs)

	existingPolicies := libs.GetSystemPolicies(CfgDB, "", "")
	log.Info().Msgf("len(tot-syslogs):%d len(existingPolicies):%d", len(sysLogs), len(existingPolicies))
	for clusterName, sysLogs := range clusteredLogs {
		// get existing system policies in db
		log.Info().Msgf("system policy discovery cluster [%s] len(sysLogs):%d", clusterName, len(sysLogs))

		// get k8s pods
		pods := cluster.GetPods(clusterName)

		// filter system logs from configuration
		cfgFilteredLogs := FilterSystemLogsByConfig(sysLogs, pods)

		// iterate sys log key := [namespace + pod_name]
		nsPodLogs := clusteringSystemLogsByNamespacePod(cfgFilteredLogs)

		for sysKey, perPodlogs := range nsPodLogs {
			discoveredSysPolicies := []types.KnoxSystemPolicy{}

			pod, err := getPodInstance(sysKey, pods)
			if err != nil {
				log.Error().Msg(err.Error())
				continue
			}

			polCnt := 0
			isWpfsDbUpdated := false
			// 1. discover file operation system policy
			if SystemPolicyTypes&SYS_OP_FILE_INT > 0 {
				fileOpLogs := getOperationLogs(SYS_OP_FILE, perPodlogs)
				isWpfsDbUpdated = GenFileSetForAllPodsInCluster(clusterName, pods, SYS_OP_FILE, fileOpLogs) || isWpfsDbUpdated
				if !cfg.CurrentCfg.ConfigSysPolicy.DeprecateOldMode {
					discoveredSysPolicies = discoverFileOperationPolicy(discoveredSysPolicies, pod, fileOpLogs)
					log.Info().Msgf("discovered %d file policies from %d file logs",
						len(discoveredSysPolicies), len(fileOpLogs))
				}
			}

			// 2. discover process operation system policy
			if SystemPolicyTypes&SYS_OP_PROCESS_INT > 0 {
				procOpLogs := getOperationLogs(SYS_OP_PROCESS, perPodlogs)
				isWpfsDbUpdated = GenFileSetForAllPodsInCluster(clusterName, pods, SYS_OP_PROCESS, procOpLogs) || isWpfsDbUpdated
				if !cfg.CurrentCfg.ConfigSysPolicy.DeprecateOldMode {
					discoveredSysPolicies = discoverProcessOperationPolicy(discoveredSysPolicies, pod, procOpLogs)
					polCnt = len(discoveredSysPolicies)
					log.Info().Msgf("discovered %d process policies from %d process logs",
						len(discoveredSysPolicies)-polCnt, len(procOpLogs))
				}
			}

			// 3. discover network operation system policy
			if SystemPolicyTypes&SYS_OP_NETWORK_INT > 0 {
				netOpLogs := getOperationLogs(SYS_OP_NETWORK, perPodlogs)
				isWpfsDbUpdated = GenFileSetForAllPodsInCluster(clusterName, pods, SYS_OP_NETWORK, netOpLogs) || isWpfsDbUpdated

			}

			if cfg.CurrentCfg.ConfigSysPolicy.DeprecateOldMode {
				// New mode of system policy generation using WPFS table
				if isWpfsDbUpdated {
					UpdateSysPolicies([]types.KnoxSystemPolicy{})
				}
			}

			if !cfg.CurrentCfg.ConfigSysPolicy.DeprecateOldMode {
				// 3. update selector
				discoveredSysPolicies = updateSysPolicySelector(clusterName, pod, discoveredSysPolicies)
				discoveredSystemPolicies = append(discoveredSystemPolicies, discoveredSysPolicies...)

				// 4. update duplicated policy
				newPolicies := UpdateDuplicatedPolicy(existingPolicies, discoveredSysPolicies, clusterName)

				if len(newPolicies) > 0 {
					// insert discovered policies to db
					if strings.Contains(SystemPolicyTo, "db") {
						libs.InsertSystemPolicies(CfgDB, newPolicies)
					}

					log.Info().Msgf("system policy discovery done for [%s/%s/%s], [%d] policies discovered",
						clusterName, pod.Namespace, pod.PodName, len(newPolicies))
				}
			}

			if strings.Contains(SystemPolicyTo, "file") {
				WriteSystemPoliciesToFile(sysKey.Namespace, "", "", "", true)
			}
		}
	}

	return discoveredSystemPolicies
}

func GetPodLabels(cn string, pn string, ns string, pods []types.Pod) ([]string, error) {
	for _, pod := range pods {
		if pod.Namespace == ns && pod.PodName == pn {
			return pod.Labels, nil
		}
	}
	return nil, errors.New("pod not found")
}

// Merge, remove duplicates and sort
func mergeStringSlices(a []string, b []string) []string {
	check := make(map[string]int)
	d := append(a, b...)
	res := make([]string, 0)
	for _, val := range d {
		check[val] = 1
	}
	for letter := range check {
		res = append(res, letter)
	}
	sort.Strings(res)
	return res
}

var retcp, reudp, reicmp, reraw *regexp.Regexp
var reInit bool

func regexInit() error {
	if reInit {
		return nil
	}
	var err error
	retcp, err = regexp.Compile("domain=.*type=SOCK_STREAM")
	if err != nil {
		log.Error().Msgf("failed tcp regexp compile err=%s", err.Error())
		return err
	}
	reudp, err = regexp.Compile("domain=.*type=SOCK_DGRAM")
	if err != nil {
		log.Error().Msgf("failed udp regexp compile err=%s", err.Error())
		return err
	}
	reicmp, err = regexp.Compile(`domain=.*protocol=(\b58\b|\b1\b)`) //1=icmp, 58=icmp6
	if err != nil {
		log.Error().Msgf("failed icmp regexp compile err=%s", err.Error())
		return err
	}
	reraw, err = regexp.Compile("domain=.*type=SOCK_RAW")
	if err != nil {
		log.Error().Msgf("failed raw regexp compile err=%s", err.Error())
		return err
	}
	reInit = true
	return nil
}

func getProtocolType(str string) string {
	if err := regexInit(); err != nil {
		return ""
	}

	if reicmp.MatchString(str) {
		return "icmp"
		// return "icmp,icmp6"
	}
	if retcp.MatchString(str) {
		return "tcp"
	}
	if reudp.MatchString(str) {
		return "udp"
	}
	if reraw.MatchString(str) {
		return "raw"
	}
	return ""
}

// cleanResource : Certain linux files keep changing always and needs to refed
// just once. Examples are /proc, /sys.
func cleanResource(op string, str string) []string {
	var arr []string
	if op == SYS_OP_NETWORK {
		prot := getProtocolType(str)
		if prot != "" {
			arr = strings.Split(prot, ",")
		}
	} else {
		if strings.HasPrefix(str, "/proc") {
			arr = append(arr, "/proc/")
		} else if strings.HasPrefix(str, "/sys") {
			arr = append(arr, "/sys/")
		} else {
			arr = append(arr, str)
		}
	}
	return arr
}

// removeDuplicates Works by Sorting the input and then checking if consecutive elements are same
func removeDuplicates(arr []string) []string {
	var res []string
	sort.Strings(arr)
	prev := ""
	for _, v := range arr {
		if prev == v {
			continue
		}
		prev = v
		res = append(res, v)
	}
	return res
}

// GenFileSetForAllPodsInCluster Generate process specific fileset across all pods in a cluster
func GenFileSetForAllPodsInCluster(clusterName string, pods []types.Pod, settype string, slogs []types.KnoxSystemLog) bool {
	res := types.ResourceSetMap{} // key: WorkloadProcess - val: Accesss File Set
	wpfs := types.WorkloadProcessFileSet{}
	isNetworkOp := false
	status := false
	if settype == SYS_OP_NETWORK {
		isNetworkOp = true // for network logs, need full ResourceOrigin to do regexp matching in getProtocolType()
	}
	var resource []string
	for _, slog := range slogs {
		wpfs.ClusterName = slog.ClusterName
		wpfs.ContainerName = slog.ContainerName
		wpfs.Namespace = slog.Namespace
		wpfs.FromSource = slog.Source
		wpfs.SetType = settype
		labels, err := GetPodLabels(slog.ClusterName, slog.PodName, slog.Namespace, pods)
		if err != nil {
			log.Error().Msgf("could not get pod labels for podname=%s ns=%s", slog.PodName, slog.Namespace)
			continue
		}

		if slog.Namespace == types.PolicyDiscoveryContainerNamespace {
			labels = append(labels, "kubearmor.io/container.name="+slog.ContainerName)
		}

		wpfs.Labels = strings.Join(labels[:], ",")

		if isNetworkOp {
			resource = cleanResource(settype, slog.ResourceOrigin)
		} else {
			resource = cleanResource(settype, slog.Resource)
		}
		if len(resource) == 0 {
			continue
		}
		res[wpfs] = append(res[wpfs], resource...)
	}

	var mergedfs []string
	for wpfs, fs := range res {
		out, _, err := libs.GetWorkloadProcessFileSet(CfgDB, wpfs)
		if err != nil {
			log.Error().Msgf("failed processing wpfs=%+v err=%s", wpfs, err.Error())
			continue
		}
		dbEntry := true
		if len(out[wpfs]) == 0 {
			dbEntry = false
		}
		mergedfs = removeDuplicates(append(fs, out[wpfs]...))
		if !isNetworkOp {
			// Path aggregation makes sense for file, process operations only
			mergedfs = common.AggregatePathsExt(mergedfs) // merge and sort the filesets
		}

		sort.SliceStable(mergedfs, func(i, j int) bool {
			return (len(mergedfs[i]) < len(mergedfs[j]))
		})

		i := 0
		lenMergedFs := len(mergedfs)
		for i < lenMergedFs {
			j := i + 1
			lenMergedFs = len(mergedfs)
			if strings.HasSuffix(mergedfs[i], "/") {
				for j < lenMergedFs {
					if (len(mergedfs[i]) < len(mergedfs[j])) && strings.HasPrefix(mergedfs[j], mergedfs[i]) {
						lenMergedFs--
						mergedfs = append(mergedfs[:j], mergedfs[j+1:]...)
						continue
					}
					j++
				}
			}
			i++
		}
		// Add/Update DB Entry
		if !dbEntry {
			log.Info().Msgf("adding wpfs db entry for wpfs=%+v", wpfs)
			err = libs.InsertWorkloadProcessFileSet(CfgDB, wpfs, mergedfs)
			status = true
		} else {
			if !reflect.DeepEqual(mergedfs, out[wpfs]) {
				log.Info().Msgf("updating wpfs db entry for wpfs=%+v", wpfs)
				if CfgDB.DBDriver == "mysql" {
					err = libs.UpdateWorkloadProcessFileSetMySQL(CfgDB, wpfs, mergedfs)
					status = true
				} else if CfgDB.DBDriver == "sqlite3" {
					err = libs.UpdateWorkloadProcessFileSetSQLite(CfgDB, wpfs, mergedfs)
					status = true
				}
			}
		}
		if err != nil {
			log.Error().Msgf("failure add/updt db entry for wpfs=%+v err=%s", wpfs, err.Error())
		}
	}

	return status
}

// InsertSysPoliciesYamlToDB inserts systempolicy to DB
func InsertSysPoliciesYamlToDB(policies []types.KnoxSystemPolicy) {

	kubeArmorPolicies := plugin.ConvertKnoxSystemPolicyToKubeArmorPolicy(policies)

	res := []types.PolicyYaml{}
	for _, kubearmorPolicy := range kubeArmorPolicies {
		// dont save network policies to db
		kubearmorPolicy.Spec.Network = types.NetworkRule{}
		jsonBytes, err := json.Marshal(kubearmorPolicy)
		if err != nil {
			log.Error().Msg(err.Error())
			continue
		}
		yamlBytes, err := yaml.JSONToYAML(jsonBytes)
		if err != nil {
			log.Error().Msg(err.Error())
			continue
		}

		policyYaml := types.PolicyYaml{
			Type:        types.PolicyTypeSystem,
			Kind:        kubearmorPolicy.Kind,
			Name:        kubearmorPolicy.Metadata["name"],
			Namespace:   kubearmorPolicy.Metadata["namespace"],
			Cluster:     cfg.GetCfgClusterName(),
			WorkspaceId: cfg.GetCfgWorkspaceId(),
			ClusterId:   cfg.GetCfgClusterId(),
			Labels:      kubearmorPolicy.Spec.Selector.MatchLabels,
			Yaml:        yamlBytes,
		}
		res = append(res, policyYaml)

		PolicyStore.Publish(&policyYaml)
	}

	if err := libs.UpdateOrInsertPolicyYamls(CfgDB, res); err != nil {
		log.Error().Msgf(err.Error())
	}
}

func DiscoverSystemPolicyMain() {
	if SystemWorkerStatus == STATUS_RUNNING {
		return
	}

	SystemWorkerStatus = STATUS_RUNNING

	defer func() {
		SystemWorkerStatus = STATUS_IDLE
	}()

	InitSysPolicyDiscoveryConfiguration()

	// get system logs
	allSystemkLogs := getSystemLogs()
	if allSystemkLogs == nil {
		return
	}

	PopulateSystemPoliciesFromSystemLogs(allSystemkLogs)
}

// ==================================== //
// == System Policy Discovery Worker == //
// ==================================== //

func StartSystemLogRcvr() {
	for {
		if cfg.GetCfgSystemLogFrom() == "kubearmor" {
			err := plugin.StartKubeArmorRelay(SystemStopChan, cfg.GetCfgKubeArmor())
			if val, ok := <-err; ok && val != nil {
				url := cluster.GetKubearmorRelayURL()
				kubearmorRelayURL.KubeArmorRelayURL = url
				kubearmorRelayURL.KubeArmorRelayPort = "32767"
				_ = plugin.StartKubeArmorRelay(SystemStopChan, kubearmorRelayURL)
			}
		} else if cfg.GetCfgSystemLogFrom() == "feed-consumer" {
			fc.ConsumerMutex.Lock()
			fc.StartConsumer()
			fc.ConsumerMutex.Unlock()
		}
		time.Sleep(time.Second * 2)
	}
}

func StartSystemCronJob() {
	go StartSystemLogRcvr()

	// init cron job
	SystemCronJob = cron.New()
	err := SystemCronJob.AddFunc(cfg.GetCfgSysCronJobTime(), DiscoverSystemPolicyMain) // time interval
	if err != nil {
		log.Error().Msg(err.Error())
		return
	}
	SystemCronJob.Start()

	log.Info().Msg("Auto system policy discovery cron job started")
}

func StopSystemCronJob() {
	if SystemCronJob != nil {
		log.Info().Msg("Got a signal to terminate the auto system policy discovery")

		close(SystemStopChan)

		SystemCronJob.Stop() // Stop the scheduler (does not stop any jobs already running).

		SystemCronJob = nil
	}
}

func StartSystemWorker() {
	if SystemWorkerStatus != STATUS_IDLE {
		log.Info().Msg("There is no idle system policy discovery worker")

		return
	}

	if cfg.GetCfgSysOperationMode() == OP_MODE_NOOP { // Do not run the operation
		log.Info().Msg("system operation mode is NOOP ... NO SYSTEM POLICY DISCOVERY")
	} else if cfg.GetCfgSysOperationMode() == OP_MODE_CRONJOB { // every time intervals
		StartSystemCronJob()
	} else { // one-time generation
		DiscoverSystemPolicyMain()
		log.Info().Msgf("Auto system policy discovery onetime job done")
	}
}

func StopSystemWorker() {
	if cfg.GetCfgSysOperationMode() == OP_MODE_CRONJOB { // every time intervals
		StopSystemCronJob()
	} else {
		if SystemWorkerStatus != STATUS_RUNNING {
			log.Info().Msg("There is no running system policy discovery worker")
			return
		}
	}
}
