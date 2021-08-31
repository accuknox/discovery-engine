package systempolicy

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"os"
	"strings"
	"sync"

	"github.com/accuknox/knoxAutoPolicy/src/cluster"
	cfg "github.com/accuknox/knoxAutoPolicy/src/config"
	"github.com/accuknox/knoxAutoPolicy/src/feedconsumer"
	"github.com/accuknox/knoxAutoPolicy/src/libs"
	logger "github.com/accuknox/knoxAutoPolicy/src/logging"
	"github.com/accuknox/knoxAutoPolicy/src/plugin"
	types "github.com/accuknox/knoxAutoPolicy/src/types"
	"github.com/rs/zerolog"

	"github.com/robfig/cron"
)

var log *zerolog.Logger

func init() {
	log = logger.GetInstance()
}

// const values
const (
	// operation mode
	OP_MODE_CRONJOB = 1
	OP_MODE_ONETIME = 2

	// status
	STATUS_RUNNING = "running"
	STATUS_IDLE    = "idle"
)

const (
	SYS_OP_PROCESS = "Process"
	SYS_OP_FILE    = "File"

	SYS_OP_PROCESS_INT = 1
	SYS_OP_FILE_INT    = 2

	SOURCE_ALL = "/ALL" // for fromSource 'off'
)

// ====================== //
// == Gloabl Variables == //
// ====================== //

var CfgDB types.ConfigDB

// SystemWorkerStatus global worker
var SystemWorkerStatus string

// for cron job
var SystemCronJob *cron.Cron
var SystemWaitG sync.WaitGroup
var SystemStopChan chan struct{} // for hubble
var OperationTrigger int

var OneTimeJobTime string

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
	SystemWaitG = sync.WaitGroup{}
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

// SysPath Structure
type SysPath struct {
	Path  string
	isDir bool
}

// ================ //
// == System Log == //
// ================ //

func getSystemLogs() []types.KnoxSystemLog {
	systemLogs := []types.KnoxSystemLog{}

	if SystemLogFrom == "db" {
		// ============== //
		// == Database == //
		// ============== //
		log.Info().Msg("Get system log from the database")

		// get system logs from db
		sysLogs := libs.GetSystemLogsFromDB(cfg.GetCfgDB(), cfg.GetCfgSysOneTime(), OperationTrigger, SystemLogLimit)
		if len(sysLogs) == 0 {
			return nil
		}

		// get system alerts from db, and merge it to the system logs
		sysAlerts := libs.GetSystemAlertsFromDB(cfg.GetCfgDB(), cfg.GetCfgSysOneTime(), OperationTrigger, SystemLogLimit)
		if len(sysAlerts) != 0 {
			sysLogs = append(sysLogs, sysAlerts...)
		}

		// convert kubearmor system logs -> knox system logs
		systemLogs = plugin.ConvertKubeArmorSystemLogsToKnoxSystemLogs(cfg.GetCfgDB().DBDriver, sysLogs)
	} else if SystemLogFrom == "file" {
		// =============================== //
		// == File (.json) for testing  == //
		// =============================== //

		jsonLogs := []map[string]interface{}{}
		log.Info().Msg("Get system logs from the json file : " + SystemLogFile)

		// Opens jsonFile
		logFile, err := os.Open(SystemLogFile)
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
		systemLogs = plugin.ConvertMySQLKubeArmorLogsToKnoxSystemLogs(jsonLogs)

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
			log := plugin.ConvertKubeArmorLogToKnoxSystemLog(relayLog)
			systemLogs = append(systemLogs, log)
		}
	} else if SystemLogFrom == "kafka" {
		log.Info().Msg("Get system log from kafka consumer")

		// get system logs from kafka consumer
		sysLogs := plugin.GetSystemLogsFromKafkaConsumer(OperationTrigger)
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
	print(systemLogs)

	return systemLogs
}

func WriteSystemPoliciesToFile(namespace string) {
	latestPolicies := libs.GetSystemPolicies(CfgDB, namespace, "latest")

	kubeArmorPolicies := plugin.ConvertKnoxSystemPolicyToKubeArmorPolicy(latestPolicies)

	libs.WriteKubeArmorPolicyToYamlFile("", kubeArmorPolicies)
}

// ============================= //
// == Discover System Policy  == //
// ============================= //

func clusteringSystemLogsByCluster(logs []types.KnoxSystemLog) map[string][]types.KnoxSystemLog {
	results := map[string][]types.KnoxSystemLog{} // key: cluster name - val: system logs

	for _, log := range logs {
		if _, ok := results[log.ClusterName]; ok {
			results[log.ClusterName] = append(results[log.ClusterName], log)
		} else {
			results[log.ClusterName] = []types.KnoxSystemLog{log}
		}
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

		if _, ok := results[key]; ok {
			results[key] = append(results[key], log)
		} else {
			results[key] = []types.KnoxSystemLog{log}
		}
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
		aggreatedFilePaths := AggregatePaths(filePaths)

		// step 4: append spec to the policy
		for _, filePath := range aggreatedFilePaths {
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
		aggreatedProcessPaths := AggregatePaths(processPaths)

		// step 4: append spec to the policy
		for _, processPath := range aggreatedProcessPaths {
			appended = true
			policy = updateSysPolicySpec(SYS_OP_PROCESS, policy, src, processPath)
		}
	}

	if appended {
		results = append(results, policy)
	}

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

func updateSysPolicySpec(opType string, policy types.KnoxSystemPolicy, src string, pathSpec SysPath) types.KnoxSystemPolicy {
	// matchDirectories
	if pathSpec.isDir {
		matchDirs := types.KnoxMatchDirectories{
			Dir: pathSpec.Path + "/",
		}

		if opType == SYS_OP_FILE {
			if FileFromSource {
				matchDirs.FromSource = []types.KnoxFromSource{
					types.KnoxFromSource{
						Path: src,
					},
				}
				policy.Metadata["fromSource"] = src
			}

			if len(policy.Spec.File.MatchDirectories) == 0 {
				policy.Spec.File.MatchDirectories = []types.KnoxMatchDirectories{matchDirs}
			} else {
				policy.Spec.File.MatchDirectories = append(policy.Spec.File.MatchDirectories, matchDirs)
			}
		} else if opType == SYS_OP_PROCESS {
			if ProcessFromSource {
				matchDirs.FromSource = []types.KnoxFromSource{
					types.KnoxFromSource{
						Path: src,
					},
				}
				policy.Metadata["fromSource"] = src
			}

			if len(policy.Spec.File.MatchDirectories) == 0 {
				policy.Spec.Process.MatchDirectories = []types.KnoxMatchDirectories{matchDirs}
			} else {
				policy.Spec.Process.MatchDirectories = append(policy.Spec.Process.MatchDirectories, matchDirs)
			}
		}
	} else {
		// matchPaths
		matchPaths := types.KnoxMatchPaths{
			Path: pathSpec.Path,
		}

		if opType == SYS_OP_FILE {
			if FileFromSource {
				matchPaths.FromSource = []types.KnoxFromSource{
					types.KnoxFromSource{
						Path: src,
					},
				}
				policy.Metadata["fromSource"] = src
			}

			if len(policy.Spec.File.MatchPaths) == 0 {
				policy.Spec.File.MatchPaths = []types.KnoxMatchPaths{matchPaths}
			} else {
				policy.Spec.File.MatchPaths = append(policy.Spec.File.MatchPaths, matchPaths)
			}
		} else if opType == SYS_OP_PROCESS {
			if ProcessFromSource {
				matchPaths.FromSource = []types.KnoxFromSource{
					types.KnoxFromSource{
						Path: src,
					},
				}
				policy.Metadata["fromSource"] = src
			}

			if len(policy.Spec.File.MatchPaths) == 0 {
				policy.Spec.Process.MatchPaths = []types.KnoxMatchPaths{matchPaths}
			} else {
				policy.Spec.Process.MatchPaths = append(policy.Spec.Process.MatchPaths, matchPaths)
			}
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

// ============================= //
// == Discover System Policy  == //
// ============================= //

func InitSysPolicyDiscoveryConfiguration() {
	CfgDB = cfg.GetCfgDB()

	OneTimeJobTime = cfg.GetCfgSysOneTime()

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

func DiscoverSystemPolicyMain() {
	if SystemWorkerStatus == STATUS_RUNNING {
		return
	} else {
		SystemWorkerStatus = STATUS_RUNNING
	}

	defer func() {
		SystemWorkerStatus = STATUS_IDLE
	}()

	InitSysPolicyDiscoveryConfiguration()

	// get system logs
	allSystemkLogs := getSystemLogs()
	if allSystemkLogs == nil {
		return
	}

	// delete duplicate logs
	allSystemkLogs = systemLogDeduplication(allSystemkLogs)

	// get cluster names, iterate each cluster
	clusteredLogs := clusteringSystemLogsByCluster(allSystemkLogs)

	for clusterName, sysLogs := range clusteredLogs {
		log.Info().Msgf("System policy discovery started for cluster [%s]", clusterName)

		// get existing system policies in db
		existingPolicies := libs.GetSystemPolicies(CfgDB, "", "")

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

			// 1. discover file operation system policy
			if SystemPolicyTypes&SYS_OP_FILE_INT > 0 {
				fileOpLogs := getOperationLogs(SYS_OP_FILE, perPodlogs)
				discoveredSysPolicies = discoverFileOperationPolicy(discoveredSysPolicies, pod, fileOpLogs)
			}

			// 2. discover process operation system policy
			if SystemPolicyTypes&SYS_OP_PROCESS_INT > 0 {
				procOpLogs := getOperationLogs(SYS_OP_PROCESS, perPodlogs)
				discoveredSysPolicies = discoverProcessOperationPolicy(discoveredSysPolicies, pod, procOpLogs)
			}

			// 3. update selector
			discoveredSysPolicies = updateSysPolicySelector(clusterName, pod, discoveredSysPolicies)

			// 4. update duplicated policy
			newPolicies := UpdateDuplicatedPolicy(existingPolicies, discoveredSysPolicies, clusterName)

			if len(newPolicies) > 0 {
				// insert discovered policies to db
				if strings.Contains(SystemPolicyTo, "db") {
					libs.InsertSystemPolicies(CfgDB, newPolicies)
				}

				log.Info().Msgf("-> System policy discovery done for cluster/namespace/pod: [%s/%s/%s], [%d] policies discovered", clusterName, pod.Namespace, pod.PodName, len(newPolicies))
			}

			if strings.Contains(SystemPolicyTo, "file") {
				WriteSystemPoliciesToFile(sysKey.Namespace)
			}
		}
	}
}

// ==================================== //
// == System Policy Discovery Worker == //
// ==================================== //

func StartSystemCronJob() {
	//if system log directly from kubearmor relay
	if cfg.GetCfgSystemLogFrom() == "kubearmor" {
		go plugin.StartKubeArmorRelay(SystemStopChan, &SystemWaitG, cfg.GetCfgKubeArmor())
		SystemWaitG.Add(1)
	} else if cfg.GetCfgSystemLogFrom() == "kafka" {
		go feedconsumer.StartConsumer()
	}

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
		SystemWaitG.Wait()

		SystemCronJob.Stop() // Stop the scheduler (does not stop any jobs already running).

		SystemCronJob = nil
	}
}

func StartSystemWorker() {
	if SystemWorkerStatus != STATUS_IDLE {
		log.Info().Msg("There is no idle system policy discovery worker")

		return
	}

	if cfg.GetCfgSysOperationMode() == OP_MODE_CRONJOB { // every time intervals
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
