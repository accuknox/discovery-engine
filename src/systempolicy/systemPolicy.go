package systempolicy

import (
	"errors"
	"sort"
	"strings"
	"sync"

	cfg "github.com/accuknox/knoxAutoPolicy/src/config"
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
	SYS_OP_NETWORK = "Network"
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

var OneTimeJobTime string

var SystemLogFrom string
var SystemLogFile string
var SystemPolicyTo string

// init Function
func init() {
	SystemWorkerStatus = STATUS_IDLE
	SystemStopChan = make(chan struct{})
	SystemWaitG = sync.WaitGroup{}
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

// getSystemLogs function
func getSystemLogs() []types.KnoxSystemLog {
	systemLogs := []types.KnoxSystemLog{}

	// =============== //
	// == Database  == //
	// =============== //
	if cfg.GetCfgSystemLogFrom() == "db" {
		log.Info().Msg("Get system log from the database")

		// get system logs from db
		sysLogs := libs.GetSystemLogsFromDB(cfg.GetCfgDB(), cfg.GetCfgOneTime())
		if len(sysLogs) == 0 {
			return nil
		}

		// convert kubearmor system logs -> knox system logs
		systemLogs = plugin.ConvertKubeArmorSystemLogsToKnoxSystemLogs(cfg.GetCfgDB().DBDriver, sysLogs)
	} else {
		log.Error().Msgf("System log from not correct: %s", cfg.GetCfgSystemLogFrom())
		return nil
	}

	return systemLogs
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
		if !libs.ContainsElement(results, log) {
			results = append(results, log)
		}
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

func discoverFileOperationPolicy(results []types.KubeArmorSystemPolicy, pod types.Pod, logs []types.KnoxSystemLog) []types.KubeArmorSystemPolicy {
	// step 1: [system logs] -> {source: []destination(resource)}
	srcToDest := map[string][]string{}
	for _, log := range logs {
		if val, ok := srcToDest[log.Source]; ok {
			if !libs.ContainsElement(val, log.Resource) {
				srcToDest[log.Source] = append(srcToDest[log.Source], log.Resource)
			}
		} else {
			srcToDest[log.Source] = []string{log.Resource}
		}
	}

	// step 2: aggregate file paths
	for src, filePaths := range srcToDest {
		// if the source is not in the absolute path, skip it
		if !strings.Contains(src, "/") {
			continue
		}

		aggreatedFilePaths := AggregatePaths(filePaths)

		// step 3: build system policies
		policy := buildSystemPolicy()
		policy.Metadata["type"] = "file"
		policy.Spec.File = types.KubeArmorSys{}
		for _, filePath := range aggreatedFilePaths {
			policy = updateSysPolicySpec(policy, src, filePath)
		}

		results = append(results, policy)

	}

	return results
}

func discoverProcessOperationPolicy(results []types.KubeArmorSystemPolicy, pod types.Pod, logs []types.KnoxSystemLog) []types.KubeArmorSystemPolicy {
	// step 1: [system logs] -> {source: []destination(resource)}
	srcToDest := map[string][]string{}
	for _, log := range logs {
		if val, ok := srcToDest[log.Source]; ok {
			if !libs.ContainsElement(val, log.Resource) {
				srcToDest[log.Source] = append(srcToDest[log.Source], log.Resource)
			}
		} else {
			srcToDest[log.Source] = []string{log.Resource}
		}
	}

	// step 2: aggregate process paths
	for src, processPaths := range srcToDest {
		// if the source is not in the absolute path, skip it
		if !strings.Contains(src, "/") {
			continue
		}

		aggreatedProcessPaths := AggregatePaths(processPaths)

		// step 3: build system policies
		policy := buildSystemPolicy()
		policy.Metadata["type"] = "process"
		policy.Spec.Process = types.KubeArmorSys{}
		for _, processPath := range aggreatedProcessPaths {
			policy = updateSysPolicySpec(policy, src, processPath)
		}

		results = append(results, policy)

	}

	return results
}

func getPodInstance(key SysLogKey, pods []types.Pod) (types.Pod, error) {
	for _, pod := range pods {
		// for test //
		if strings.Contains(pod.PodName, "ubuntu-1") {
			return pod, nil
		}

		if key.Namespace == pod.Namespace && key.PodName == pod.PodName {
			return pod, nil
		}
	}

	return types.Pod{}, errors.New("Not exist: " + key.Namespace + " " + key.PodName)
}

// ============================ //
// == Building System Policy == //
// ============================ //

func buildSystemPolicy() types.KubeArmorSystemPolicy {
	return types.KubeArmorSystemPolicy{
		APIVersion: "security.accuknox.com/v1",
		Kind:       "KubeArmorPolicy",
		Metadata:   map[string]string{},
		Spec: types.KubeArmorSpec{
			Severity: 1, // by default
			Selector: types.Selector{
				MatchLabels: map[string]string{}},
			Action: "Allow",
		},
	}
}

func updateSysPolicySpec(policy types.KubeArmorSystemPolicy, src string, pathSpec SysPath) types.KubeArmorSystemPolicy {
	if pathSpec.isDir {
		matchDirs := types.KubeArmorMatchDirectories{
			Dir: pathSpec.Path,
			FromSource: types.KubeArmorFromSource{
				Path: []string{src},
			},
		}

		if len(policy.Spec.File.MatchDirectories) == 0 {
			policy.Spec.File.MatchDirectories = []types.KubeArmorMatchDirectories{matchDirs}
		} else {
			policy.Spec.File.MatchDirectories = append(policy.Spec.File.MatchDirectories, matchDirs)
		}
	} else {
		matchPaths := types.KubeArmorMatchPaths{
			Path: pathSpec.Path,
			FromSource: types.KubeArmorFromSource{
				Path: []string{src},
			},
		}

		if len(policy.Spec.File.MatchPaths) == 0 {
			policy.Spec.File.MatchPaths = []types.KubeArmorMatchPaths{matchPaths}
		} else {
			policy.Spec.File.MatchPaths = append(policy.Spec.File.MatchPaths, matchPaths)
		}
	}

	return policy
}

func updateSysPolicySelector(clusterName string, pod types.Pod, policies []types.KubeArmorSystemPolicy) []types.KubeArmorSystemPolicy {
	results := []types.KubeArmorSystemPolicy{}

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

func initNetPolicyDiscoveryConfiguration() {
	CfgDB = cfg.GetCfgDB()

	OneTimeJobTime = cfg.GetCfgOneTime()

	SystemLogFrom = cfg.GetCfgSystemLogFrom()
	SystemLogFile = cfg.GetCfgSystemLogFile()
	SystemPolicyTo = cfg.GetCfgSystemPolicyTo()
}

// DiscoverSystemPolicyMain function
func DiscoverSystemPolicyMain() {
	if SystemWorkerStatus == STATUS_RUNNING {
		return
	} else {
		SystemWorkerStatus = STATUS_RUNNING
	}

	defer func() {
		SystemWorkerStatus = STATUS_IDLE
	}()

	initNetPolicyDiscoveryConfiguration()

	// get system logs
	allSystemkLogs := getSystemLogs()
	if allSystemkLogs == nil {
		return
	}

	// delete duplicate logs
	allSystemkLogs = systemLogDeduplication(allSystemkLogs)

	// get cluster names, iterate each cluster
	clusteredLogs := clusteringSystemLogsByCluster(allSystemkLogs)

	discoveredSysPolicies := []types.KubeArmorSystemPolicy{}

	for clusterName, sysLogs := range clusteredLogs {
		clusterName = "accuknox-qa" // for test

		clusterInstance := libs.GetClusterFromClusterName(clusterName)
		if clusterInstance.ClusterID == 0 { // cluster not onboarded
			continue
		}

		// get existing system policies in db
		existingPolicies := libs.GetSystemPolicies(CfgDB, "", "")

		// get k8s pods
		pods := libs.GetPodsFromCluster(clusterInstance)

		// iterate namespace + pod_name
		nsPodLogs := clusteringSystemLogsByNamespacePod(sysLogs)
		for sysKey, perPodlogs := range nsPodLogs {
			pod, err := getPodInstance(sysKey, pods)
			if err != nil {
				log.Error().Msg(err.Error())
				continue
			}

			// 1. discover file operation system policy
			fileOpLogs := getOperationLogs(SYS_OP_FILE, perPodlogs)
			discoveredSysPolicies = discoverFileOperationPolicy(discoveredSysPolicies, pod, fileOpLogs)

			// 2. discover process operation system policy
			procOpLogs := getOperationLogs(SYS_OP_PROCESS, perPodlogs)
			discoveredSysPolicies = discoverProcessOperationPolicy(discoveredSysPolicies, pod, procOpLogs)

			// 3. update selector
			discoveredSysPolicies = updateSysPolicySelector(clusterName, pod, discoveredSysPolicies)
		}

		// update duplicated policy
		newPolicies := UpdateDuplicatedPolicy(existingPolicies, discoveredSysPolicies, clusterName)
		sort.Slice(newPolicies, func(i, j int) bool {
			return newPolicies[i].Metadata["name"] < newPolicies[j].Metadata["name"]
		})

		if len(newPolicies) > 0 {
			// insert discovered policies to db
			if strings.Contains(SystemPolicyTo, "db") {
				libs.InsertSystemPolicies(CfgDB, newPolicies)
			}
		}

		log.Info().Msgf("Network policy discovery done for cluster: [%s], [%d] policies discovered", clusterName, len(newPolicies))
	}

	libs.WriteKubeArmorPolicyToYamlFile("multiubuntu", discoveredSysPolicies)
}

// ==================================== //
// == System Policy Discovery Worker == //
// ==================================== //

// StartSystemCronJob function
func StartSystemCronJob() {
	// init cron job
	SystemCronJob = cron.New()
	err := SystemCronJob.AddFunc(cfg.GetCfgCronJobTime(), DiscoverSystemPolicyMain) // time interval
	if err != nil {
		log.Error().Msg(err.Error())
		return
	}
	SystemCronJob.Start()

	log.Info().Msg("Auto system policy discovery cron job started")
}

// StopSystemCronJob function
func StopSystemCronJob() {
	if SystemCronJob != nil {
		log.Info().Msg("Got a signal to terminate the auto system policy discovery")

		close(SystemStopChan)
		SystemWaitG.Wait()

		SystemCronJob.Stop() // Stop the scheduler (does not stop any jobs already running).

		SystemCronJob = nil
	}
}

// StartSystemWorker function
func StartSystemWorker() {
	if SystemWorkerStatus != STATUS_IDLE {
		log.Info().Msg("There is no idle system policy discovery worker")
		return
	}

	if cfg.GetCfgOperationMode() == OP_MODE_CRONJOB { // every time intervals
		StartSystemCronJob()
	} else { // one-time generation
		DiscoverSystemPolicyMain()
		log.Info().Msgf("Auto system policy discovery onetime job done")
	}
}

// StopSystemWorker function
func StopSystemWorker() {
	if cfg.GetCfgOperationMode() == OP_MODE_CRONJOB { // every time intervals
		StopSystemCronJob()
	} else {
		if SystemWorkerStatus != STATUS_RUNNING {
			log.Info().Msg("There is no running system policy discovery worker")
			return
		}
	}
}
