package systempolicy

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"os"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/accuknox/auto-policy-discovery/src/cluster"
	cfg "github.com/accuknox/auto-policy-discovery/src/config"
	"github.com/accuknox/auto-policy-discovery/src/feedconsumer"
	"github.com/accuknox/auto-policy-discovery/src/libs"
	logger "github.com/accuknox/auto-policy-discovery/src/logging"
	"github.com/accuknox/auto-policy-discovery/src/plugin"
	types "github.com/accuknox/auto-policy-discovery/src/types"
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

	SYS_OP_PROCESS_INT = 1
	SYS_OP_FILE_INT    = 2

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

// SysPath Structure
type SysPath struct {
	Path  string
	isDir bool
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

	return systemLogs
}

func WriteSystemPoliciesToFile_Ext() {
	var wpfs types.WorkloadProcessFileSet
	res, policyNames, err := libs.GetWorkloadProcessFileSet(CfgDB, wpfs)
	if err != nil {
		log.Error().Msgf("cudnot fetch WPFS err=%s", err.Error())
		return
	}
	log.Info().Msgf("found %d WPFS records", len(res))
	sysPols := ConvertWPFSToKnoxSysPolicy(res, policyNames)

	kubeArmorPolicies := plugin.ConvertKnoxSystemPolicyToKubeArmorPolicy(sysPols)
	//	kubeArmorPolicies := plugin.ConvertWPFSToKubeArmorPolicy(res, policyNames)
	libs.WriteKubeArmorPolicyToYamlFile("kubearmor_policies_ext", "", kubeArmorPolicies)
}

func WriteSystemPoliciesToFile(namespace string) {
	latestPolicies := libs.GetSystemPolicies(CfgDB, namespace, "latest")
	if len(latestPolicies) > 0 {
		kubeArmorPolicies := plugin.ConvertKnoxSystemPolicyToKubeArmorPolicy(latestPolicies)
		libs.WriteKubeArmorPolicyToYamlFile("kubearmor_policies", "", kubeArmorPolicies)
	}
	WriteSystemPoliciesToFile_Ext()
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
		aggregatedFilePaths := AggregatePaths(filePaths)

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
		aggregatedProcessPaths := AggregatePaths(processPaths)

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

func ConvertWPFSToKnoxSysPolicy(wpfsSet map[types.WorkloadProcessFileSet][]string, policyNames []string) []types.KnoxSystemPolicy {
	if len(wpfsSet) != len(policyNames) {
		log.Error().Msgf("len(wpfsSet):%d != len(policyNames):%d", len(wpfsSet), len(policyNames))
		return nil
	}
	var results []types.KnoxSystemPolicy
	idx := 0
	for wpfs, fsset := range wpfsSet {

		policy := buildSystemPolicy()
		policy.Metadata["type"] = wpfs.SetType
		policy.Spec.File = types.KnoxSys{}

		for _, fpath := range fsset {
			path := SysPath{
				Path:  fpath,
				isDir: false,
			}
			policy = updateSysPolicySpec(wpfs.SetType, policy, wpfs.FromSource, path)
		}

		policy.Metadata["clusterName"] = wpfs.ClusterName
		policy.Metadata["namespace"] = wpfs.Namespace
		policy.Metadata["name"] = policyNames[idx]

		labels := strings.Split(wpfs.Labels, ",")
		for _, label := range labels {
			k := strings.Split(label, "=")[0]
			v := strings.Split(label, "=")[1]
			policy.Spec.Selector.MatchLabels[k] = v
		}

		results = append(results, policy)
		idx++
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

	for clusterName, sysLogs := range clusteredLogs {
		// get existing system policies in db
		existingPolicies := libs.GetSystemPolicies(CfgDB, "", "")
		log.Info().Msgf("System policy discovery started for cluster [%s] len(existingPolicies):%d len(sysLogs):%d",
			clusterName, len(existingPolicies), len(sysLogs))

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

			filePolCnt := 0
			// 1. discover file operation system policy
			if SystemPolicyTypes&SYS_OP_FILE_INT > 0 {
				fileOpLogs := getOperationLogs(SYS_OP_FILE, perPodlogs)
				GenFileSetForAllPodsInCluster(clusterName, pods, SYS_OP_FILE, fileOpLogs)
				if !cfg.CurrentCfg.ConfigSysPolicy.DeprecateOldMode {
					discoveredSysPolicies = discoverFileOperationPolicy(discoveredSysPolicies, pod, fileOpLogs)
					filePolCnt = len(discoveredSysPolicies)
					log.Info().Msgf("discovered %d file policies from %d file logs in the current batch",
						len(discoveredSysPolicies), len(fileOpLogs))
				}
			}

			// 2. discover process operation system policy
			if SystemPolicyTypes&SYS_OP_PROCESS_INT > 0 {
				procOpLogs := getOperationLogs(SYS_OP_PROCESS, perPodlogs)
				GenFileSetForAllPodsInCluster(clusterName, pods, SYS_OP_PROCESS, procOpLogs)
				if !cfg.CurrentCfg.ConfigSysPolicy.DeprecateOldMode {
					discoveredSysPolicies = discoverProcessOperationPolicy(discoveredSysPolicies, pod, procOpLogs)
					log.Info().Msgf("discovered %d process policies from %d process logs in the current batch",
						len(discoveredSysPolicies)-filePolCnt, len(procOpLogs))
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
				WriteSystemPoliciesToFile(sysKey.Namespace)
			}
		}
	}

	return discoveredSystemPolicies
}

func stringInSlice(needle string, hay []string) bool {
	for _, b := range hay {
		if b == needle {
			return true
		}
	}
	return false
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
	for letter, _ := range check {
		res = append(res, letter)
	}
	sort.Strings(res)
	return res
}

// cleanResource : Certain linux files keep changing always and needs to refed
// just once. Examples are /proc, /sys.
func cleanResource(str string) string {
	if strings.HasPrefix(str, "/proc") {
		return "/proc"
	}
	if strings.HasPrefix(str, "/sys") {
		return "/sys"
	}
	return str
}

// GenFileSetForAllPodsInCluster Generate process specific fileset across all pods in a cluster
func GenFileSetForAllPodsInCluster(clusterName string, pods []types.Pod, settype string, slogs []types.KnoxSystemLog) map[types.WorkloadProcessFileSet][]string {
	res := map[types.WorkloadProcessFileSet][]string{} // key: WorkloadProcess - val: Accesss File Set
	wpfs := types.WorkloadProcessFileSet{}
	for _, slog := range slogs {
		wpfs.ClusterName = slog.ClusterName
		wpfs.ContainerName = slog.ContainerName
		wpfs.Namespace = slog.Namespace
		wpfs.FromSource = slog.Source
		wpfs.SetType = settype
		labels, err := GetPodLabels(slog.ClusterName, slog.PodName, slog.Namespace, pods)
		if err != nil {
			log.Error().Msgf("cudnot get pod labels for podname=%s ns=%s", slog.PodName, slog.Namespace)
			continue
		}
		wpfs.Labels = strings.Join(labels[:], ",")

		resource := cleanResource(slog.Resource)

		if !stringInSlice(resource, res[wpfs]) {
			res[wpfs] = append(res[wpfs], resource)
		}
	}

	for wpfs, fs := range res {
		out, _, err := libs.GetWorkloadProcessFileSet(CfgDB, wpfs)
		if err != nil {
			log.Error().Msgf("failed processing wpfs=%+v err=%s", wpfs, err.Error())
			continue
		}
		dbfs := out[wpfs]
		if len(dbfs) == 0 {
			wpfs.CreatedTime = uint(time.Now().Unix())
			wpfs.UpdatedTIme = uint(time.Now().Unix())
			sort.Strings(fs)
			log.Info().Msgf("adding wpfs db entry for wpfs=%+v", wpfs)
			err = libs.InsertWorkloadProcessFileSet(CfgDB, wpfs, fs)
		} else {
			// Update file set
			mergedfs := mergeStringSlices(fs, dbfs)
			// mergedfs = mergeFileIntoDirs(mergedfs)
			// mergedfs = AggregatePaths(mergedfs)
			sort.Strings(mergedfs)
			if !reflect.DeepEqual(mergedfs, dbfs) {
				wpfs.UpdatedTIme = uint(time.Now().Unix())
				log.Info().Msgf("updating wpfs db entry for wpfs=%+v", wpfs)
				// log.Info().Msgf("\nmergedfs=%+v\ndbfs=%+v", mergedfs, dbfs)
				err = libs.UpdateWorkloadProcessFileSetMySQL(CfgDB, wpfs, mergedfs)
			}
		}
		if err != nil {
			log.Error().Msgf("failure add/updt db entry for wpfs=%+v err=%s", wpfs, err.Error())
		}
	}
	return res
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
			plugin.StartKubeArmorRelay(SystemStopChan, cfg.GetCfgKubeArmor())
		} else if cfg.GetCfgSystemLogFrom() == "kafka" {
			feedconsumer.StartConsumer()
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
