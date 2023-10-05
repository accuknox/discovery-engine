package crownjewel

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/accuknox/auto-policy-discovery/src/cluster"
	"github.com/accuknox/auto-policy-discovery/src/common"
	"github.com/accuknox/auto-policy-discovery/src/config"
	cfg "github.com/accuknox/auto-policy-discovery/src/config"
	"github.com/accuknox/auto-policy-discovery/src/libs"
	logger "github.com/accuknox/auto-policy-discovery/src/logging"
	obs "github.com/accuknox/auto-policy-discovery/src/observability"
	opb "github.com/accuknox/auto-policy-discovery/src/protobuf/v1/observability"
	"github.com/accuknox/auto-policy-discovery/src/systempolicy"
	"github.com/accuknox/auto-policy-discovery/src/types"
	"github.com/robfig/cron"
	"github.com/rs/zerolog"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

var log *zerolog.Logger

// CrownjewelCronJob for cron job
var CrownjewelCronJob *cron.Cron

var CrownjewelStopChan chan struct{}

// CrownjewelWorkerStatus global worker
var CrownjewelWorkerStatus string

// const values
const (
	// operation mode
	opModeNoop    = 0
	opModeCronjob = 1

	// status
	statusRunning = "running"
	statusIdle    = "idle"
)

// init Function
func init() {
	log = logger.GetInstance()
	CrownjewelWorkerStatus = statusIdle
	CrownjewelStopChan = make(chan struct{})
}

// StartCrownjewelWorker starts the crown jewel worker (run once or as a cronjob)
func StartCrownjewelWorker() {
	if CrownjewelWorkerStatus != statusIdle {
		log.Info().Msg("There is no idle Crown jewel policy worker")
		return
	}
	if cfg.GetCfgCrownjewelOperationMode() == opModeNoop { // Do not run the operation
		log.Info().Msg("Crown jewel operation mode is NOOP... ")
	} else if cfg.GetCfgCrownjewelOperationMode() == opModeCronjob { // every time intervals
		log.Info().Msg("Crown jewel policy cron job started")
		CrownjewelPolicyMain()
		StartCrownjewelCronJob()
	} else { // one-time generation
		CrownjewelPolicyMain()
		log.Info().Msgf("Crown jewel policy onetime job done")
	}
}

// StartCrownjewelCronJob starts the cronjob
func StartCrownjewelCronJob() {
	// init cron job
	CrownjewelCronJob = cron.New()
	err := CrownjewelCronJob.AddFunc(cfg.GetCfgCrownjewelCronJobTime(), CrownjewelPolicyMain)
	if err != nil {
		log.Error().Msg(err.Error())
		return
	}
	CrownjewelCronJob.Start()
}

// StopCrownjewelCronJob stops the cronjob
func StopCrownjewelCronJob() {
	if CrownjewelCronJob != nil {
		log.Info().Msg("Got a signal to terminate the auto system policy discovery")

		CrownjewelStopChan = make(chan struct{})

		close(CrownjewelStopChan)

		CrownjewelCronJob.Stop() // Stop the scheduler (does not stop any jobs already running).

		CrownjewelCronJob = nil
	}
}

// Create Crown Jewel Policy based on K8s object type
func CrownjewelPolicyMain() {
	deployment := cluster.GetDeploymentsFromK8sClient()
	client := cluster.ConnectK8sClient()

	for _, d := range deployment {
		err := getFilteredPolicy(client, d.Name, d.Namespace, d.Labels)
		if err != nil {
			log.Error().Msg("Error getting mount paths, err=" + err.Error())
		}
	}
}

type LabelMap = map[string]string

// Get list of running processes from observability data
func getProcessList(client kubernetes.Interface, namespace string, labels string) ([]string, error) {
	var processList []string
	duplicatePaths := make(map[string]bool)

	podList, err := client.CoreV1().Pods("").List(context.Background(), metav1.ListOptions{
		LabelSelector: labels,
	})
	if err != nil {
		log.Warn().Msg(err.Error())
	}
	for _, pod := range podList.Items {
		for _, container := range pod.Spec.Containers {
			sumResp, err := obs.GetSummaryData(&opb.Request{
				PodName:       pod.Name,
				NameSpace:     pod.Namespace,
				ContainerName: container.Name,
				Type:          "process,file,network",
			})
			if err != nil {
				log.Warn().Msgf("Error getting summary data for pod %s, container %s, namespace %s: %s", pod.Name, container.Name, pod.Namespace, err.Error())
				break
			}

			for _, procData := range sumResp.ProcessData {
				if !duplicatePaths[procData.Source] {
					processList = append(processList, procData.Source)
					duplicatePaths[procData.Source] = true
				}
				if !duplicatePaths[procData.Destination] {
					processList = append(processList, procData.Destination)
					duplicatePaths[procData.Destination] = true
				}
			}
			for _, fileData := range sumResp.FileData {
				if !duplicatePaths[fileData.Source] {
					processList = append(processList, fileData.Source)
					duplicatePaths[fileData.Source] = true
				}
			}
			for _, netData := range sumResp.IngressConnection {
				if !duplicatePaths[netData.Command] {
					processList = append(processList, netData.Command)
					duplicatePaths[netData.Command] = true
				}
			}
			for _, netData := range sumResp.EgressConnection {
				if !duplicatePaths[netData.Command] {
					processList = append(processList, netData.Command)
					duplicatePaths[netData.Command] = true
				}
			}
		}
	}
	return processList, nil
}

// Get all mounted paths
func getVolumeMountPaths(client kubernetes.Interface, labels string) ([]string, error) {
	podList, err := client.CoreV1().Pods("").List(context.Background(), metav1.ListOptions{
		LabelSelector: labels,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get pod list: %v", err)
	}

	var mountPaths []string

	for _, pod := range podList.Items {
		for _, container := range pod.Spec.Containers {
			for _, volumeMount := range container.VolumeMounts {
				// fmt.Printf("\n\n\n%s\n\n\n", volumeMount.MountPath)
				if volumeMount.MountPath == "/var/run/secrets/kubernetes.io/serviceaccount" {
					//
					mountPaths = append(mountPaths, "/run/secrets/kubernetes.io/serviceaccount")
					continue
				}
				mountPaths = append(mountPaths, volumeMount.MountPath)
			}
		}
	}
	return mountPaths, nil
}

// Get used mount paths from observability data
func usedPaths(client kubernetes.Interface, namespace string, labels string) ([]string, map[string]string, error) {
	var sumResponses []string
	fromSource := make(map[string]string)

	podList, err := client.CoreV1().Pods("").List(context.Background(), metav1.ListOptions{
		LabelSelector: labels,
	})
	if err != nil {
		log.Warn().Msg(err.Error())
	}

	for _, pod := range podList.Items {
		for _, container := range pod.Spec.Containers {
			sumResp, err := obs.GetSummaryData(&opb.Request{
				PodName:       pod.Name,
				NameSpace:     pod.Namespace,
				ContainerName: container.Name,
				Type:          "file",
			})
			if err != nil {
				log.Warn().Msgf("Error getting summary data for pod %s, container %s, namespace %s: %s", pod.Name, container.Name, pod.Namespace, err.Error())
				break
			}

			for _, fileData := range sumResp.FileData {
				sumResponses = append(sumResponses, fileData.Destination)
				fromSource[fileData.Destination] = fileData.Source
			}
		}
	}
	return sumResponses, fromSource, nil
}

// Get network information from observability data
func usedNetwork(client kubernetes.Interface, namespace string, labels string) ([]types.KnoxMatchProtocols, error) {
	fromSource := make(map[string][]string)

	podList, err := client.CoreV1().Pods("").List(context.Background(), metav1.ListOptions{
		LabelSelector: labels,
	})
	if err != nil {
		log.Warn().Msg(err.Error())
	}

	for _, pod := range podList.Items {
		for _, container := range pod.Spec.Containers {
			sumResp, err := obs.GetSummaryData(&opb.Request{
				PodName:       pod.Name,
				NameSpace:     pod.Namespace,
				ContainerName: container.Name,
				Type:          "network",
			})
			if err != nil {
				log.Warn().Msgf("Error getting summary data for pod %s, container %s, namespace %s: %s", pod.Name, container.Name, pod.Namespace, err.Error())
				break
			}

			for _, netData := range sumResp.IngressConnection {
				if strings.Contains(strings.ToLower(netData.Protocol), "tcp") {
					fromSource["tcp"] = append(fromSource["tcp"], netData.Command)
				}
				if strings.Contains(strings.ToLower(netData.Protocol), "udp") {
					fromSource["udp"] = append(fromSource["udp"], netData.Command)
				}
				if strings.Contains(strings.ToLower(netData.Protocol), "icmp") {
					fromSource["icmp"] = append(fromSource["icmp"], netData.Command)
				}
				if strings.Contains(strings.ToLower(netData.Protocol), "raw") {
					fromSource["raw"] = append(fromSource["raw"], netData.Command)
				}
			}
			for _, netData := range sumResp.EgressConnection {
				if strings.Contains(strings.ToLower(netData.Protocol), "tcp") {
					fromSource["tcp"] = append(fromSource["tcp"], netData.Command)
				}
				if strings.Contains(strings.ToLower(netData.Protocol), "udp") {
					fromSource["udp"] = append(fromSource["udp"], netData.Command)
				}
				if strings.Contains(strings.ToLower(netData.Protocol), "icmp") {
					fromSource["icmp"] = append(fromSource["icmp"], netData.Command)
				}
				if strings.Contains(strings.ToLower(netData.Protocol), "raw") {
					fromSource["raw"] = append(fromSource["raw"], netData.Command)
				}
			}
		}
	}

	var matchProtocols []types.KnoxMatchProtocols

	for k, v := range fromSource {
		var matchProto types.KnoxMatchProtocols
		matchProto.Protocol = k
		for _, src := range v {
			matchProto.FromSource = append(matchProto.FromSource, types.KnoxFromSource{Path: src})
		}
		matchProtocols = append(matchProtocols, matchProto)
	}
	return matchProtocols, nil
}

// Match used mounts paths with actually accessed mount paths
func accessedMountPaths(sumResp, mnt []string) ([]string, error) {
	var matchedMountPaths []string
	duplicatePaths := make(map[string]bool)

	for _, sumRespPath := range sumResp {
		for _, mntPath := range mnt {
			if strings.HasPrefix(sumRespPath, mntPath) && !duplicatePaths[mntPath] {
				matchedMountPaths = append(matchedMountPaths, mntPath)
				duplicatePaths[mntPath] = true
			}
		}
	}
	return matchedMountPaths, nil
}

// Ignore namespaces based on config
func getFilteredPolicy(client kubernetes.Interface, cname, namespace string, labels string) error {
	// filters to check the namespaces to be ignored
	nsFilter := config.CurrentCfg.ConfigSysPolicy.NsFilter
	nsNotFilter := config.CurrentCfg.ConfigSysPolicy.NsNotFilter

	var policies []types.KnoxSystemPolicy
	var err error
	if len(nsFilter) > 0 {
		for _, ns := range nsFilter {
			if strings.Contains(namespace, ns) {
				policies, err = getCrownjewelPolicy(client, cname, namespace, labels)
				if err != nil {
					log.Error().Msg("Error getting Crown jewel policy, err=" + err.Error())
				}
			}
		}
		systempolicy.UpdateSysPolicies(policies)
	} else if len(nsNotFilter) > 0 {
		for _, notns := range nsNotFilter {
			if !strings.Contains(namespace, notns) {
				policies, err = getCrownjewelPolicy(client, cname, namespace, labels)
				if err != nil {
					log.Error().Msg("Error getting Crown jewel policy, err=" + err.Error())
				}
			}
		}
		systempolicy.UpdateSysPolicies(policies)
	}
	return nil
}

// Generate crown jewel policy
func getCrownjewelPolicy(client kubernetes.Interface, cname, namespace string, labels string) ([]types.KnoxSystemPolicy, error) {
	var policies []types.KnoxSystemPolicy

	var matchedMountPaths []string
	var ms types.MatchSpec
	action := "Allow"

	// file paths being used (from observability)
	sumResp, fileFromSrc, _ := usedPaths(client, namespace, labels)

	netFromSrc, _ := usedNetwork(client, namespace, labels)

	// all mount paths being used (from k8s cluster)
	mnt, _ := getVolumeMountPaths(client, labels)

	// mount paths being used and are present in observability data (accessed mount paths)
	matchedMountPaths, _ = accessedMountPaths(sumResp, mnt)

	// process paths being used and are present in observability data
	matchedProcessPaths, _ := getProcessList(client, namespace, labels)

	policy := createCrownjewelPolicy(ms, cname, namespace, action, labels, mnt, matchedMountPaths, matchedProcessPaths, fileFromSrc, netFromSrc)
	// Check for empty policy
	if policy.Spec.File.MatchDirectories == nil && policy.Spec.File.MatchPaths == nil &&
		policy.Spec.Process.MatchDirectories == nil && policy.Spec.Process.MatchPaths == nil {
		return nil, nil
	}
	policies = append(policies, policy)

	return policies, nil
}

// Build Crown jewel System policy structure
func buildSystemPolicy(cname, ns, action string, labels string, matchDirs []types.KnoxMatchDirectories, matchPaths []types.KnoxMatchPaths, matchProtocols []types.KnoxMatchProtocols) types.KnoxSystemPolicy {
	clustername := config.GetCfgClusterName()

	// create policy name
	name := strconv.FormatUint(uint64(common.HashInt(labels+ns+clustername+cname)), 10)
	return types.KnoxSystemPolicy{
		APIVersion: "security.kubearmor.com/v1",
		Kind:       "KubeArmorPolicy",
		Metadata: map[string]string{
			"name":      "autopol-sensitive-" + name,
			"namespace": ns,
			"status":    "latest",
		},
		Spec: types.KnoxSystemSpec{
			Severity: 7,
			Selector: types.Selector{
				MatchLabels: libs.LabelMapFromString(labels)},
			Action:  "Allow", // global action - default Allow
			Message: "Sensitive assets and process control policy",
			File: types.KnoxSys{
				MatchDirectories: matchDirs,
			},
			Process: types.KnoxSys{
				MatchPaths: matchPaths,
			},
			Network: types.NetworkRule{
				MatchProtocols: matchProtocols,
			},
		},
	}
}

func createCrownjewelPolicy(ms types.MatchSpec, cname, namespace, action string, labels string, matchedDirPts, matchedMountPts, matchedProcessPts []string, fromSrc map[string]string, matchProtocols []types.KnoxMatchProtocols) types.KnoxSystemPolicy {
	var matchDirs []types.KnoxMatchDirectories
	i := 1
	for _, dirpath := range matchedDirPts {
		action = "Block"
		for _, mountPt := range matchedMountPts {
			if dirpath == mountPt {
				action = "Allow"
				break
			}
		}

		var fromSourceVal []types.KnoxFromSource
		for key, value := range fromSrc {
			if strings.HasPrefix(key, dirpath) {
				// Check if the value already exists in fromSourceVal
				exists := false
				for _, existing := range fromSourceVal {
					if existing.Path == value {
						exists = true
						break
					}
				}
				if !exists {
					fromSourceVal = append(fromSourceVal, types.KnoxFromSource{Path: value})
				}
			}
		}

		matchDir := types.KnoxMatchDirectories{
			Dir:        dirpath + "/",
			Recursive:  true,
			FromSource: fromSourceVal,
			Action:     action,
		}

		if action == "Allow" {
			// Block that dir from global access
			matchAllowedDir := types.KnoxMatchDirectories{
				Dir:       dirpath + "/",
				Recursive: true,
				Action:    "Block",
			}
			matchDirs = append(matchDirs, matchAllowedDir)
		}

		matchDirs = append(matchDirs, matchDir)

		if i == 1 {
			// default allow access to root directory "/"
			matchDir := types.KnoxMatchDirectories{
				Dir:       "/",
				Recursive: true,
			}
			matchDirs = append(matchDirs, matchDir)
			i++
		}
	}

	var matchPaths []types.KnoxMatchPaths
	for _, processpath := range matchedProcessPts {
		matchPath := types.KnoxMatchPaths{
			Path: processpath,
		}
		matchPaths = append(matchPaths, matchPath)
	}
	policy := buildSystemPolicy(cname, namespace, action, labels, matchDirs, matchPaths, matchProtocols)

	return policy
}
