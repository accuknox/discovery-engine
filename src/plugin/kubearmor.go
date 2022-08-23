package plugin

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/accuknox/auto-policy-discovery/src/common"
	"github.com/accuknox/auto-policy-discovery/src/config"
	"github.com/accuknox/auto-policy-discovery/src/libs"
	obs "github.com/accuknox/auto-policy-discovery/src/observability"
	"github.com/accuknox/auto-policy-discovery/src/types"
	pb "github.com/kubearmor/KubeArmor/protobuf"
	"google.golang.org/grpc"
)

// Global Variable
var KubeArmorRelayLogs []*pb.Log
var KubeArmorRelayLogsMutex *sync.Mutex

var KubeArmorFCLogs []*types.KnoxSystemLog
var KubeArmorFCLogsMutex *sync.Mutex

func generateProcessPaths(fromSrc []types.KnoxFromSource) []string {
	var processpaths []string
	for _, locfrmsrc := range fromSrc {
		processpaths = append(processpaths, locfrmsrc.Path)
	}
	return processpaths
}

func ConvertKnoxSystemPolicyToKubeArmorPolicy(knoxPolicies []types.KnoxSystemPolicy) []types.KubeArmorPolicy {
	results := []types.KubeArmorPolicy{}

	for _, policy := range knoxPolicies {
		filePathsFromSrc := []string{}
		processPaths := []string{}
		resPath := []string{}

		kubePolicy := types.KubeArmorPolicy{
			APIVersion: "security.kubearmor.com/v1",
			Kind:       "KubeArmorPolicy",
			Metadata:   map[string]string{},
		}

		kubePolicy.Metadata["namespace"] = policy.Metadata["namespace"]
		kubePolicy.Metadata["clusterName"] = policy.Metadata["clusterName"]
		kubePolicy.Metadata["containername"] = policy.Metadata["containername"]
		kubePolicy.Metadata["name"] = policy.Metadata["name"]

		if policy.Metadata["namespace"] == types.PolicyDiscoveryVMNamespace {
			kubePolicy.Kind = "KubeArmorHostPolicy"
		}

		kubePolicy.Spec = policy.Spec

		if kubePolicy.Kind == "KubeArmorPolicy" {
			dirRule := types.KnoxMatchDirectories{
				Dir:       types.PreConfiguredKubearmorRule,
				Recursive: true,
			}
			kubePolicy.Spec.File.MatchDirectories = append(policy.Spec.File.MatchDirectories, dirRule)
		}

		for _, procpath := range kubePolicy.Spec.Process.MatchPaths {
			processPaths = append(processPaths, procpath.Path)
		}

		for _, matchpaths := range kubePolicy.Spec.File.MatchPaths {
			filePathsFromSrc = append(filePathsFromSrc, generateProcessPaths(matchpaths.FromSource)...)
		}
		for _, matchpaths := range kubePolicy.Spec.File.MatchDirectories {
			filePathsFromSrc = append(filePathsFromSrc, generateProcessPaths(matchpaths.FromSource)...)
		}

		filePathsFromSrc = common.StringDeDuplication(filePathsFromSrc)
		procPaths := common.StringDeDuplication(processPaths)

		for _, file := range filePathsFromSrc {
			isPathExist := false
			for _, proc := range procPaths {
				if proc == file {
					isPathExist = true
					continue
				}
			}
			if !isPathExist {
				resPath = append(resPath, file)
			}
		}

		resPath = common.StringDeDuplication(resPath)

		for _, path := range resPath {
			kubePolicy.Spec.Process.MatchPaths = append(kubePolicy.Spec.Process.MatchPaths, types.KnoxMatchPaths{
				Path: path,
			})
		}

		results = append(results, kubePolicy)
	}

	return results
}

func ConvertSQLiteKubeArmorLogsToKnoxSystemLogs(docs []map[string]interface{}) []types.KnoxSystemLog {
	results := []types.KnoxSystemLog{}

	for _, doc := range docs {
		syslog := types.SystemLogEvent{}

		b, err := json.Marshal(doc)
		if err != nil {
			log.Error().Msg(err.Error())
			continue
		}

		if err := json.Unmarshal(b, &syslog); err != nil {
			log.Error().Msg(err.Error())
		}

		sources := strings.Split(syslog.Source, " ")
		source := ""
		if len(sources) >= 1 {
			source = sources[0]
		}

		resources := strings.Split(syslog.Resource, " ")
		resource := ""
		if len(resources) >= 1 {
			resource = resources[0]
		}

		readOnly := false
		if syslog.Data != "" && strings.Contains(syslog.Data, "O_RDONLY") {
			readOnly = true
		}

		knoxSysLog := types.KnoxSystemLog{
			ClusterName:    syslog.ClusterName,
			HostName:       syslog.HostName,
			Namespace:      syslog.NamespaceName,
			ContainerName:  syslog.ContainerName,
			PodName:        syslog.PodName,
			Source:         source,
			SourceOrigin:   syslog.Source,
			Operation:      syslog.Operation,
			ResourceOrigin: syslog.Resource,
			Resource:       resource,
			Data:           syslog.Data,
			ReadOnly:       readOnly,
			Result:         syslog.Result,
		}

		results = append(results, knoxSysLog)
	}

	return results
}

func ConvertMySQLKubeArmorLogsToKnoxSystemLogs(docs []map[string]interface{}) []types.KnoxSystemLog {
	results := []types.KnoxSystemLog{}

	for _, doc := range docs {
		syslog := types.SystemLogEvent{}

		b, err := json.Marshal(doc)
		if err != nil {
			log.Error().Msg(err.Error())
			continue
		}

		if err := json.Unmarshal(b, &syslog); err != nil {
			log.Error().Msg(err.Error())
		}

		sources := strings.Split(syslog.Source, " ")
		source := ""
		if len(sources) >= 1 {
			source = sources[0]
		}

		resources := strings.Split(syslog.Resource, " ")
		resource := ""
		if len(resources) >= 1 {
			resource = resources[0]
		}

		readOnly := false
		if syslog.Data != "" && strings.Contains(syslog.Data, "O_RDONLY") {
			readOnly = true
		}

		knoxSysLog := types.KnoxSystemLog{
			ClusterName:    syslog.ClusterName,
			HostName:       syslog.HostName,
			Namespace:      syslog.NamespaceName,
			ContainerName:  syslog.ContainerName,
			PodName:        syslog.PodName,
			Source:         source,
			SourceOrigin:   syslog.Source,
			Operation:      syslog.Operation,
			ResourceOrigin: syslog.Resource,
			Resource:       resource,
			Data:           syslog.Data,
			ReadOnly:       readOnly,
			Result:         syslog.Result,
		}

		results = append(results, knoxSysLog)
	}

	return results
}

func ConvertKubeArmorSystemLogsToKnoxSystemLogs(dbDriver string, docs []map[string]interface{}) []types.KnoxSystemLog {
	if dbDriver == "mysql" {
		return ConvertMySQLKubeArmorLogsToKnoxSystemLogs(docs)
	} else if dbDriver == "sqlite3" {
		return ConvertSQLiteKubeArmorLogsToKnoxSystemLogs(docs)
	}

	return []types.KnoxSystemLog{}
}

func ConvertKubeArmorLogToKnoxSystemLog(relayLog *pb.Log) (types.KnoxSystemLog, error) {

	sources := strings.Split(relayLog.Source, " ")
	source := ""
	if len(sources) >= 1 {
		source = sources[0]
	}

	// check if source is absolute path and does not terminate in "/"
	if !filepath.IsAbs(source) || strings.HasSuffix(source, "/") {
		log.Error().Msgf("invalid source [%s]. %+v", source, relayLog)
		return types.KnoxSystemLog{}, errors.New("invalid file source")
	}

	resources := strings.Split(relayLog.Resource, " ")
	resource := ""
	if len(resources) >= 1 {
		resource = resources[0]
	}

	// check if resource is absolute path. "/" is ok.
	if (relayLog.Operation == "File" || relayLog.Operation == "Process") && !filepath.IsAbs(resource) {
		log.Error().Msgf("invalid resource [%s]. %+v", resource, relayLog)
		return types.KnoxSystemLog{}, errors.New("invalid file resource")
	}

	readOnly := false
	if relayLog.Data != "" && strings.Contains(relayLog.Data, "O_RDONLY") {
		readOnly = true
	}

	if strings.Contains(source, "runc") {
		source = ""
	}

	if strings.Contains(resource, "runc") {
		resource = ""
	}

	if strings.HasPrefix(resource, types.PreConfiguredKubearmorRule) {
		return types.KnoxSystemLog{}, errors.New("predefined file resource")
	}

	knoxSystemLog := types.KnoxSystemLog{
		ClusterName:    relayLog.ClusterName,
		HostName:       relayLog.HostName,
		Namespace:      relayLog.NamespaceName,
		ContainerName:  relayLog.ContainerName,
		PodName:        relayLog.PodName,
		Source:         source,
		SourceOrigin:   relayLog.Source,
		Operation:      relayLog.Operation,
		ResourceOrigin: relayLog.Resource,
		Resource:       resource,
		Data:           relayLog.Data,
		ReadOnly:       readOnly,
		Result:         relayLog.Result,
	}

	if relayLog.Type == "HostLog" {
		knoxSystemLog.ContainerName = relayLog.HostName
		knoxSystemLog.Namespace = types.PolicyDiscoveryVMNamespace
		knoxSystemLog.PodName = types.PolicyDiscoveryVMPodName
	}

	if relayLog.Type == "ContainerLog" && relayLog.NamespaceName == types.PolicyDiscoveryContainerNamespace {
		knoxSystemLog.ContainerName = relayLog.ContainerName
		knoxSystemLog.Namespace = types.PolicyDiscoveryContainerNamespace
		knoxSystemLog.PodName = types.PolicyDiscoveryContainerPodName
	}

	return knoxSystemLog, nil
}

// ========================= //
// == KubeArmor Relay == //
// ========================= //

func ConnectKubeArmorRelay(cfg types.ConfigKubeArmorRelay) *grpc.ClientConn {
	addr := net.JoinHostPort(cfg.KubeArmorRelayURL, cfg.KubeArmorRelayPort)

	conn, err := grpc.Dial(addr, grpc.WithInsecure())
	if err != nil {
		log.Error().Msg("err connecting kubearmor relay. " + err.Error())
		return nil
	}

	log.Info().Msg("connected to kubearmor relay " + addr)
	return conn
}

func GetSystemAlertsFromKubeArmorRelay(trigger int) []*pb.Log {
	results := []*pb.Log{}
	KubeArmorRelayLogsMutex.Lock()
	if len(KubeArmorRelayLogs) == 0 {
		log.Info().Msgf("KubeArmor Relay traffic flow not exist")
		KubeArmorRelayLogsMutex.Unlock()
		return results
	}

	if len(KubeArmorRelayLogs) < trigger {
		log.Info().Msgf("The number of KubeArmor traffic flow [%d] is less than trigger [%d]", len(KubeArmorRelayLogs), trigger)
		KubeArmorRelayLogsMutex.Unlock()
		return results
	}

	results = KubeArmorRelayLogs     // copy
	KubeArmorRelayLogs = []*pb.Log{} // reset
	KubeArmorRelayLogsMutex.Unlock()

	log.Info().Msgf("The total number of KubeArmor relay traffic flow: [%d] from %s ~ to %s", len(results),
		time.Unix(results[0].Timestamp, 0).Format(libs.TimeFormSimple),
		time.Unix(results[len(results)-1].Timestamp, 0).Format(libs.TimeFormSimple))

	return results
}

var KubeArmorRelayStarted = false

func StartKubeArmorRelay(StopChan chan struct{}, cfg types.ConfigKubeArmorRelay) {
	if KubeArmorRelayStarted {
		// log.Info().Msg("kubearmor relay already started")
		return
	}
	KubeArmorRelayStarted = true
	conn := ConnectKubeArmorRelay(cfg)

	client := pb.NewLogServiceClient(conn)
	req := pb.RequestMessage{}
	req.Filter = "all"

	nsFilter := config.CurrentCfg.ConfigSysPolicy.NsFilter
	nsNotFilter := config.CurrentCfg.ConfigSysPolicy.NsNotFilter
	fromSourceFilter := config.CurrentCfg.ConfigSysPolicy.FromSourceFilter

	//Stream Logs
	go func(client pb.LogServiceClient) {
		defer func() {
			log.Info().Msg("watchlogs returning")
			KubeArmorRelayStarted = false
			_ = conn.Close()
		}()
		stream, err := client.WatchLogs(context.Background(), &req)
		if err != nil {
			log.Error().Msg("unable to stream systems logs: " + err.Error())
			return
		}
		for {
			select {
			case <-StopChan:
				return

			default:
				res, err := stream.Recv()
				if err != nil {
					log.Error().Msg("watch logs stream stopped: " + err.Error())
					return
				}

				if IgnoreLogFromRelayWithNamespace(nsFilter, nsNotFilter, res.NamespaceName) {
					continue
				}

				if IgnoreLogFromRelayWithSource(fromSourceFilter, res.Source) {
					continue
				}

				KubeArmorRelayLogsMutex.Lock()
				KubeArmorRelayLogs = append(KubeArmorRelayLogs, res)
				KubeArmorRelayLogsMutex.Unlock()

				if config.GetCfgObservabilityEnable() {
					obs.ProcessKubearmorLog(res)
				}
			}
		}
	}(client)

	//Stream Alerts
	go func() {
		defer func() {
			log.Info().Msg("watchalerts returning")
			KubeArmorRelayStarted = false
			_ = conn.Close()
		}()
		stream, err := client.WatchAlerts(context.Background(), &req)
		if err != nil {
			log.Error().Msg("unable to stream systems alerts: " + err.Error())
			return
		}
		for {
			select {
			case <-StopChan:
				return

			default:
				res, err := stream.Recv()
				if err != nil {
					log.Error().Msg("system alerts stream stopped: " + err.Error())
					return
				}

				log := pb.Log{
					ClusterName:   res.ClusterName,
					ContainerName: res.ContainerName,
					HostName:      res.HostName,
					NamespaceName: res.NamespaceName,
					PodName:       res.PodName,
					Source:        res.Source,
					Operation:     res.Operation,
					Resource:      res.Resource,
					Data:          res.Data,
					Result:        res.Result,
					Type:          res.Type,
				}

				if IgnoreLogFromRelayWithNamespace(nsFilter, nsNotFilter, log.NamespaceName) {
					continue
				}

				if IgnoreLogFromRelayWithSource(fromSourceFilter, log.Source) {
					continue
				}

				KubeArmorRelayLogsMutex.Lock()
				KubeArmorRelayLogs = append(KubeArmorRelayLogs, &log)
				KubeArmorRelayLogsMutex.Unlock()

				if config.GetCfgObservabilityEnable() {
					obs.ProcessKubearmorAlert(&log)
				}
			}
		}
	}()
}

func GetSystemLogsFromFeedConsumer(trigger int) []*types.KnoxSystemLog {
	results := []*types.KnoxSystemLog{}
	KubeArmorFCLogsMutex.Lock()
	defer KubeArmorFCLogsMutex.Unlock()
	if len(KubeArmorFCLogs) == 0 {
		log.Info().Msgf("KubeArmor feed-consumer traffic flow not exist")
		return results
	}

	if len(KubeArmorFCLogs) < trigger {
		log.Info().Msgf("The number of KubeArmor traffic flow [%d] is less than trigger [%d]", len(KubeArmorFCLogs), trigger)
		return results
	}

	results = KubeArmorFCLogs                  // copy
	KubeArmorFCLogs = []*types.KnoxSystemLog{} // reset

	log.Info().Msgf("The total number of KubeArmor feed-consumer traffic flow: [%d]", len(results))

	return results
}
