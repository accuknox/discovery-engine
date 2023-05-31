package config

import (
	"os"
	"strconv"

	types "github.com/accuknox/auto-policy-discovery/src/types"
	"github.com/spf13/viper"
)

// operation mode: 		 cronjob: 1
//                 		 onetime job: 2

// network policy types: egress only   : 1
//                       ingress only  : 2
//                       all           : 3

// network rule types:   matchLabels: 1
//                       toPorts    : 2
//                       toHTTPs    : 4
//                       toCIDRs    : 8
//                       toEntities : 16
//                       toServices : 32
//                       toFQDNs    : 64
//                       fromCIDRs  : 128
//                       fromEntities : 256
//                       all        : 511

// system policy types: process     : 1
//                      file        : 2
//                      network     : 4
//                      all		    : 7

// ====================== //
// == Global Variables == //
// ====================== //

var CurrentCfg types.Configuration

var NetworkPlugIn string
var IgnoringNetworkNamespaces []string
var HTTPUrlThreshold int

func init() {
	IgnoringNetworkNamespaces = []string{"kube-system"}
	HTTPUrlThreshold = 5
	NetworkPlugIn = "cilium" // for now, cilium only supported
}

// =========================== //
// == Configuration Loading == //
// =========================== //

func LoadConfigDB() types.ConfigDB {
	cfgDB := types.ConfigDB{}

	cfgDB.DBDriver = viper.GetString("database.driver")
	cfgDB.DBUser = viper.GetString("database.user")
	cfgDB.DBPass = viper.GetString("database.password")
	cfgDB.DBName = viper.GetString("database.dbname")

	cfgDB.DBHost = viper.GetString("database.host")
	cfgDB.SQLiteDBPath = viper.GetString("database.sqlite-db-path")
	/*
		fix for #405
		dbAddr, err := net.LookupIP(cfgDB.DBHost)
		if err == nil {
			cfgDB.DBHost = dbAddr[0].String()
		} else {
			cfgDB.DBHost = libs.GetExternalIPAddr()
		}
	*/
	cfgDB.DBPort = viper.GetString("database.port")

	return cfgDB
}

func LoadConfigCiliumHubble() types.ConfigCiliumHubble {
	cfgHubble := types.ConfigCiliumHubble{}

	cfgHubble.HubbleURL = viper.GetString("cilium-hubble.url")
	/*
		commented for fixing #405
		addr, err := net.LookupIP(cfgHubble.HubbleURL)
		if err == nil {
			cfgHubble.HubbleURL = addr[0].String()
		} else {
			cfgHubble.HubbleURL = libs.GetExternalIPAddr()
		}
	*/

	cfgHubble.HubblePort = viper.GetString("cilium-hubble.port")

	return cfgHubble
}

func LoadConfigKubeArmor() types.ConfigKubeArmorRelay {
	cfgKubeArmor := types.ConfigKubeArmorRelay{}
	cfgKubeArmor.KubeArmorRelayURL = viper.GetString("kubearmor.url")
	/*
		addr, err := net.LookupIP(cfgKubeArmor.KubeArmorRelayURL)
		if err == nil {
			cfgKubeArmor.KubeArmorRelayURL = addr[0].String()
		} else {
			cfgKubeArmor.KubeArmorRelayURL = libs.GetExternalIPAddr()
		}
	*/

	cfgKubeArmor.KubeArmorRelayPort = viper.GetString("kubearmor.port")

	return cfgKubeArmor
}

func LoadConfigFromFile() {
	CurrentCfg = types.Configuration{}

	// default
	CurrentCfg.ConfigName = "default"

	CurrentCfg.Status = 1 // 1: active 0: inactive

	// Load cluster related config
	workspaceId, _ := strconv.ParseInt(os.Getenv("workspace_id"), 0, 32)
	clusterId, _ := strconv.ParseInt(os.Getenv("cluster_id"), 0, 32)

	CurrentCfg.ClusterName = os.Getenv("cluster_name")
	CurrentCfg.WorkspaceID = int32(workspaceId)
	CurrentCfg.ClusterID = int32(clusterId)

	// load network policy discovery
	CurrentCfg.ConfigNetPolicy = types.ConfigNetworkPolicy{
		OperationMode:           viper.GetInt("application.network.operation-mode"),
		OperationTrigger:        viper.GetInt("application.network.operation-trigger"),
		CronJobTimeInterval:     "@every " + viper.GetString("application.network.cron-job-time-interval"),
		OneTimeJobTimeSelection: "", // e.g., 2021-01-20 07:00:23|2021-01-20 07:00:25

		NetworkLogLimit:  viper.GetInt("application.network.network-log-limit"),
		NetworkLogFrom:   viper.GetString("application.network.network-log-from"),
		NetworkLogFile:   viper.GetString("application.network.network-log-file"),
		NetworkPolicyTo:  viper.GetString("application.network.network-policy-to"),
		NetworkPolicyDir: viper.GetString("application.network.network-policy-dir"),

		NetPolicyTypes:     3,
		NetPolicyRuleTypes: 1023,
		NetPolicyCIDRBits:  32,

		NetLogFilters: []types.NetworkLogFilter{},

		NetPolicyL3Level: 1,
		NetPolicyL4Level: 1,
		NetPolicyL7Level: 1,

		NetSkipCertVerification: viper.GetBool("application.network.skip-cert-verification"),
	}

	CurrentCfg.ConfigNetPolicy.NsFilter, CurrentCfg.ConfigNetPolicy.NsNotFilter = getConfigNsFilter("application.network.namespace-filter")

	// load system policy discovery
	CurrentCfg.ConfigSysPolicy = types.ConfigSystemPolicy{
		OperationMode:           viper.GetInt("application.system.operation-mode"),
		OperationTrigger:        viper.GetInt("application.system.operation-trigger"),
		CronJobTimeInterval:     "@every " + viper.GetString("application.system.cron-job-time-interval"),
		OneTimeJobTimeSelection: "", // e.g., 2021-01-20 07:00:23|2021-01-20 07:00:25

		SystemLogLimit:   viper.GetInt("application.system.system-log-limit"),
		SystemLogFrom:    viper.GetString("application.system.system-log-from"),
		SystemLogFile:    viper.GetString("application.system.system-log-file"),
		SystemPolicyTo:   viper.GetString("application.system.system-policy-to"),
		SystemPolicyDir:  viper.GetString("application.system.system-policy-dir"),
		SysPolicyTypes:   viper.GetInt("application.system.system-policy-types"),
		DeprecateOldMode: viper.GetBool("application.system.deprecate-old-mode"),

		SystemLogFilters: []types.SystemLogFilter{},

		ProcessFromSource: true,
		FileFromSource:    true,
	}

	CurrentCfg.ConfigSysPolicy.NsFilter, CurrentCfg.ConfigSysPolicy.NsNotFilter = getConfigNsFilter("application.system.namespace-filter")
	CurrentCfg.ConfigSysPolicy.FromSourceFilter = viper.GetStringSlice("application.system.fromsource-filter")

	CurrentCfg.ConfigAdmissionControllerPolicy.NsFilter, CurrentCfg.ConfigAdmissionControllerPolicy.NsNotFilter = getConfigNsFilter("application.admission-controller.namespace-filter")
	CurrentCfg.ConfigAdmissionControllerPolicy.GenericPolicyList = viper.GetStringSlice("application.admission-controller.generic-policy-list")

	// load cluster resource info
	CurrentCfg.ConfigClusterMgmt = types.ConfigClusterMgmt{
		ClusterInfoFrom: viper.GetString("application.cluster.cluster-info-from"),
		ClusterMgmtURL:  viper.GetString("application.cluster.cluster-mgmt-url"),
	}

	CurrentCfg.ConfigObservability = types.ConfigObservability{
		Enable:              viper.GetBool("observability.enable"),
		CronJobTimeInterval: "@every " + viper.GetString("observability.cron-job-time-interval"),
		DBName:              viper.GetString("observability.dbname"),
		SysObservability:    viper.GetBool("observability.system-observability"),
		NetObservability:    viper.GetBool("observability.network-observability"),
		WriteLogsToDB:       viper.GetBool("observability.write-logs-to-db"),
	}

	CurrentCfg.ConfigPublisher = types.ConfigPublisher{
		Enable:              viper.GetBool("publisher.enable"),
		CronJobTimeInterval: "@every " + viper.GetString("publisher.cron-job-time-interval"),
	}

	// for purge old entries from db
	CurrentCfg.ConfigPurgeOldDBEntries = types.ConfigPurgeOldDBEntries{
		Enable:              viper.GetBool("purge-old-db-entries.enable"),
		CronJobTimeInterval: "@every " + viper.GetString("purge-old-db-entries.cron-job-time-interval"),
		DBName:              viper.GetStringSlice("purge-old-db-entries.dbname"),
	}

	// recommend policy configurations
	CurrentCfg.ConfigRecommendPolicy = types.ConfigRecommendPolicy{
		CronJobTimeInterval:                "@every " + viper.GetString("recommend.cron-job-time-interval"),
		OneTimeJobTimeSelection:            "", // e.g., 2021-01-20 07:00:23|2021-01-20 07:00:25
		OperationMode:                      viper.GetInt("recommend.operation-mode"),
		RecommendHostPolicy:                viper.GetBool("recommend.host-policy"),
		RecommendAdmissionControllerPolicy: viper.GetBool("recommend.admission-controller-policy"),
	}

	// load database
	CurrentCfg.ConfigDB = LoadConfigDB()

	// load cilium hubble relay
	CurrentCfg.ConfigCiliumHubble = LoadConfigCiliumHubble()

	// load kubearmor relay config
	CurrentCfg.ConfigKubeArmorRelay = LoadConfigKubeArmor()
}

// ============================ //
// == Set Configuration Info == //
// ============================ //

func SetLogFile(file string) {
	CurrentCfg.ConfigNetPolicy.NetworkLogFile = file
}

// ============================ //
// == Get Configuration Info == //
// ============================ //

func GetCurrentCfg() types.Configuration {
	return CurrentCfg
}

func GetCfgDB() types.ConfigDB {
	return CurrentCfg.ConfigDB
}

// =============================== //
// == Get Cluster Configuration == //
// =============================== //

func GetCfgClusterName() string {
	return CurrentCfg.ClusterName
}

func GetCfgWorkspaceId() int32 {
	return CurrentCfg.WorkspaceID
}

func GetCfgClusterId() int32 {
	return CurrentCfg.ClusterID
}

// ============================= //
// == Get Network Config Info == //
// ============================= //

func GetCfgNet() types.ConfigNetworkPolicy {
	return CurrentCfg.ConfigNetPolicy
}

func GetCfgNetOperationMode() int {
	return CurrentCfg.ConfigNetPolicy.OperationMode
}

func GetCfgNetCronJobTime() string {
	return CurrentCfg.ConfigNetPolicy.CronJobTimeInterval
}

func GetCfgNetOneTime() string {
	return CurrentCfg.ConfigNetPolicy.OneTimeJobTimeSelection
}

func GetCfgNetOperationTrigger() int {
	return CurrentCfg.ConfigNetPolicy.OperationTrigger
}

// == //

func GetCfgNetLimit() int {
	return CurrentCfg.ConfigNetPolicy.NetworkLogLimit
}

func GetCfgNetworkLogFrom() string {
	return CurrentCfg.ConfigNetPolicy.NetworkLogFrom
}

func GetCfgNetworkLogFile() string {
	return CurrentCfg.ConfigNetPolicy.NetworkLogFile
}

func GetCfgCiliumHubble() types.ConfigCiliumHubble {
	return CurrentCfg.ConfigCiliumHubble
}

func GetCfgKubeArmor() types.ConfigKubeArmorRelay {
	return CurrentCfg.ConfigKubeArmorRelay
}

func GetCfgNetworkPolicyTo() string {
	return CurrentCfg.ConfigNetPolicy.NetworkPolicyTo
}

func GetCfgCIDRBits() int {
	return CurrentCfg.ConfigNetPolicy.NetPolicyCIDRBits
}

func GetCfgNetworkPolicyTypes() int {
	return CurrentCfg.ConfigNetPolicy.NetPolicyTypes
}

func GetCfgNetworkRuleTypes() int {
	return CurrentCfg.ConfigNetPolicy.NetPolicyRuleTypes
}

func GetCfgNetworkL3Level() int {
	return CurrentCfg.ConfigNetPolicy.NetPolicyL3Level
}

func GetCfgNetworkL4Level() int {
	return CurrentCfg.ConfigNetPolicy.NetPolicyL4Level
}

func GetCfgNetworkL7Level() int {
	return CurrentCfg.ConfigNetPolicy.NetPolicyL7Level
}

func GetCfgNetworkHTTPThreshold() int {
	return HTTPUrlThreshold
}

func GetCfgNetworkSkipNamespaces() []string {
	return IgnoringNetworkNamespaces
}

func GetCfgNetworkLogFilters() []types.NetworkLogFilter {
	return CurrentCfg.ConfigNetPolicy.NetLogFilters
}

func GetCfgNetworkSkipCertVerification() bool {
	return CurrentCfg.ConfigNetPolicy.NetSkipCertVerification
}

// ============================ //
// == Get System Config Info == //
// ============================ //

func GetCfgSys() types.ConfigSystemPolicy {
	return CurrentCfg.ConfigSysPolicy
}

func GetCfgSysOperationMode() int {
	return CurrentCfg.ConfigSysPolicy.OperationMode
}

func GetCfgSysOperationTrigger() int {
	return CurrentCfg.ConfigSysPolicy.OperationTrigger
}

func GetCfgSysCronJobTime() string {
	return CurrentCfg.ConfigSysPolicy.CronJobTimeInterval
}

func GetCfgSysOneTime() string {
	return CurrentCfg.ConfigSysPolicy.OneTimeJobTimeSelection
}

// == //

func GetCfgSysLimit() int {
	return CurrentCfg.ConfigSysPolicy.SystemLogLimit
}

func GetCfgSystemLogFrom() string {
	return CurrentCfg.ConfigSysPolicy.SystemLogFrom
}

func GetCfgSystemLogFile() string {
	return CurrentCfg.ConfigSysPolicy.SystemLogFile
}

func GetCfgSystemPolicyTo() string {
	return CurrentCfg.ConfigSysPolicy.SystemPolicyTo
}

func GetCfgSystemPolicyDir() string {
	return CurrentCfg.ConfigSysPolicy.SystemPolicyDir
}

func GetCfgSystemkPolicyTypes() int {
	return CurrentCfg.ConfigSysPolicy.SysPolicyTypes
}

func GetCfgSystemLogFilters() []types.SystemLogFilter {
	return CurrentCfg.ConfigSysPolicy.SystemLogFilters
}

func GetCfgSystemProcFromSource() bool {
	return CurrentCfg.ConfigSysPolicy.ProcessFromSource
}

func GetCfgSystemFileFromSource() bool {
	return CurrentCfg.ConfigSysPolicy.FileFromSource
}

// ============================= //
// == Get Cluster Config Info == //
// ============================= //

func GetCfgClusterInfoFrom() string {
	return CurrentCfg.ConfigClusterMgmt.ClusterInfoFrom
}

func GetCfgClusterMgmtURL() string {
	return CurrentCfg.ConfigClusterMgmt.ClusterMgmtURL
}

// ============================ //
// == Get Observability Info == //
// ============================ //

func GetCfgObservabilityEnable() bool {
	return CurrentCfg.ConfigObservability.Enable
}

func GetCfgObservabilityCronJobTime() string {
	return CurrentCfg.ConfigObservability.CronJobTimeInterval
}

func GetCfgObservabilityDBName() string {
	return CurrentCfg.ConfigObservability.DBName
}

func GetCfgObservabilitySysObsStatus() bool {
	return CurrentCfg.ConfigObservability.SysObservability
}

func GetCfgObservabilityNetObsStatus() bool {
	return CurrentCfg.ConfigObservability.NetObservability
}

func GetCfgObservabilityWriteLogsToDB() bool {
	return CurrentCfg.ConfigObservability.WriteLogsToDB
}

// ======================= //
// == Extract NS Filter == //
// ======================= //

func getConfigNsFilter(config string) ([]string, []string) {
	var ns, notNs []string
	namespaces := viper.GetStringSlice(config)
	for _, n := range namespaces {
		if n[0] == '!' {
			notNs = append(notNs, n[1:])
		} else {
			ns = append(ns, n)
		}
	}
	return ns, notNs
}

// ========================== //
// == Get Publisher Config == //
// ========================== //

func GetCfgPublisherEnable() bool {
	return CurrentCfg.ConfigPublisher.Enable
}

func GetCfgPublisherCronJobTime() string {
	return CurrentCfg.ConfigPublisher.CronJobTimeInterval
}

// ========================== //
// == Purge Old DB Entries == //
// ========================== //

func GetCfgPurgeOldDBEntriesEnable() bool {
	return CurrentCfg.ConfigPurgeOldDBEntries.Enable
}

func GetCfgPurgeOldDBEntriesCronJobTime() string {
	return CurrentCfg.ConfigPurgeOldDBEntries.CronJobTimeInterval
}

func GetCfgPurgeOldDBEntriesDBName() []string {
	return CurrentCfg.ConfigPurgeOldDBEntries.DBName
}

// ============================ //
// == Get Recommend Config Info == //
// ============================ //

func GetCfgRecOperationMode() int {
	return CurrentCfg.ConfigRecommendPolicy.OperationMode
}

func GetCfgRecCronJobTime() string {
	return CurrentCfg.ConfigRecommendPolicy.CronJobTimeInterval
}

func GetCfgRecOneTime() string {
	return CurrentCfg.ConfigRecommendPolicy.OneTimeJobTimeSelection
}

func GetCfgRecommendHostPolicy() bool {
	return CurrentCfg.ConfigRecommendPolicy.RecommendHostPolicy
}

func GetCfgRecommendAdmissionControllerPolicy() bool {
	return CurrentCfg.ConfigRecommendPolicy.RecommendAdmissionControllerPolicy
}
