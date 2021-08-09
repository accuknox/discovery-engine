package config

import (
	"errors"
	"net"

	"github.com/accuknox/knoxAutoPolicy/src/libs"
	types "github.com/accuknox/knoxAutoPolicy/src/types"
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
	dbAddr, err := net.LookupIP(cfgDB.DBHost)
	if err == nil {
		cfgDB.DBHost = dbAddr[0].String()
	} else {
		cfgDB.DBHost = libs.GetExternalIPAddr()
	}
	cfgDB.DBPort = viper.GetString("database.port")

	cfgDB.TableConfiguration = viper.GetString("database.table-configuration")
	cfgDB.TableNetworkLog = viper.GetString("database.table-network-log")
	cfgDB.TableNetworkPolicy = viper.GetString("database.table-network-policy")
	cfgDB.TableSystemLog = viper.GetString("database.table-system-log")
	cfgDB.TableSystemAlert = viper.GetString("database.table-system-alert")
	cfgDB.TableSystemPolicy = viper.GetString("database.table-system-policy")

	return cfgDB
}

func LoadConfigCiliumHubble() types.ConfigCiliumHubble {
	cfgHubble := types.ConfigCiliumHubble{}

	cfgHubble.HubbleURL = viper.GetString("cilium-hubble.url")
	addr, err := net.LookupIP(cfgHubble.HubbleURL)
	if err == nil {
		cfgHubble.HubbleURL = addr[0].String()
	} else {
		cfgHubble.HubbleURL = libs.GetExternalIPAddr()
	}

	cfgHubble.HubblePort = viper.GetString("cilium-hubble.port")

	return cfgHubble
}

func LoadDefaultConfig() {
	CurrentCfg = types.Configuration{}

	// default
	CurrentCfg.ConfigName = "default"

	CurrentCfg.Status = 1 // 1: active 0: inactive

	// load network policy discovery
	CurrentCfg.ConfigNetPolicy = types.ConfigNetworkPolicy{
		OperationMode:           viper.GetInt("application.network.operation-mode"),
		CronJobTimeInterval:     "@every " + viper.GetString("application.network.cron-job-time-interval"),
		OneTimeJobTimeSelection: "", // e.g., 2021-01-20 07:00:23|2021-01-20 07:00:25
		OperationTrigger:        viper.GetInt("application.network.operation-trigger"),

		NetworkLogFrom:   viper.GetString("application.network.network-log-from"),
		NetworkLogFile:   viper.GetString("application.network.network-log-file"),
		NetworkPolicyTo:  viper.GetString("application.network.network-policy-to"),
		NetworkPolicyDir: viper.GetString("application.network.network-policy-dir"),

		NetPolicyTypes:     3,
		NetPolicyRuleTypes: 511,
		NetPolicyCIDRBits:  32,

		NetLogFilters: []types.NetworkLogFilter{},

		NetPolicyL3Level: 1,
		NetPolicyL4Level: 1,
		NetPolicyL7Level: 1,
	}

	// load system policy discovery
	CurrentCfg.ConfigSysPolicy = types.ConfigSystemPolicy{
		OperationMode:           viper.GetInt("application.system.operation-mode"),
		CronJobTimeInterval:     "@every " + viper.GetString("application.system.cron-job-time-interval"),
		OneTimeJobTimeSelection: "", // e.g., 2021-01-20 07:00:23|2021-01-20 07:00:25
		OperationTrigger:        viper.GetInt("application.network.operation-trigger"),

		SysPolicyTypes: 7,

		SystemLogFrom:   viper.GetString("application.system.system-log-from"),
		SystemLogFile:   viper.GetString("application.system.system-log-file"),
		SystemPolicyTo:  viper.GetString("application.system.system-policy-to"),
		SystemPolicyDir: viper.GetString("application.system.system-policy-dir"),

		SystemLogFilters: []types.SystemLogFilter{},

		ProcessFromSource: true,
		FileFromSource:    true,
	}

	// load cluster resource info
	CurrentCfg.ConfigClusterMgmt = types.ConfigClusterMgmt{
		ClusterInfoFrom: viper.GetString("application.cluster.cluster-info-from"),
		ClusterMgmtURL:  viper.GetString("application.cluster.cluster-mgmt-url"),
	}

	// load database
	CurrentCfg.ConfigDB = LoadConfigDB()

	// load cilium hubble relay
	CurrentCfg.ConfigCiliumHubble = LoadConfigCiliumHubble()
}

// ======================== //
// == Configuration CRUD == //
// ======================== //

func AddConfiguration(newConfig types.Configuration) error {
	return libs.AddConfiguration(CurrentCfg.ConfigDB, newConfig)
}

func GetConfigurations(configName string) ([]types.Configuration, error) {
	return libs.GetConfigurations(CurrentCfg.ConfigDB, configName)
}

func UpdateConfiguration(configName string, updateConfig types.Configuration) error {
	return libs.UpdateConfiguration(CurrentCfg.ConfigDB, configName, updateConfig)
}

func DeleteConfiguration(configName string) error {
	return libs.DeleteConfiguration(CurrentCfg.ConfigDB, configName)
}

func ApplyConfiguration(configName string) error {
	if CurrentCfg.ConfigName == configName {
		return errors.New("Not applied " + configName + " due to same configuration name")
	}

	if err := libs.ApplyConfiguration(CurrentCfg.ConfigDB, CurrentCfg.ConfigName, configName); err != nil {
		return err
	}

	appliedConfigs, err := libs.GetConfigurations(CurrentCfg.ConfigDB, configName)
	if err != nil {
		return err
	}

	// check if db info is null
	appliedCfg := appliedConfigs[0]
	if appliedCfg.ConfigDB.DBHost == "" {
		appliedCfg.ConfigDB = CurrentCfg.ConfigDB
	}

	// update current Cfg
	CurrentCfg = appliedCfg

	return nil
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

// ============================= //
// == Get Network Config Info == //
// ============================= //

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

func GetCfgNetworkLogFrom() string {
	return CurrentCfg.ConfigNetPolicy.NetworkLogFrom
}

func GetCfgNetworkLogFile() string {
	return CurrentCfg.ConfigNetPolicy.NetworkLogFile
}

func GetCfgCiliumHubble() types.ConfigCiliumHubble {
	return CurrentCfg.ConfigCiliumHubble
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

// ============================ //
// == Get System Config Info == //
// ============================ //

func GetCfgSysOperationMode() int {
	return CurrentCfg.ConfigSysPolicy.OperationMode
}

func GetCfgSysOperationTrigger() int {
	return CurrentCfg.ConfigNetPolicy.OperationTrigger
}

func GetCfgSysCronJobTime() string {
	return CurrentCfg.ConfigSysPolicy.CronJobTimeInterval
}

func GetCfgSysOneTime() string {
	return CurrentCfg.ConfigSysPolicy.OneTimeJobTimeSelection
}

// == //

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
