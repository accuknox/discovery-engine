package config

import (
	"errors"
	"net"
	"strings"

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

// ====================== //
// == Global Variables == //
// ====================== //

var Cfg types.Configuration

var IgnoringNetworkNamespaces []string

var HTTPUrlThreshold int

var NetworkPlugIn string

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
	cfgDB.TableSystemPolicy = viper.GetString("database.table-system-policy")

	NetworkPlugIn = "cilium" // for now, cilium only supported

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
	Cfg = types.Configuration{}

	// base
	Cfg.ConfigName = "default"
	Cfg.Status = 1

	Cfg.ConfigDB = LoadConfigDB()
	Cfg.ConfigCiliumHubble = LoadConfigCiliumHubble()

	// set worker
	Cfg.OperationMode = viper.GetInt("application.operation-mode")
	Cfg.CronJobTimeInterval = viper.GetString("application.cron-job-time-interval")
	Cfg.OneTimeJobTimeSelection = "" // e.g., 2021-01-20 07:00:23|2021-01-20 07:00:25

	// set network policy discovery
	Cfg.NetworkLogFrom = viper.GetString("application.network-log-from")
	Cfg.NetworkLogFile = viper.GetString("application.network-log-file") // for local testing
	Cfg.NetworkPolicyTo = viper.GetString("application.network-policy-to")
	Cfg.NetworkPolicyDir = viper.GetString("application.network-policy-dir")

	Cfg.NetPolicyTypes = viper.GetInt("application.network-policy-types")          // 3: all types
	Cfg.NetPolicyRuleTypes = viper.GetInt("application.network-policy-rule-types") // 511: all rules
	Cfg.NetPolicyCIDRBits = 32

	igNamespaces := viper.GetString("application.network-policy-ignoring-namespaces")
	IgnoringNetworkNamespaces = strings.Split(igNamespaces, "|")

	// aggregation level
	Cfg.NetPolicyL3Level = 3
	Cfg.NetPolicyL4Level = 3
	Cfg.NetPolicyL7Level = 3

	if Cfg.NetPolicyL7Level == 3 {
		HTTPUrlThreshold = 3
	} else if Cfg.NetPolicyL7Level == 2 {
		HTTPUrlThreshold = 5
	}

	// set system policy discovery
	Cfg.SystemLogFrom = viper.GetString("application.system-log-from")
	Cfg.SystemLogFile = viper.GetString("application.system-log-file")
	Cfg.SystemPolicyTo = viper.GetString("application.system-policy-to")
	Cfg.SystemPolicyDir = viper.GetString("application.system-policy-dir")

	libs.AddConfiguration(Cfg.ConfigDB, Cfg)
}

func SetLogFile(file string) {
	Cfg.NetworkLogFile = file
}

// ======================== //
// == Configuration CRUD == //
// ======================== //

func AddConfiguration(newConfig types.Configuration) error {
	return libs.AddConfiguration(Cfg.ConfigDB, newConfig)
}

func GetConfigurations(configName string) ([]types.Configuration, error) {
	return libs.GetConfigurations(Cfg.ConfigDB, configName)
}

func UpdateConfiguration(configName string, updateConfig types.Configuration) error {
	return libs.UpdateConfiguration(Cfg.ConfigDB, configName, updateConfig)
}

func DeleteConfiguration(configName string) error {
	return libs.DeleteConfiguration(Cfg.ConfigDB, configName)
}

func ApplyConfiguration(configName string) error {
	if Cfg.ConfigName == configName {
		return errors.New("Not applied " + configName + " due to same configuration name")
	}

	if err := libs.ApplyConfiguration(Cfg.ConfigDB, Cfg.ConfigName, configName); err != nil {
		return err
	}

	appliedConfigs, err := libs.GetConfigurations(Cfg.ConfigDB, configName)
	if err != nil {
		return err
	}

	// check if db info is null
	appliedCfg := appliedConfigs[0]
	if appliedCfg.ConfigDB.DBHost == "" {
		appliedCfg.ConfigDB = Cfg.ConfigDB
	}

	// update current Cfg
	Cfg = appliedCfg

	return nil
}

// ============================ //
// == Get Configuration Info == //
// ============================ //

func GetCfgDB() types.ConfigDB {
	return Cfg.ConfigDB
}

func GetCfgOneTime() string {
	return Cfg.OneTimeJobTimeSelection
}

func GetCfgCronJobTime() string {
	return Cfg.CronJobTimeInterval
}

func GetCfgOperationMode() int {
	return Cfg.OperationMode
}

func GetCfgNetworkLogFrom() string {
	return Cfg.NetworkLogFrom
}

func GetCfgNetworkLogFile() string {
	return Cfg.NetworkLogFile
}

func GetCfgCiliumHubble() types.ConfigCiliumHubble {
	return Cfg.ConfigCiliumHubble
}

func GetCfgNetworkPolicyTo() string {
	return Cfg.NetworkPolicyTo
}

func GetCfgCIDRBits() int {
	return Cfg.NetPolicyCIDRBits
}

func GetCfgNetworkPolicyTypes() int {
	return Cfg.NetPolicyTypes
}

func GetCfgNetworkRuleTypes() int {
	return Cfg.NetPolicyRuleTypes
}

func GetCfgNetworkL3Level() int {
	return Cfg.NetPolicyL3Level
}

func GetCfgNetworkL4Level() int {
	return Cfg.NetPolicyL4Level
}

func GetCfgNetworkL7Level() int {
	return Cfg.NetPolicyL7Level
}

func GetCfgNetworkHTTPThreshold() int {
	return HTTPUrlThreshold
}

func GetCfgNetworkSkipNamespaces() []string {
	return IgnoringNetworkNamespaces
}

func GetCfgNetworkIgnoreFlows() []types.IgnoringFlows {
	return Cfg.NetPolicyIgnoringFlows
}

func GetCfgSystemLogFrom() string {
	return Cfg.SystemLogFrom
}

func GetCfgSystemLogFile() string {
	return Cfg.SystemLogFile
}

func GetCfgSystemPolicyTo() string {
	return Cfg.SystemPolicyTo
}
