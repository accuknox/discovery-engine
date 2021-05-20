package core

import (
	"errors"
	"net"
	"strings"

	"github.com/accuknox/knoxAutoPolicy/src/libs"
	types "github.com/accuknox/knoxAutoPolicy/src/types"
	"github.com/spf13/viper"
)

// operation mode: 		   cronjob: 1
//                 		   onetime job: 2
// discovery policy types: egress only   : 1
//                         ingress only  : 2
//                         all           : 3
// discovery rule types:   matchLabels: 1
//                         toPorts    : 2
//                         toHTTPs    : 4
//                         toCIDRs    : 8
//                         toEntities : 16
//                         toServices : 32
//                         toFQDNs    : 64
//                         fromCIDRs  : 128
//                         fromEntities : 256
//                         all        : 511

// Cfg ...
var Cfg types.Configuration

// SkipNamespaces ...
var SkipNamespaces []string

// HTTPUrlThreshold ...
var HTTPUrlThreshold int

// PlugIn ...
var PlugIn string

// LoadConfigDB ...
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

	cfgDB.TableNetworkFlow = viper.GetString("database.table-network-flow")
	cfgDB.TableDiscoveredPolicies = viper.GetString("database.table-discovered-policies")
	cfgDB.TableConfiguration = viper.GetString("database.table-configuration")
	cfgDB.TableSystemLog = viper.GetString("database.table-system-log")

	PlugIn = "cilium" // for now, cilium only supported

	return cfgDB
}

// LoadConfigCiliumHubble ...
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

// LoadDefaultConfig ...
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

	// input
	Cfg.NetworkLogFrom = viper.GetString("application.network-log-from")
	Cfg.NetworkLogFile = "./flows.json" // for just local testing

	// output
	Cfg.NetworkPolicyTo = viper.GetString("application.discovered-policy-to")
	Cfg.NetworkPolicyDir = viper.GetString("application.policy-dir")

	// discovery types
	Cfg.DiscoveryPolicyTypes = viper.GetInt("application.discovery-policy-types") // 3: all types
	Cfg.DiscoveryRuleTypes = viper.GetInt("application.discovery-rule-types")     // 511: all rules

	// cidr bits
	Cfg.CIDRBits = 32

	// ignoring flows
	skipNamespacesStr := viper.GetString("application.ignoring-namespaces")
	SkipNamespaces = strings.Split(skipNamespacesStr, "|")

	// aggregation level
	Cfg.L3AggregationLevel = 3
	Cfg.L4Compression = 3
	Cfg.L7AggregationLevel = 3

	if Cfg.L7AggregationLevel == 3 {
		HTTPUrlThreshold = 3
	} else if Cfg.L7AggregationLevel == 2 {
		HTTPUrlThreshold = 5
	}

	libs.AddConfiguration(Cfg.ConfigDB, Cfg)
}

// SetLogFile for testing
func SetLogFile(file string) {
	Cfg.NetworkLogFile = file
}

// AddConfiguration function
func AddConfiguration(newConfig types.Configuration) error {
	return libs.AddConfiguration(Cfg.ConfigDB, newConfig)
}

// GetConfigurations function
func GetConfigurations(configName string) ([]types.Configuration, error) {
	return libs.GetConfigurations(Cfg.ConfigDB, configName)
}

// UpdateConfiguration function
func UpdateConfiguration(configName string, updateConfig types.Configuration) error {
	return libs.UpdateConfiguration(Cfg.ConfigDB, configName, updateConfig)
}

// DeleteConfiguration function
func DeleteConfiguration(configName string) error {
	return libs.DeleteConfiguration(Cfg.ConfigDB, configName)
}

// ApplyConfiguration ...
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
