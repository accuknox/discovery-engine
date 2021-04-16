package core

import (
	"errors"
	"net"
	"strings"

	"github.com/accuknox/knoxAutoPolicy/src/libs"
	types "github.com/accuknox/knoxAutoPolicy/src/types"
)

// Cfg ...
var Cfg types.Configuration

// SkipNamespaces ...
var SkipNamespaces []string

// HTTPUrlThreshold ...
var HTTPUrlThreshold int

// PlugIn ...
var PlugIn string

func init() {
	// initially, default -> applied
	LoadDefaultConfig()
	libs.AddConfiguration(Cfg.ConfigDB, Cfg)
}

// LoadConfigDB ...
func LoadConfigDB() types.ConfigDB {
	cfgDB := types.ConfigDB{}

	cfgDB.DBDriver = libs.GetEnv("DB_DRIVER", "mysql")
	cfgDB.DBUser = libs.GetEnv("DB_USER", "root")
	cfgDB.DBPass = libs.GetEnv("DB_PASS", "password")
	cfgDB.DBName = libs.GetEnv("DB_NAME", "flow_management")

	if libs.IsK8sEnv() {
		cfgDB.DBHost = libs.GetEnv("DB_HOST", "database.knox-auto-policy.svc.cluster.local")
		dbAddr, err := net.LookupIP(cfgDB.DBHost)
		if err == nil {
			cfgDB.DBHost = dbAddr[0].String()
		} else {
			cfgDB.DBHost = libs.GetExternalIPAddr()
		}
	} else {
		cfgDB.DBHost = libs.GetEnv("DB_HOST", "database") // for docker-compose
		dbAddr, err := net.LookupIP(cfgDB.DBHost)
		if err == nil {
			cfgDB.DBHost = dbAddr[0].String()
		} else {
			cfgDB.DBHost = libs.GetExternalIPAddr()
		}
	}
	cfgDB.DBPort = libs.GetEnv("DB_PORT", "3306")

	cfgDB.TableNetworkFlow = libs.GetEnv("TB_NETWORK_FLOW", "network_flow")
	cfgDB.TableDiscoveredPolicies = libs.GetEnv("TB_DISCOVERED_POLICIES", "discovered_policies")
	cfgDB.TableConfiguration = libs.GetEnv("TB_CONFIGURATION", "auto_policy_config")

	PlugIn = "cilium" // for now, cilium only supported

	return cfgDB
}

// LoadConfigCiliumHubble ...
func LoadConfigCiliumHubble() types.ConfigCiliumHubble {
	cfgHubble := types.ConfigCiliumHubble{}

	if libs.IsK8sEnv() {
		cfgHubble.HubbleURL = libs.GetEnv("HUBBLE_URL", "hubble-relay.cilium.svc.cluster.local")
		addr, err := net.LookupIP(cfgHubble.HubbleURL)
		if err == nil {
			cfgHubble.HubbleURL = addr[0].String()
		} else {
			cfgHubble.HubbleURL = libs.GetExternalIPAddr()
		}
	} else {
		cfgHubble.HubbleURL = libs.GetEnv("HUBBLE_URL", "127.0.0.1")
		addr, err := net.LookupIP(cfgHubble.HubbleURL)
		if err == nil {
			cfgHubble.HubbleURL = addr[0].String()
		} else {
			cfgHubble.HubbleURL = libs.GetExternalIPAddr()
		}
	}
	cfgHubble.HubblePort = libs.GetEnv("HUBBLE_PORT", "80")

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
	Cfg.OperationMode = libs.GetEnvInt("OPERATION_MODE", 1)
	Cfg.CronJobTimeInterval = libs.GetEnv("CRON_JOB_TIME_INTERVAL", "@every 0h0m5s")
	Cfg.OneTimeJobTimeSelection = "" // e.g., 2021-01-20 07:00:23|2021-01-20 07:00:25

	// input
	Cfg.NetworkLogFrom = libs.GetEnv("NETWORK_LOG_FROM", "db")
	Cfg.NetworkLogFile = libs.GetEnv("NETWORK_LOG_FILE", "./flows.json")

	// output
	Cfg.DiscoveredPolicyTo = libs.GetEnv("DISCOVERED_POLICY_TO", "db")
	Cfg.PolicyDir = libs.GetEnv("POLICY_DIR", "./")

	// discovery types
	Cfg.DiscoveryPolicyTypes = libs.GetEnvInt("DISCOVERY_POLICY_TYPES", 3) // 3: all types
	Cfg.DiscoveryRuleTypes = libs.GetEnvInt("DISCOVERY_RULE_TYPES", 511)   // 511: all rules

	// cidr bits
	Cfg.CIDRBits = 32

	// ignoring flows
	skipNamespacesStr := libs.GetEnv("IGNORING_NAMESPACES", "")
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
