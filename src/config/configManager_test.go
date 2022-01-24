package config

import (
	"bytes"
	"testing"

	types "github.com/accuknox/auto-policy-discovery/src/types"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func initMockYaml() {
	viper.SetConfigType("yaml")
	viper.ReadConfig(bytes.NewBuffer(types.MockConfigYaml))
}

func TestLoadConfigDB(t *testing.T) {
	initMockYaml()

	cfg := LoadConfigDB()

	assert.NotEmpty(t, cfg.DBDriver, "DB driver should not be empty")
	assert.NotEmpty(t, cfg.DBUser, "DB user should not be empty")
	assert.NotEmpty(t, cfg.DBPass, "DB pass should not be empty")
	assert.NotEmpty(t, cfg.DBName, "DB name should not be empty")
	assert.NotEmpty(t, cfg.DBHost, "DB host should not be empty")
	assert.NotEmpty(t, cfg.DBPort, "DB host should not be empty")

	assert.NotEmpty(t, cfg.TableNetworkLog, "Table network_log should not be empty")
	// assert.NotEmpty(t, cfg.TableNetworkPolicy, "Table network_policy should not be empty")
	assert.NotEmpty(t, cfg.TableSystemLog, "Table system_log should not be empty")
	// assert.NotEmpty(t, cfg.TableSystemPolicy, "Table system_policy should not be empty")
}

func TestLoadConfigCiliumHubble(t *testing.T) {
	initMockYaml()

	cfg := LoadConfigCiliumHubble()

	assert.NotEmpty(t, cfg.HubbleURL, "Cilium Hubble URL should not be empty")
	assert.NotEmpty(t, cfg.HubblePort, "Cilium Hubble Port should not be empty")
}

func TestLoadConfigKubeArmor(t *testing.T) {
	initMockYaml()

	cfg := LoadConfigKubeArmor()

	assert.NotEmpty(t, cfg.KubeArmorRelayURL, "KubeArmor relay URL should not be empty")
	assert.NotEmpty(t, cfg.KubeArmorRelayPort, "KubeArmor relay Port should not be empty")
}

func TestLoadDefaultConfig(t *testing.T) {
	initMockYaml()

	LoadConfigFromFile()

	assert.NotEmpty(t, CurrentCfg.ConfigName, "Configuration name should not be empty")
	assert.NotEmpty(t, CurrentCfg.Status, "Configuration status should not be empty")

	assert.NotEmpty(t, CurrentCfg.ConfigDB, "Configuration DB should not be empty")
	assert.NotEmpty(t, CurrentCfg.ConfigCiliumHubble, "Configuration Cilium Hubble should not be empty")

	assert.NotEmpty(t, CurrentCfg.ConfigNetPolicy.OperationMode, "Operation mode should not be empty")
	assert.NotEmpty(t, CurrentCfg.ConfigNetPolicy.CronJobTimeInterval, "Cron job time interval should not be empty")
	// assert.NotEmpty(t, Cfg.OneTConfigNetPolicy.imeJobTimeSelection, "One time job time selection should not be empty")

	assert.NotEmpty(t, CurrentCfg.ConfigNetPolicy.NetworkLogFrom, "Network log from should not be empty")
	assert.NotEmpty(t, CurrentCfg.ConfigNetPolicy.NetworkLogFile, "Network log file should not be empty")
	assert.NotEmpty(t, CurrentCfg.ConfigNetPolicy.NetworkPolicyTo, "Network policy to should not be empty")
	assert.NotEmpty(t, CurrentCfg.ConfigNetPolicy.NetworkPolicyDir, "Network policy dir should not be empty")

	assert.NotEmpty(t, CurrentCfg.ConfigNetPolicy.NetPolicyTypes, "Network policy types should not be empty")
	assert.NotEmpty(t, CurrentCfg.ConfigNetPolicy.NetPolicyRuleTypes, "Network policy rule types should not be empty")
	assert.NotEmpty(t, CurrentCfg.ConfigNetPolicy.NetPolicyCIDRBits, "Network Policy cidr bits should not be empty")

	assert.NotEmpty(t, CurrentCfg.ConfigNetPolicy.NetPolicyL3Level, "Network policy L3 level should not be empty")
	assert.NotEmpty(t, CurrentCfg.ConfigNetPolicy.NetPolicyL4Level, "Network policy L4 level should not be empty")
	assert.NotEmpty(t, CurrentCfg.ConfigNetPolicy.NetPolicyL7Level, "Network policy L7 level should not be empty")

	assert.NotEmpty(t, CurrentCfg.ConfigSysPolicy.SystemLogFrom, "System log from should not be empty")
	assert.NotEmpty(t, CurrentCfg.ConfigSysPolicy.SystemLogFile, "System log file should not be empty")
	assert.NotEmpty(t, CurrentCfg.ConfigSysPolicy.SystemPolicyTo, "System policy to should not be empty")
	assert.NotEmpty(t, CurrentCfg.ConfigSysPolicy.SystemPolicyDir, "System policy dir should not be empty")
}

func TestSetLogFile(t *testing.T) {
	SetLogFile("test_log.log")

	assert.Equal(t, CurrentCfg.ConfigNetPolicy.NetworkLogFile, "test_log.log", "network log file should be \"test_log.log\"")
}
