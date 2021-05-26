package config

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/accuknox/knoxAutoPolicy/src/libs"
	types "github.com/accuknox/knoxAutoPolicy/src/types"
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

	assert.NotEmpty(t, cfg.TableConfiguration, "Table configuration should not be empty")
	assert.NotEmpty(t, cfg.TableNetworkLog, "Table network_log should not be empty")
	assert.NotEmpty(t, cfg.TableNetworkPolicy, "Table network_policy should not be empty")
	assert.NotEmpty(t, cfg.TableSystemLog, "Table system_log should not be empty")
	assert.NotEmpty(t, cfg.TableSystemPolicy, "Table system_policy should not be empty")
}

func TestLoadConfigCiliumHubble(t *testing.T) {
	initMockYaml()

	cfg := LoadConfigCiliumHubble()

	assert.NotEmpty(t, cfg.HubbleURL, "Cilium Hubble URL should not be empty")
	assert.NotEmpty(t, cfg.HubblePort, "Cilium Hubble Port should not be empty")
}

func TestLoadDefaultConfig(t *testing.T) {
	initMockYaml()

	LoadDefaultConfig()

	assert.NotEmpty(t, Cfg.ConfigName, "Configuration name should not be empty")
	assert.NotEmpty(t, Cfg.Status, "Configuration status should not be empty")

	assert.NotEmpty(t, Cfg.ConfigDB, "Configuration DB should not be empty")
	assert.NotEmpty(t, Cfg.ConfigCiliumHubble, "Configuration Cilium Hubble should not be empty")

	assert.NotEmpty(t, Cfg.OperationMode, "Operation mode should not be empty")
	assert.NotEmpty(t, Cfg.CronJobTimeInterval, "Cron job time interval should not be empty")
	// assert.NotEmpty(t, Cfg.OneTimeJobTimeSelection, "One time job time selection should not be empty")

	assert.NotEmpty(t, Cfg.NetworkLogFrom, "Network log from should not be empty")
	assert.NotEmpty(t, Cfg.NetworkLogFile, "Network log file should not be empty")
	assert.NotEmpty(t, Cfg.NetworkPolicyTo, "Network policy to should not be empty")
	assert.NotEmpty(t, Cfg.NetworkPolicyDir, "Network policy dir should not be empty")

	assert.NotEmpty(t, Cfg.NetPolicyTypes, "Network policy types should not be empty")
	assert.NotEmpty(t, Cfg.NetPolicyRuleTypes, "Network policy rule types should not be empty")
	assert.NotEmpty(t, Cfg.NetPolicyCIDRBits, "Network Policy cidr bits should not be empty")

	assert.NotEmpty(t, Cfg.NetPolicyL3Level, "Network policy L3 level should not be empty")
	assert.NotEmpty(t, Cfg.NetPolicyL4Level, "Network policy L4 level should not be empty")
	assert.NotEmpty(t, Cfg.NetPolicyL7Level, "Network policy L7 level should not be empty")

	assert.NotEmpty(t, Cfg.SystemLogFrom, "System log from should not be empty")
	assert.NotEmpty(t, Cfg.SystemLogFile, "System log file should not be empty")
	assert.NotEmpty(t, Cfg.SystemPolicyTo, "System policy to should not be empty")
	assert.NotEmpty(t, Cfg.SystemPolicyDir, "System policy dir should not be empty")
}

func TestSetLogFile(t *testing.T) {
	SetLogFile("test_log.log")

	assert.Equal(t, Cfg.NetworkLogFile, "test_log.log", "network log file should be \"test_log.log\"")
}

func TestAddConfiguration(t *testing.T) {
	// prepare mock mysql
	_, mock := libs.NewMock()

	newCfg := types.Configuration{}
	newCfg.ConfigName = "test_config"
	newCfg.NetPolicyCIDRBits = 32

	configDBPtr := &newCfg.ConfigDB
	configDB, _ := json.Marshal(configDBPtr)

	configHubblePtr := &newCfg.ConfigCiliumHubble
	configCilium, _ := json.Marshal(configHubblePtr)

	ignoringFlowsPtr := &newCfg.NetPolicyIgnoringFlows
	ignoringFlows, _ := json.Marshal(ignoringFlowsPtr)

	prep := mock.ExpectPrepare("INSERT INTO auto_policy_config")
	prep.ExpectExec().WithArgs("test_config", 0, configDB, configCilium, 0, "", "", "", "", "", "",
		0, 0, 32, ignoringFlows, 0, 0, 0, "", "", "", "").WillReturnResult(sqlmock.NewResult(0, 1))

	// add configuration
	err := AddConfiguration(newCfg)
	assert.NoError(t, err)

	if err = mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectation error: %s", err)
	}
}

func TestGetConfigurations(t *testing.T) {
	// prepare mock mysql
	_, mock := libs.NewMock()

	testCfg := types.Configuration{}
	testCfg.ConfigName = "test_config"
	testCfg.NetPolicyCIDRBits = 32

	configDBPtr := &testCfg.ConfigDB
	configDB, _ := json.Marshal(configDBPtr)

	configHubblePtr := &testCfg.ConfigCiliumHubble
	configCilium, _ := json.Marshal(configHubblePtr)

	ignoringFlowsPtr := &testCfg.NetPolicyIgnoringFlows
	ignoringFlows, _ := json.Marshal(ignoringFlowsPtr)

	rows := mock.NewRows([]string{"id", "config_name", "status", "config_db", "config_cilium_hubble",
		"operation_mode", "cronjob_time_interval", "one_time_job_time_selection",
		"network_log_from", "network_log_file", "network_policy_to",
		"network_policy_dir", "network_policy_types", "network_policy_rule_types",
		"network_policy_cidr_bits", "network_policy_ignoring_flows", "network_policy_l3_level",
		"network_policy_l4_level", "network_policy_l7_level", "system_log_from", "system_log_file",
		"system_policy_to", "system_policy_dir"}).
		AddRow(1, "test_config", 0, configDB, configCilium, 0, "", "", "", "", "", "",
			0, 0, 32, ignoringFlows, 0, 0, 0, "", "", "", "")

	query := "SELECT (.+) FROM auto_policy_config WHERE config_name = ?"
	mock.ExpectQuery(query).WillReturnRows(rows)

	// get configuration by name
	results, err := GetConfigurations(testCfg.ConfigName)
	assert.NoError(t, err)
	assert.Equal(t, results[0].ConfigName, "test_config")

	if err = mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectation error: %s", err)
	}
}

func TestUpdateConfiguration(t *testing.T) {
	// prepare mock mysql
	_, mock := libs.NewMock()

	testCfg := types.Configuration{}
	testCfg.ConfigName = "test_config"
	testCfg.NetPolicyCIDRBits = 24

	configDBPtr := &testCfg.ConfigDB
	configDB, _ := json.Marshal(configDBPtr)

	configHubblePtr := &testCfg.ConfigCiliumHubble
	configCilium, _ := json.Marshal(configHubblePtr)

	ignoringFlowsPtr := &testCfg.NetPolicyIgnoringFlows
	ignoringFlows, _ := json.Marshal(ignoringFlowsPtr)

	prep := mock.ExpectPrepare("UPDATE auto_policy_config")
	prep.ExpectExec().WithArgs(configDB, configCilium, 0, "", "", "", "", "", "",
		0, 0, 24, ignoringFlows, 0, 0, 0, "", "", "", "", "test_config").
		WillReturnResult(sqlmock.NewResult(0, 1))

	// update configuration by name
	err := UpdateConfiguration("test_config", testCfg)
	assert.NoError(t, err)

	if err = mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectation error: %s", err)
	}
}

func TestDeleteConfiguration(t *testing.T) {
	// prepare mock mysql
	_, mock := libs.NewMock()

	testCfg := types.Configuration{}
	testCfg.ConfigName = "test_config"

	prep := mock.ExpectPrepare("DELETE FROM auto_policy_config")
	prep.ExpectExec().WithArgs("test_config").
		WillReturnResult(sqlmock.NewResult(0, 1))

	// update configuration by name
	err := DeleteConfiguration("test_config")
	assert.NoError(t, err)

	if err = mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectation error: %s", err)
	}
}
