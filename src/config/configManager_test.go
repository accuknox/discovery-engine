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

func TestLoadConfigKubeArmor(t *testing.T) {
	initMockYaml()

	cfg := LoadConfigKubeArmor()

	assert.NotEmpty(t, cfg.KubeArmorRelayURL, "KubeArmor relay URL should not be empty")
	assert.NotEmpty(t, cfg.KubeArmorRelayPort, "KubeArmor relay Port should not be empty")
}

func TestLoadDefaultConfig(t *testing.T) {
	initMockYaml()

	LoadDefaultConfig()

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

func TestAddConfiguration(t *testing.T) {
	// prepare mock mysql
	_, mock := libs.NewMock()

	newCfg := types.Configuration{}
	newCfg.ConfigName = "test_config"
	newCfg.ConfigNetPolicy.NetPolicyCIDRBits = 32

	configDBPtr := &newCfg.ConfigDB
	configDB, _ := json.Marshal(configDBPtr)

	configHubblePtr := &newCfg.ConfigCiliumHubble
	configCilium, _ := json.Marshal(configHubblePtr)

	configFilterPtr := &newCfg.ConfigNetPolicy.NetLogFilters
	configFilter, _ := json.Marshal(configFilterPtr)

	prep := mock.ExpectPrepare("INSERT INTO auto_policy_config")
	prep.ExpectExec().WithArgs(
		"test_config", //config_name
		0,             //status
		configDB,      //config_db
		configCilium,  //config_cilium_hubble
		0,             //network_operation_mode
		"",            //network_cronjob_time_interval
		"",            //network_one_time_job_time_selection
		"",            //network_log_from
		"",            //network_log_file
		"",            //network_policy_to
		"",            //network_policy_dir
		configFilter,  //network_policy_log_filters
		0,             //network_policy_types
		0,             //network_policy_rule_types
		32,            //network_policy_cidr_bits
		0,             //network_policy_l3_level
		0,             //network_policy_l4_level
		0,             //network_policy_l7_level
		0,             //system_operation_mode
		"",            //system_cronjob_time_interval
		"",            //system_one_time_job_time_selection
		"",            //system_log_from
		"",            //system_log_file
		"",            //system_policy_to
		"",            //system_policy_dir
		0,             //system_policy_types
		configFilter,  //system_policy_log_filters
		false,         //system_policy_proc_fromsource
		false,         //system_policy_file_fromsource
		"",            //cluster_info_from
		"",            //cluster_mgmt_url
	).WillReturnResult(sqlmock.NewResult(0, 1))

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
	testCfg.ConfigNetPolicy.NetPolicyCIDRBits = 32

	configDBPtr := &testCfg.ConfigDB
	configDB, _ := json.Marshal(configDBPtr)

	configHubblePtr := &testCfg.ConfigCiliumHubble
	configCilium, _ := json.Marshal(configHubblePtr)

	configKubeArmorPtr := &testCfg.ConfigKubeArmorRelay
	configKubeArmor, _ := json.Marshal(configKubeArmorPtr)

	configFilterPtr := &testCfg.ConfigNetPolicy.NetLogFilters
	configFilter, _ := json.Marshal(configFilterPtr)

	rows := mock.NewRows([]string{
		"id",
		"config_name",
		"status",
		"config_db",
		"config_cilium_hubble",
		"config_kubearmor_relay",
		"network_operation_mode",
		"network_cronjob_time_interval",
		"network_one_time_job_time_selection",
		"network_log_from",
		"network_log_file",
		"network_policy_to",
		"network_policy_dir",
		"network_policy_log_filters",
		"network_policy_types",
		"network_policy_rule_types",
		"network_policy_cidr_bits",
		"network_policy_l3_level",
		"network_policy_l4_level",
		"network_policy_l7_level",
		"system_operation_mode",
		"system_cronjob_time_interval",
		"system_one_time_job_time_selection",
		"system_log_from",
		"system_log_file",
		"system_policy_to",
		"system_policy_dir",
		"system_policy_types",
		"system_policy_log_filters",
		"system_policy_proc_fromsource",
		"system_policy_file_fromsource",
		"cluster_info_from",
		"cluster_mgmt_url"}).
		AddRow(
			1,               //id
			"test_config",   //config_name
			0,               //status
			configDB,        //config_db
			configCilium,    //config_cilium_hubble
			configKubeArmor, //config_kubearmor_relay
			0,               //network_operation_mode
			"",              //network_cronjob_time_interval
			"",              //network_one_time_job_time_selection
			"",              //network_log_from
			"",              //network_log_file
			"",              //network_policy_to
			"",              //network_policy_dir
			configFilter,    //network_policy_log_filters
			0,               //network_policy_types
			0,               //network_policy_rule_types
			32,              //network_policy_cidr_bits
			0,               //network_policy_l3_level
			0,               //network_policy_l4_level
			0,               //network_policy_l7_level
			0,               //system_operation_mode
			"",              //system_cronjob_time_interval
			"",              //system_one_time_job_time_selection
			"",              //system_log_from
			"",              //system_log_file
			"",              //system_policy_to
			"",              //system_policy_dir
			0,               //system_policy_types
			configFilter,    //system_policy_log_filters
			false,           //system_policy_proc_fromsource
			false,           //system_policy_file_fromsource
			"",              //cluster_info_from
			"",              //cluster_mgmt_url
		)

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
	testCfg.ConfigNetPolicy.NetPolicyCIDRBits = 24

	configDBPtr := &testCfg.ConfigDB
	configDB, _ := json.Marshal(configDBPtr)

	configHubblePtr := &testCfg.ConfigCiliumHubble
	configCilium, _ := json.Marshal(configHubblePtr)

	configFilterPtr := &testCfg.ConfigNetPolicy.NetLogFilters
	configFilter, _ := json.Marshal(configFilterPtr)

	prep := mock.ExpectPrepare("UPDATE auto_policy_config")
	prep.ExpectExec().WithArgs(
		configDB,      //config_db
		configCilium,  //config_cilium_hubble
		0,             //network_operation_mode
		"",            //network_cronjob_time_interval
		"",            //network_one_time_job_time_selection
		"",            //network_log_from
		"",            //network_log_file
		"",            //network_policy_to
		"",            //network_policy_dir
		configFilter,  //network_policy_log_filters
		0,             //network_policy_types
		0,             //network_policy_rule_types
		24,            //network_policy_cidr_bits
		0,             //network_policy_l3_level
		0,             //network_policy_l4_level
		0,             //network_policy_l7_level
		0,             //system_operation_mode
		"",            //system_cronjob_time_interval
		"",            //system_one_time_job_time_selection
		"",            //system_log_from
		"",            //system_log_file
		"",            //system_policy_to
		"",            //system_policy_dir
		0,             //system_policy_types
		configFilter,  //system_policy_log_filters
		false,         //system_policy_proc_fromsource
		false,         //system_policy_file_fromsource
		"",            //cluster_info_from
		"",            //cluster_mgmt_url).
		"test_config", //config_name
	).WillReturnResult(sqlmock.NewResult(0, 1))

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
