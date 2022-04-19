package config

import (
	"bytes"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

var MockConfigYaml = []byte(`
application:
  name: auto-policy-discovery
  network:
    operation-mode: 2
    cron-job-time-interval: "@every 0h0m10s"
    network-log-from: db
    network-log-file: "./flow.json"
    network-policy-to: "db|file"
    network-policy-dir: "./"
    network-policy-types: 3
    network-policy-rule-types: 511
    network-policy-ignoring-namespaces: "kube-system"
  system:
    system-log-from: db
    system-log-file: "./log.json"
    system-policy-to: "db|file"
    system-policy-dir: "./"
  cluster:
    #accuknox-cluster-mgmt: "http://cluster-management-service.accuknox-dev-cluster-mgmt.svc.cluster.local/cm"
    cluster-mgmt: "http://localhost:8080"

logging:
  level: INFO

feed-consumer:
  kafka:
    broker-address-family: v4
    session-timeout-ms: 6000
    auto-offset-reset: "earliest"
    bootstrap-servers: "dev-kafka-kafka-bootstrap.accuknox-dev-kafka.svc.cluster.local:9092"
    group-id: policy.cilium
    topics: 
      - cilium-telemetry-test
      - kubearmor-syslogs
    ssl:
      enabled: false
    events:
      buffer: 50

database:
  driver: sqlite3
  host: 127.0.0.1
  port: 3306
  user: root
  password: password
  dbname: networkflowdb
  table-configuration: auto_policy_config
  table-network-log: network_log
  table-network-policy: network_policy
  table-system-log: system_log
  table-system-policy: system_policy

cilium-hubble:
  url: 10.4.41.240
  port: 80

kubearmor:
  url: 10.4.41.240
  port: 8079
`)

func initMockYaml() {
	viper.SetConfigType("yaml")
	viper.ReadConfig(bytes.NewBuffer(MockConfigYaml))
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
