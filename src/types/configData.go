package types

var MockConfigYaml = []byte(`
application:
  name: knoxautopolicy
  operation-mode: 2
  cron-job-time-interval: "@every 0h0m10s"
  network-log-from: db
  network-log-file: "./flow.json"
  network-policy-to: "db|file"
  network-policy-dir: "./"
  network-policy-types: 3
  network-policy-rule-types: 511
  network-policy-ignoring-namespaces: "kube-system"
  system-log-from: db
  system-log-file: "./log.json"
  system-policy-to: "db|file"
  system-policy-dir: "./"
  #accuknox-cluster-mgmt: "http://cluster-management-service.accuknox-dev-cluster-mgmt.svc.cluster.local/cm"
  accuknox-cluster-mgmt: "http://localhost:8080"

logging:
  level: INFO

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
  driver: mysql
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
`)

type ConfigDB struct {
	DBDriver string `json:"db_driver,omitempty" bson:"db_driver,omitempty"`
	DBHost   string `json:"db_host,omitempty" bson:"db_host,omitempty"`
	DBPort   string `json:"db_port,omitempty" bson:"db_port,omitempty"`
	DBUser   string `json:"db_user,omitempty" bson:"db_user,omitempty"`
	DBPass   string `json:"db_pass,omitempty" bson:"db_pass,omitempty"`
	DBName   string `json:"db_name,omitempty" bson:"db_name,omitempty"`

	TableConfiguration string `json:"table_auto_policy_config,omitempty" bson:"table_auto_policy_config,omitempty"`
	TableNetworkLog    string `json:"table_network_log,omitempty" bson:"table_network_log,omitempty"`
	TableNetworkPolicy string `json:"table_network_policy,omitempty" bson:"table_network_policy,omitempty"`
	TableSystemLog     string `json:"table_system_log,omitempty" bson:"table_system_log,omitempty"`
	TableSystemPolicy  string `json:"table_system_policy,omitempty" bson:"table_system_policy,omitempty"`
}

type ConfigCiliumHubble struct {
	HubbleURL  string `json:"hubble_url,omitempty" bson:"hubble_url,omitempty"`
	HubblePort string `json:"hubble_port,omitempty" bson:"hubble_port,omitempty"`
}

type IgnoringFlows struct {
	IgSourceNamespace      string   `json:"ig_source_namespace,omitempty" bson:"ig_source_namespace,omitempty"`
	IgSourceLabels         []string `json:"ig_source_labels,omitempty" bson:"ig_source_labels,omitempty"`
	IgDestinationNamespace string   `json:"ig_destination_namespace,omitempty" bson:"ig_destination_namespace,omitempty"`
	IgDestinationLabels    []string `json:"ig_destination_labels,omitempty" bson:"ig_destination_labels,omitempty"`
	IgProtocol             string   `json:"ig_protocol,omitempty" bson:"ig_protocol,omitempty"`
	IgPortNumber           string   `json:"ig_port_number,omitempty" bson:"ig_port_number,omitempty"`
}

type ConfigNetworkPolicy struct {
	OperationMode           int    `json:"operation_mode,omitempty" bson:"operation_mode,omitempty"`
	CronJobTimeInterval     string `json:"cronjob_time_interval,omitempty" bson:"cronjob_time_interval,omitempty"`
	OneTimeJobTimeSelection string `json:"one_time_job_time_selection,omitempty" bson:"one_time_job_time_selection,omitempty"`

	NetworkLogFrom   string `json:"network_log_from,omitempty" bson:"network_log_from,omitempty"`
	NetworkLogFile   string `json:"network_log_file,omitempty" bson:"network_log_file,omitempty"`
	NetworkPolicyTo  string `json:"network_policy_to,omitempty" bson:"network_policy_to,omitempty"`
	NetworkPolicyDir string `json:"network_policy_dir,omitempty" bson:"network_policy_dir,omitempty"`

	NetPolicyTypes     int `json:"network_policy_types,omitempty" bson:"network_policy_types,omitempty"`
	NetPolicyRuleTypes int `json:"network_policy_rule_types,omitempty" bson:"network_policy_rule_types,omitempty"`

	NetPolicyCIDRBits      int             `json:"network_policy_cidrbits,omitempty" bson:"network_policy_cidrbits,omitempty"`
	NetPolicyIgnoringFlows []IgnoringFlows `json:"network_policy_ignoring_flows,omitempty" bson:"network_policy_ignoring_flows,omitempty"`

	NetPolicyL3Level int `json:"network_policy_l3_level,omitempty" bson:"network_policy_l3_level,omitempty"`
	NetPolicyL4Level int `json:"network_policy_l4_level,omitempty" bson:"network_policy_l4_level,omitempty"`
	NetPolicyL7Level int `json:"network_policy_l7_level,omitempty" bson:"network_policy_l7_level,omitempty"`
}

type ConfigSystemPolicy struct {
	OperationMode           int    `json:"operation_mode,omitempty" bson:"operation_mode,omitempty"`
	CronJobTimeInterval     string `json:"cronjob_time_interval,omitempty" bson:"cronjob_time_interval,omitempty"`
	OneTimeJobTimeSelection string `json:"one_time_job_time_selection,omitempty" bson:"one_time_job_time_selection,omitempty"`

	SystemLogFrom   string `json:"system_log_from,omitempty" bson:"system_log_from,omitempty"`
	SystemLogFile   string `json:"system_log_file,omitempty" bson:"system_log_file,omitempty"`
	SystemPolicyTo  string `json:"system_policy_to,omitempty" bson:"system_policy_to,omitempty"`
	SystemPolicyDir string `json:"system_policy_dir,omitempty" bson:"system_policy_dir,omitempty"`
}

type ConfigClusterMgmt struct {
	ClusterInfoFrom string `json:"cluster_info_from,omitempty" bson:"cluster_info_from,omitempty"`
	ClusterMgmtURL  string `json:"cluster_mgmt_url,omitempty" bson:"cluster_mgmt_url,omitempty"`
}

type Configuration struct {
	ConfigName string `json:"config_name,omitempty" bson:"config_name,omitempty"`
	Status     int    `json:"status,omitempty" bson:"status,omitempty"`

	ConfigDB           ConfigDB           `json:"config_db,omitempty" bson:"config_db,omitempty"`
	ConfigCiliumHubble ConfigCiliumHubble `json:"config_cilium_hubble,omitempty" bson:"config_cilium_hubble,omitempty"`

	ConfigNetPolicy   ConfigNetworkPolicy `json:"config_network_policy,omitempty" bson:"config_network_policy,omitempty"`
	ConfigSysPolicy   ConfigSystemPolicy  `json:"config_system_policy,omitempty" bson:"config_system_policy,omitempty"`
	ConfigClusterMgmt ConfigClusterMgmt   `json:"config_cluster_mgmt,omitempty" bson:"config_cluster_mgmt,omitempty"`
}
