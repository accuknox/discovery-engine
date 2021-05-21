package types

// ConfigDB ...
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

// ConfigCiliumHubble ...
type ConfigCiliumHubble struct {
	HubbleURL  string `json:"hubble_url,omitempty" bson:"hubble_url,omitempty"`
	HubblePort string `json:"hubble_port,omitempty" bson:"hubble_port,omitempty"`
}

// IgnoringFlows ...
type IgnoringFlows struct {
	IgSourceNamespace      string   `json:"ig_source_namespace,omitempty" bson:"ig_source_namespace,omitempty"`
	IgSourceLabels         []string `json:"ig_source_labels,omitempty" bson:"ig_source_labels,omitempty"`
	IgDestinationNamespace string   `json:"ig_destination_namespace,omitempty" bson:"ig_destination_namespace,omitempty"`
	IgDestinationLabels    []string `json:"ig_destination_labels,omitempty" bson:"ig_destination_labels,omitempty"`
	IgProtocol             string   `json:"ig_protocol,omitempty" bson:"ig_protocol,omitempty"`
	IgPortNumber           string   `json:"ig_port_number,omitempty" bson:"ig_port_number,omitempty"`
}

// Configuration ...
type Configuration struct {
	ConfigName string `json:"config_name,omitempty" bson:"config_name,omitempty"`
	Status     int    `json:"status,omitempty" bson:"status,omitempty"`

	ConfigDB           ConfigDB           `json:"config_db,omitempty" bson:"config_db,omitempty"`
	ConfigCiliumHubble ConfigCiliumHubble `json:"config_cilium_hubble,omitempty" bson:"config_cilium_hubble,omitempty"`

	OperationMode           int    `json:"operation_mode,omitempty" bson:"operation_mode,omitempty"`
	CronJobTimeInterval     string `json:"cronjob_time_interval,omitempty" bson:"cronjob_time_interval,omitempty"`
	OneTimeJobTimeSelection string `json:"one_time_job_time_selection,omitempty" bson:"one_time_job_time_selection,omitempty"`

	// network policy discovery
	NetworkLogFrom   string `json:"network_log_from,omitempty" bson:"network_log_from,omitempty"`
	NetworkLogFile   string `json:"network_log_file,omitempty" bson:"network_log_file,omitempty"`
	NetworkPolicyTo  string `json:"network_policy_to,omitempty" bson:"network_policy_to,omitempty"`
	NetworkPolicyDir string `json:"network_policy_dir,omitempty" bson:"network_policy_dir,omitempty"`

	NetPolicyTypes     int `json:"network_policy_types,omitempty" bson:"network_policy_types,omitempty"`
	NetPolicyRuleTypes int `json:"network_policy_rule_types,omitempty" bson:"network_policy_rule_types,omitempty"`

	NetPolicyCIDRBits      int             `json:"network_policy_cidrbits,omitempty" bson:"network_policy_cidrbits,omitempty"`
	NetPolicyIgnoringFlows []IgnoringFlows `json:"network_policy_ignoring_flows,omitempty" bson:"network_policy_ignoring_flows,omitempty"`

	// L3 aggregation level
	NetPolicyL3Level int `json:"network_policy_l3_level,omitempty" bson:"network_policy_l3_level,omitempty"`
	// L4 compression level
	NetPolicyL4Level int `json:"network_policy_l4_level,omitempty" bson:"network_policy_l4_level,omitempty"`
	// L7 aggregation level
	NetPolicyL7Level int `json:"network_policy_l7_level,omitempty" bson:"network_policy_l7_level,omitempty"`

	// system policy discovery
	SystemLogFrom  string `json:"system_log_from,omitempty" bson:"system_log_from,omitempty"`
	SystemLogFile  string `json:"system_log_file,omitempty" bson:"system_log_file,omitempty"`
	SystemPolicyTo string `json:"system_policy_to,omitempty" bson:"system_policy_to,omitempty"`
}
