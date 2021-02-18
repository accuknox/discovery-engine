package types

// ConfigDB ...
type ConfigDB struct {
	DBDriver string `json:"db_driver,omitempty" bson:"db_driver,omitempty"`
	DBHost   string `json:"db_host,omitempty" bson:"db_host,omitempty"`
	DBPort   string `json:"db_port,omitempty" bson:"db_port,omitempty"`
	DBUser   string `json:"db_user,omitempty" bson:"db_user,omitempty"`
	DBPass   string `json:"db_pass,omitempty" bson:"db_pass,omitempty"`
	DBName   string `json:"db_name,omitempty" bson:"db_name,omitempty"`

	TableNetworkFlow      string `json:"table_network_flow,omitempty" bson:"table_network_flow,omitempty"`
	TableDiscoveredPolicy string `json:"table_discovered_policy,omitempty" bson:"table_discovered_policy,omitempty"`
	TableConfiguration    string `json:"table_auto_policy_config,omitempty" bson:"table_auto_policy_config,omitempty"`
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

	NetworkLogFrom string `json:"network_log_from,omitempty" bson:"network_log_from,omitempty"`
	NetworkLogFile string `json:"network_log_file,omitempty" bson:"network_log_file,omitempty"`

	DiscoveredPolicyTo string `json:"discovered_policy_to,omitempty" bson:"discovered_policy_to,omitempty"`
	PolicyDir          string `json:"policy_dir,omitempty" bson:"policy_dir,omitempty"`

	DiscoveryPolicyTypes int `json:"discovery_policy_types,omitempty" bson:"discovery_policy_types,omitempty"`
	DiscoveryRuleTypes   int `json:"discovery_rule_types,omitempty" bson:"discovery_rule_types,omitempty"`

	CIDRBits      int             `json:"cidr_bits,omitempty" bson:"cidr_bits,omitempty"`
	IgnoringFlows []IgnoringFlows `json:"ignoring_flows,omitempty" bson:"ignoring_flows,omitempty"`

	L3AggregationLevel int `json:"l3_aggregation_level,omitempty" bson:"l3_aggregation_level,omitempty"`
	L4Compression      int `json:"l4_compression,omitempty" bson:"l4_compression,omitempty"`
	L7AggregationLevel int `json:"l7_aggregation_level,omitempty" bson:"l7_aggregation_level,omitempty"`
}
