package types

// Config structure
type Config struct {
	Database struct {
		Driver                string `yaml:"db_driver"`
		User                  string `yaml:"db_user"`
		Password              string `yaml:"db_pass"`
		Name                  string `yaml:"db_name"`
		TableNetworkFlow      string `yaml:"db_table_network_flow"`
		TableDiscoveredPolicy string `yaml:"db_table_discovered_policy"`
	} `yaml:"knox_database"`
	PlugIn struct {
		Input  string `yaml:"input"`
		Output string `yaml:"output"`
	} `yaml:"plugin"`
	Policy struct {
		CidrBits  int    `yaml:"cidr_bits"`
		Namespace string `yaml:"namespace"`
	} `yaml:"policy"`
}
