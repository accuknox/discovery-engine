package libs

import (
	"net"
	"testing"

	"github.com/accuknox/knoxAutoPolicy/src/types"
	"github.com/stretchr/testify/assert"
)

// LoadMockCfgDB function
func LoadMockCfgDB() types.ConfigDB {
	cfgDB := types.ConfigDB{}
	cfgDB.DBDriver = GetEnv("DB_DRIVER", "mysql")
	cfgDB.DBUser = GetEnv("DB_USER", "root")
	cfgDB.DBPass = GetEnv("DB_PASS", "password")
	cfgDB.DBName = GetEnv("DB_NAME", "flow_management")

	if IsK8sEnv() {
		cfgDB.DBHost = GetEnv("DB_HOST", "database.knox-auto-policy.svc.cluster.local")
		dbAddr, err := net.LookupIP(cfgDB.DBHost)
		if err == nil {
			cfgDB.DBHost = dbAddr[0].String()
		} else {
			cfgDB.DBHost = GetExternalIPAddr()
		}
	} else {
		cfgDB.DBHost = GetEnv("DB_HOST", "database") // for docker-compose
		dbAddr, err := net.LookupIP(cfgDB.DBHost)
		if err == nil {
			cfgDB.DBHost = dbAddr[0].String()
		} else {
			cfgDB.DBHost = GetExternalIPAddr()
		}
	}
	cfgDB.DBPort = GetEnv("DB_PORT", "3306")

	cfgDB.TableNetworkFlow = GetEnv("TB_NETWORK_FLOW", "network_flow")
	cfgDB.TableDiscoveredPolicies = GetEnv("TB_DISCOVERED_POLICY", "discovered_policy")
	cfgDB.TableConfiguration = GetEnv("TB_CONFIGURATION", "auto_policy_config")

	ClearDBTablesMySQL(cfgDB)

	return cfgDB
}

func TestUpdateOutdatedPolicy(t *testing.T) {
	cfgDB := LoadMockCfgDB()

	outdated := "policy_a"
	latest := "policy_b"

	err := UpdateOutdatedPolicyFromMySQL(cfgDB, outdated, latest)
	assert.NoError(t, err)
}

func TestGetNetworkPolicies(t *testing.T) {
	cfgDB := LoadMockCfgDB()

	cidrPolicy := types.KnoxNetworkPolicy{
		Metadata: map[string]string{
			"cluster_name": "",
			"name":         "",
			"namespace":    "multiubuntu",
			"status":       "latest",
			"type":         "egress",
			"rule":         "toCIDRs+toPorts",
		},

		Spec: types.Spec{
			Selector: types.Selector{
				MatchLabels: map[string]string{
					"app": "test1",
				},
			},

			Egress: []types.Egress{
				types.Egress{
					ToCIDRs: []types.SpecCIDR{
						types.SpecCIDR{
							CIDRs: []string{"10.0.0.1/32"},
						},
					},
					ToPorts: []types.SpecPort{
						types.SpecPort{
							Port:     "80",
							Protocol: "tcp",
						},
					},
				},
			},
		},
	}

	discovered := []types.KnoxNetworkPolicy{cidrPolicy}

	err := InsertDiscoveredPoliciesToMySQL(cfgDB, discovered)
	assert.NoError(t, err)

	results, err := GetNetworkPoliciesFromMySQL(cfgDB, "multiubuntu", "latest")
	assert.NoError(t, err)

	assert.Equal(t, discovered, results)
}

func TestInsertDiscoveredPolicies(t *testing.T) {
	cfgDB := LoadMockCfgDB()

	cidrPolicy := types.KnoxNetworkPolicy{
		Metadata: map[string]string{
			"status": "latest",
			"type":   "egress",
			"rule":   "toCIDRs+toPorts",
		},

		Spec: types.Spec{
			Selector: types.Selector{
				MatchLabels: map[string]string{
					"app": "test1",
				},
			},

			Egress: []types.Egress{
				types.Egress{
					ToCIDRs: []types.SpecCIDR{
						types.SpecCIDR{
							CIDRs: []string{"10.0.0.1/32"},
						},
					},
					ToPorts: []types.SpecPort{
						types.SpecPort{
							Port:     "80",
							Protocol: "tcp",
						},
					},
				},
			},
		},
	}

	discovered := []types.KnoxNetworkPolicy{cidrPolicy}

	err := InsertDiscoveredPoliciesToMySQL(cfgDB, discovered)
	assert.NoError(t, err)
}
