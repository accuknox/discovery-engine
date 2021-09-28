package libs

import (
	"encoding/json"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/accuknox/knoxAutoPolicy/src/types"
	"github.com/stretchr/testify/assert"
)

const Unmet = "unmet expectation error: "

// ================= //
// == Network Log == //
// ================= //

func TestGetNetworkLogsFromDB(t *testing.T) {
	// prepare mock mysql
	_, mock := NewMock()

	rows := mock.NewRows([]string{
		"id",                // int
		"time",              // int
		"cluster_name",      // str
		"traffic_direction", // str
		"verdict",           // str
		"policy_match_type", // int
		"drop_reason",       // int
		"event_type",        // []byte
		"source",            // []byte
		"destination",       // []byte
		"ip",                // []byte
		"l4",                // []byte
		"l7"}).              // []byte
		AddRow(1, 0, "", "", "", 0, 0, []byte{}, []byte{}, []byte{}, []byte{}, []byte{}, []byte{})

	mock.ExpectQuery("^SELECT (.+) FROM network_log*").
		WithArgs(0, 100).
		WillReturnRows(rows)

	results := GetNetworkLogsFromDB(types.ConfigDB{DBDriver: "mysql", TableNetworkLog: "network_log"}, "", 0, 100)
	assert.Equal(t, results[0]["id"], uint32(1))

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unmet expectation error: %s", err)
	}
}

func TestInsertNetworkLogToDB(t *testing.T) {
	// prepare mock mysql
	_, mock := NewMock()

	prep := mock.ExpectPrepare("INSERT INTO network_log")
	prep.ExpectExec().
		WithArgs(
			1616387100,
			"test",
			"",
			0,
			"null",
			"null",
			"null",
			"null",
			false,
			"null",
			"null",
			"",
			"",
			"null",
			"null",
			"null",
			"",
			0,
			"",
			"",
		).WillReturnResult(sqlmock.NewResult(0, 1))

	nfe := []types.NetworkLogEvent{
		types.NetworkLogEvent{
			Time:        "2021-03-22T04:25:00.169452145Z",
			ClusterName: "test",
		},
	}

	err := InsertNetworkLogToDB(types.ConfigDB{DBDriver: "mysql", TableNetworkLog: "network_log"}, nfe)
	assert.NoError(t, err)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf(Unmet+"%s", err)
	}
}

// ==================== //
// == Network Policy == //
// ==================== //

func TestGetNetworkPolicies(t *testing.T) {
	// prepare mock mysql
	_, mock := NewMock()

	specPtr := &types.Spec{}
	spec, _ := json.Marshal(specPtr)

	flowIDsPrt := &[]string{}
	flowID, _ := json.Marshal(flowIDsPrt)

	rows := mock.NewRows([]string{
		"apiVersion",    // str
		"kind",          // str
		"flow_ids",      // []byte
		"name",          // str
		"cluster_name",  // str
		"namespace",     // str
		"type",          // str
		"rule",          // str
		"status",        // str
		"outdated",      // str
		"spec",          // []byte
		"generatedTime", // int
	}).
		AddRow("", "test", flowID, "", "", "", "", "", "", "", spec, 0)

	mock.ExpectQuery("^SELECT (.+) FROM network_policy*").
		WillReturnRows(rows)

	results := GetNetworkPolicies(types.ConfigDB{DBDriver: "mysql", TableNetworkPolicy: "network_policy"}, "", "", "")
	assert.Equal(t, results[0].Kind, "test")

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf(Unmet+"%s", err)
	}
}

func TestInsertNetworkPolicies(t *testing.T) {
	// prepare mock mysql
	_, mock := NewMock()

	policy := types.KnoxNetworkPolicy{}

	specPtr := &policy.Spec
	spec, _ := json.Marshal(specPtr)

	flowIDsPrt := &policy.FlowIDs
	flowID, _ := json.Marshal(flowIDsPrt)

	prep := mock.ExpectPrepare("INSERT INTO network_policy")
	prep.ExpectExec().
		WithArgs(
			"",     // str
			"kind", // str
			flowID, // []byte
			"",     // str
			"",     // str
			"",     // str
			"",     // str
			"",     // str
			"",     // str
			"",     // str
			spec,   // []byte
			0,      // int
		).WillReturnResult(sqlmock.NewResult(0, 1))

	nfe := []types.KnoxNetworkPolicy{
		types.KnoxNetworkPolicy{
			Kind: "kind",
		},
	}

	err := InsertNetworkPoliciesToMySQL(types.ConfigDB{DBDriver: "mysql", TableNetworkPolicy: "network_policy"}, nfe)
	assert.NoError(t, err)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf(Unmet+"%s", err)
	}
}
