package libs

import (
	"encoding/json"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/accuknox/auto-policy-discovery/src/types"
	"github.com/stretchr/testify/assert"
)

const Unmet = "unmet expectation error: "

// ================= //
// == Network Log == //
// ================= //

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

	results := GetNetworkPolicies(types.ConfigDB{DBDriver: "mysql"}, "", "", "", "", "")
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

	err := InsertNetworkPoliciesToMySQL(types.ConfigDB{DBDriver: "mysql"}, nfe)
	assert.NoError(t, err)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf(Unmet+"%s", err)
	}
}

func TestGetNetworkPoliciesSQLite(t *testing.T) {
	// prepare mock sqlite
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

	results := GetNetworkPolicies(types.ConfigDB{DBDriver: "sqlite3"}, "", "", "")
	assert.Equal(t, results[0].Kind, "test")

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf(Unmet+"%s", err)
	}
}

func TestInsertNetworkPoliciesSQLite(t *testing.T) {
	// prepare mock sqlite
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

	err := InsertNetworkPoliciesToSQLite(types.ConfigDB{DBDriver: "sqlite3"}, nfe)
	assert.NoError(t, err)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf(Unmet+"%s", err)
	}
}
