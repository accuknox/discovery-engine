package libs

import (
	"encoding/json"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/accuknox/auto-policy-discovery/src/types"
	"github.com/stretchr/testify/assert"
)

const Unmet = "unmet expectation error: "

func newMockDB() {
	db, mock, err := sqlmock.New()
	if err != nil {
		log.Error().Msgf("an error '%s' was not expected when opening a stub database connection", err)
	}

	MockSql = mock
	MockDB = db
}

// ==================== //
// == Network Policy == //
// ==================== //

func TestGetNetworkPolicies(t *testing.T) {
	// prepare mock mysql
	newMockDB()

	specPtr := &types.Spec{}
	spec, _ := json.Marshal(specPtr)

	flowIDsPrt := &[]string{}
	flowID, _ := json.Marshal(flowIDsPrt)

	rows := MockSql.NewRows([]string{
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
		"generatedTime", // uint64
		"updatedTime",   // uint64
	}).
		AddRow("", "test", flowID, "", "", "", "", "", "", "", spec, 0, 0)

	MockSql.ExpectQuery("^SELECT (.+) FROM network_policy*").
		WillReturnRows(rows)

	results := GetNetworkPolicies(types.ConfigDB{DBDriver: "mysql"}, "", "", "", "", "")
	assert.Equal(t, results[0].Kind, "test")

	if err := MockSql.ExpectationsWereMet(); err != nil {
		t.Errorf(Unmet+"%s", err)
	}
}

func TestInsertNetworkPolicies(t *testing.T) {
	// prepare mock mysql
	newMockDB()

	policy := types.KnoxNetworkPolicy{}

	specPtr := &policy.Spec
	spec, _ := json.Marshal(specPtr)

	flowIDsPrt := &policy.FlowIDs
	flowID, _ := json.Marshal(flowIDsPrt)

	prep := MockSql.ExpectPrepare("INSERT INTO network_policy")
	prep.ExpectExec().
		WithArgs(
			"",               // str
			"kind",           // str
			flowID,           // []byte
			"",               // str
			"",               // str
			"",               // str
			"",               // str
			"",               // str
			"",               // str
			"",               // str
			spec,             // []byte
			sqlmock.AnyArg(), // uint64
			sqlmock.AnyArg(), // uint64
		).WillReturnResult(sqlmock.NewResult(0, 1))

	nfe := []types.KnoxNetworkPolicy{
		types.KnoxNetworkPolicy{
			Kind: "kind",
		},
	}

	err := InsertNetworkPoliciesToMySQL(types.ConfigDB{DBDriver: "mysql"}, nfe)
	assert.NoError(t, err)

	if err := MockSql.ExpectationsWereMet(); err != nil {
		t.Errorf(Unmet+"%s", err)
	}
}

func TestInsertNetworkPoliciesSQLite(t *testing.T) {
	// prepare mock sqlite
	newMockDB()

	policy := types.KnoxNetworkPolicy{}

	specPtr := &policy.Spec
	spec, _ := json.Marshal(specPtr)

	flowIDsPrt := &policy.FlowIDs
	flowID, _ := json.Marshal(flowIDsPrt)

	prep := MockSql.ExpectPrepare("INSERT INTO network_policy")
	prep.ExpectExec().
		WithArgs(
			"",               // str
			"kind",           // str
			flowID,           // []byte
			"",               // str
			"",               // str
			"",               // str
			"",               // str
			"",               // str
			"",               // str
			"",               // str
			spec,             // []byte
			sqlmock.AnyArg(), // uint64
			sqlmock.AnyArg(), // uint64
		).WillReturnResult(sqlmock.NewResult(0, 1))

	nfe := []types.KnoxNetworkPolicy{
		types.KnoxNetworkPolicy{
			Kind: "kind",
		},
	}

	err := InsertNetworkPoliciesToSQLite(types.ConfigDB{DBDriver: "sqlite3"}, nfe)
	assert.NoError(t, err)

	if err := MockSql.ExpectationsWereMet(); err != nil {
		t.Errorf(Unmet+"%s", err)
	}
}
