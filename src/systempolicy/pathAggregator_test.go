package systempolicy

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// ===================== //
// == Build Path Tree == //
// ===================== //

func TestAggregatePaths(t *testing.T) {
	paths := []string{"/usr/lib/python2.7/UserDict.py", "/usr/lib/python2.7/UserDict.pyo"}

	results := AggregatePaths(paths)

	assert.Equal(t, len(results), 2)
	assert.False(t, results[0].isDir)
	assert.False(t, results[1].isDir)
}
