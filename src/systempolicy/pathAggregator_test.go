package systempolicy

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

// ===================== //
// == Build Path Tree == //
// ===================== //

func TestAggregatePaths_1(t *testing.T) {
	paths := []string{"/usr/lib/python2.7/UserDict.py", "/usr/lib/python2.7/UserDict.pyo"}

	results := AggregatePaths(paths)

	assert.Equal(t, len(results), 2)
	assert.False(t, results[0].isDir)
	assert.False(t, results[1].isDir)
}

func TestAggregatePaths_2(t *testing.T) {
	paths := []string{"/usr/lib/python2.7/UserDict.py", "/usr/lib/python2.7/UserDict.pyo", "/usr/lib/python2.7/UserDict.3", "/usr/lib/python2.7/UserDict.4"}

	results := AggregatePaths(paths)

	assert.Equal(t, len(results), 1)
	assert.True(t, results[0].isDir)
}

func TestAggregatePaths_3(t *testing.T) {
	paths := []string{"/usr/lib/python2.7/", "/usr/lib/python2.8/", "/usr/lib/python2.9/", "/usr/lib/python2.10/"}

	results := AggregatePaths(paths)

	assert.Equal(t, len(results), 1)
	assert.True(t, results[0].isDir)
}

func TestAggregatePaths_4(t *testing.T) {
	paths := []string{"/usr/lib/python2.7/", "/usr/lib/python2.8/", "/usr/xyz/python2.9/", "/usr/lib/python2.10/", "/usr/lib/python2.11/"}

	results := AggregatePaths(paths)
	fmt.Println(results)

	assert.Equal(t, len(results), 2)
	assert.True(t, results[0].isDir)
	assert.False(t, results[1].isDir)
}

func TestAggregatePaths_5(t *testing.T) {
	paths := []string{"/usr/lib/python2.7/", "/usr/lib/python2.7/xyz"}

	results := AggregatePaths(paths)
	fmt.Println(results)

	assert.Equal(t, len(results), 1)
	assert.False(t, results[0].isDir)
	//	assert.True(t, results[1].isDir)
}
