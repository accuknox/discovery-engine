package libs

import (
	"net"
	"reflect"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
)

func TestGetExternalIPAddr(t *testing.T) {
	actual := GetExternalIPAddr()

	if actual != "None" && net.ParseIP(actual) == nil {
		t.Error("Wrong result ", actual)
	}
}

func TestGetProtocol(t *testing.T) {
	actual := GetProtocol(1)

	assert.Equal(t, "icmp", actual, "they should be equal")
}

func TestGetEnv(t *testing.T) {
	actual := GetEnv("KNOX_UNIT_TEST_GET_ENV", "fallback")

	assert.Equal(t, "fallback", actual, "they should be equal")
}

func TestContainsElement(t *testing.T) {
	elements := []string{"a", "b", "c"}
	element := "c"

	assert.True(t, ContainsElement(elements, element), "it should contain the element 'c'")
}

func TestCombinations(t *testing.T) {
	elements := []string{"a", "b", "c"}

	actual := Combinations(elements, 2)
	expected := [][]string{{"a", "b"}, {"a", "c"}, {"b", "c"}}

	if !cmp.Equal(actual, expected) {
		t.Error("Wrong result ", expected, actual)
	}
}

func TestRandSeq(t *testing.T) {
	actual := RandSeq(5)

	if len(actual) != 5 && reflect.TypeOf(actual).Kind() != reflect.String {
		t.Error("Wrong result ", actual)
	}
}

func TestGetCommandOutput(t *testing.T) {
	actual := GetCommandOutput("echo", []string{"test"})

	assert.Equal(t, "test\n", actual, "they should be equal")
}
