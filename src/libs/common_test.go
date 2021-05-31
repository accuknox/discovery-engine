package libs

import (
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// ============= //
// == Network == //
// ============= //

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

// ============ //
// == Common == //
// ============ //

func TestGetEnv(t *testing.T) {
	actual := GetEnv("KNOX_UNIT_TEST_GET_ENV", "fallback")

	assert.Equal(t, "fallback", actual, "they should be equal")
}

func TestContainsElement(t *testing.T) {
	elements := []string{"a", "b", "c"}
	element := "c"

	assert.True(t, ContainsElement(elements, element), "it should contain the element 'c'")
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

// ========== //
// == Time == //
// ========== //

func TestConvertUnixTSToDateTime(t *testing.T) {
	actual := ConvertUnixTSToDateTime(100)

	assert.Equal(t, primitive.NewDateTimeFromTime(time.Unix(100, 0)), actual, "they should be equal")
}
