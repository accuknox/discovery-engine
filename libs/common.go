package libs

import (
	"math/bits"
	"math/rand"
	"os"
	"reflect"
)

// ============ //
// == Common == //
// ============ //

// GetEnv Function
func GetEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

// ContainsElement Function
func ContainsElement(slice interface{}, element interface{}) bool {
	switch reflect.TypeOf(slice).Kind() {
	case reflect.Slice:
		s := reflect.ValueOf(slice)

		for i := 0; i < s.Len(); i++ {
			val := s.Index(i).Interface()
			if reflect.DeepEqual(val, element) {
				return true
			}
		}
	}

	return false
}

// Combinations Function
func Combinations(set []string, n int) (subsets [][]string) {
	length := uint(len(set))

	if n > len(set) {
		n = len(set)
	}

	// Go through all possible combinations of objects
	// from 1 (only first object in subset) to 2^length (all objects in subset)
	for subsetBits := 1; subsetBits < (1 << length); subsetBits++ {
		if n > 0 && bits.OnesCount(uint(subsetBits)) != n {
			continue
		}

		var subset []string

		for object := uint(0); object < length; object++ {
			// checks if object is contained in subset
			// by checking if bit 'object' is set in subsetBits
			if (subsetBits>>object)&1 == 1 {
				// add object to subset
				subset = append(subset, set[object])
			}
		}
		// add subset to subsets
		subsets = append(subsets, subset)
	}
	return subsets
}

var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
var LowerLetters = []rune("abcdefghijklmnopqrstuvwxyz")

// RandSeq Function
func RandSeq(n int) string {
	b := make([]rune, n)

	for i := range b {
		b[i] = letters[rand.Intn(len(LowerLetters))]
	}

	return string(b)
}

// GetProtocol Function
func GetProtocol(protocol int) string {
	protocolMap := map[int]string{
		1:   "icmp",
		6:   "tcp",
		17:  "udp",
		132: "stcp",
	}

	return protocolMap[protocol]
}
