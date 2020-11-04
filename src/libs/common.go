package libs

import (
	"fmt"
	"math/bits"
	"math/rand"
	"os"
	"os/signal"
	"reflect"
	"strconv"
	"syscall"
	"time"

	"github.com/accuknox/knoxAutoPolicy/src/types"
	"gopkg.in/yaml.v2"
)

// ============ //
// == Common == //
// ============ //

// WriteKnoxPolicyToFile Function
func WriteKnoxPolicyToFile(policies []types.KnoxNetworkPolicy) {
	// create policy file
	f, err := os.Create("./knox_policies_" + strconv.Itoa(int(time.Now().Unix())) + ".yaml")
	if err != nil {
		fmt.Println(err)
		return
	}

	for _, policy := range policies {
		b, _ := yaml.Marshal(&policy)
		f.Write(b)
		f.WriteString("---\n")
		f.Sync()
	}

	f.Close()
}

// WriteCiliumPolicyToFile Function
func WriteCiliumPolicyToFile(policies []types.KnoxNetworkPolicy) {
	// create policy file
	f, err := os.Create("./cilium_policies_" + strconv.Itoa(int(time.Now().Unix())) + ".yaml")
	if err != nil {
		fmt.Println(err)
		return
	}

	for _, policy := range policies {
		ciliumPolicy := ToCiliumNetworkPolicy(policy) // if you want to convert it to Cilium policy
		b, _ := yaml.Marshal(&ciliumPolicy)
		f.Write(b)
		f.WriteString("---\n")
		f.Sync()
	}

	f.Close()
}

// PrintPolicyYaml Function
func PrintPolicyYaml(policy types.KnoxNetworkPolicy) {
	b, _ := yaml.Marshal(&policy)
	fmt.Print(string(b))
	fmt.Println("---")
}

// PrintPolicyYaml Function
func PrintCiliumPolicyYaml(ciliumPolicy types.CiliumNetworkPolicy) {
	b, _ := yaml.Marshal(&ciliumPolicy)
	fmt.Print(string(b))
	fmt.Println("---")
}

// GetOSSigChannel Function
func GetOSSigChannel() chan os.Signal {
	c := make(chan os.Signal, 1)

	signal.Notify(c,
		syscall.SIGKILL,
		syscall.SIGHUP,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGQUIT,
		os.Interrupt)

	return c
}

// PrintSimplePolicyJson Function
func PrintSimplePolicyJson(policy types.CiliumNetworkPolicy) {
	fmt.Print(policy.Metadata["name"], "\t", policy.Spec.Selector, "\t")

	if policy.Spec.Egress != nil && len(policy.Spec.Egress) > 0 {
		fmt.Println(policy.Spec.Egress)
	} else {
		fmt.Println(policy.Spec.Ingress)
	}
}

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
