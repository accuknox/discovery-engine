package libs

import (
	"encoding/json"
	"fmt"
	"math/bits"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/accuknox/knoxAutoPolicy/src/plugin"
	"github.com/accuknox/knoxAutoPolicy/src/types"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"gopkg.in/yaml.v2"
)

// ============= //
// == Network == //
// ============= //

// getIPAddr Function
func getIPAddr(ifname string) string {
	if interfaces, err := net.Interfaces(); err == nil {
		for _, iface := range interfaces {
			if iface.Name == ifname {
				addrs, err := iface.Addrs()
				if err != nil {
					panic(err)
				}
				ipaddr := strings.Split(addrs[0].String(), "/")[0]
				return ipaddr
			}
		}
	}

	return "None"
}

// getExternalInterface Function
func getExternalInterface() string {
	route := GetCommandOutput("ip", []string{"route", "get", "8.8.8.8"})
	routeData := strings.Split(strings.Split(route, "\n")[0], " ")

	for idx, word := range routeData {
		if word == "dev" {
			return routeData[idx+1]
		}
	}

	return "None"
}

// GetExternalIPAddr Function
func GetExternalIPAddr() string {
	iface := getExternalInterface()
	if iface != "None" {
		return getIPAddr(iface)
	}

	return "None"
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

// ============ //
// == Common == //
// ============ //

// exists Function
func exists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return true, err
}

// IsK8sEnv Function
func IsK8sEnv() bool {
	if _, ok := os.LookupEnv("KUBERNETES_PORT"); ok {
		return true
	}

	k8sConfig := os.Getenv("HOME") + "./kube"
	if exist, _ := exists(k8sConfig); exist {
		return true
	}

	return false
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

// RandSeq Function
func RandSeq(n int) string {
	var lowerLetters = []rune("abcdefghijklmnopqrstuvwxyz")

	b := make([]rune, n)

	for i := range b {
		b[i] = lowerLetters[rand.Intn(len(lowerLetters))]
	}

	return string(b)
}

// ============== //
// == File I/O == //
// ============== //

// WriteKnoxPolicyToYamlFile Function
func WriteKnoxPolicyToYamlFile(namespace string, policies []types.KnoxNetworkPolicy) {
	outdir := GetEnv("OUT_DIR", "./")

	// create policy file
	f, err := os.Create(outdir + "knox_policies_" + namespace + "_" + strconv.Itoa(int(time.Now().Unix())) + ".yaml")
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

// WriteCiliumPolicyToYamlFile Function
func WriteCiliumPolicyToYamlFile(namespace string, policies []types.KnoxNetworkPolicy) {
	// create policy file
	outdir := GetEnv("OUT_DIR", "./")

	f, err := os.Create(outdir + "cilium_policies_" + namespace + "_" + strconv.Itoa(int(time.Now().Unix())) + ".yaml")
	if err != nil {
		fmt.Println(err)
		return
	}

	for _, policy := range policies {
		ciliumPolicy := plugin.ConvertKnoxPolicyToCiliumPolicy(policy) // if you want to convert it to Cilium policy
		b, _ := yaml.Marshal(&ciliumPolicy)
		f.Write(b)
		f.WriteString("---\n")
		f.Sync()
	}

	f.Close()
}

// WriteKnoxPolicyToJSONFile Function
func WriteKnoxPolicyToJSONFile(namespace string, policies []types.KnoxNetworkPolicy) {
	outdir := GetEnv("OUT_DIR", "./")

	// create policy file
	f, err := os.Create(outdir + "knox_policies_" + namespace + "_" + strconv.Itoa(int(time.Now().Unix())) + ".json")
	if err != nil {
		fmt.Println(err)
		return
	}

	for _, policy := range policies {
		b, _ := json.MarshalIndent(policy, "", "    ")
		f.Write(b)
		f.WriteString("\n")
		f.Sync()
	}

	f.Close()
}

// ======================= //
// == Command Execution == //
// ======================= //

// GetCommandOutput Function
func GetCommandOutput(cmd string, args []string) string {
	res := exec.Command(cmd, args...)
	out, err := res.Output()
	if err != nil {
		return ""
	}
	return string(out)
}

// ========== //
// == Time == //
// ========== //

// Time Format
const (
	TimeForm       string = "2006-01-02T15:04:05.000000"
	TimeFormSimple string = "2006-01-02 15:04:05"
	TimeFormUTC    string = "2006-01-02T15:04:05.000000Z"
	TimeFormHuman  string = "2006-01-02 15:04:05.000000"
	TimeCilium     string = "2006-01-02T15:04:05.000000000Z"
)

// ConvertUnixTSToDateTime Function
func ConvertUnixTSToDateTime(ts int64) primitive.DateTime {
	t := time.Unix(ts, 0)
	dateTime := primitive.NewDateTimeFromTime(t)
	return dateTime
}
