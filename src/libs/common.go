package libs

import (
	"bytes"
	"encoding/json"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/accuknox/knoxAutoPolicy/src/types"
	"github.com/rs/zerolog/log"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"gopkg.in/yaml.v2"
)

// ====================== //
// == HTTP aggregation == //
// ====================== //

var httpMethods = []string{
	http.MethodGet,
	http.MethodHead,
	http.MethodPost,
	http.MethodPut,
	http.MethodPatch,
	http.MethodDelete,
	http.MethodConnect,
	http.MethodOptions,
	http.MethodTrace,
}

// CheckHTTPMethod Function
func CheckHTTPMethod(method string) bool {
	for _, m := range httpMethods {
		if strings.Contains(method, m) {
			return true
		}
	}

	return false
}

// CheckSpecHTTP Function
func CheckSpecHTTP(specs []string) bool {
	for _, spec := range specs {
		if CheckHTTPMethod(spec) {
			return true
		}
	}

	return false
}

// ====================== //
// == Longest Matching == //
// ====================== //

// TrimPrefix removes the longest common prefix from all provided strings
func TrimPrefix(strs []string) {
	p := Prefix(strs)
	if p == "" {
		return
	}
	for i, s := range strs {
		strs[i] = strings.TrimPrefix(s, p)
	}
}

// TrimSuffix removes the longest common suffix from all provided strings
func TrimSuffix(strs []string) {
	p := Suffix(strs)
	if p == "" {
		return
	}
	for i, s := range strs {
		strs[i] = strings.TrimSuffix(s, p)
	}
}

// Prefix returns the longest common prefix of the provided strings
func Prefix(strs []string) string {
	return longestCommonXfix(strs, true)
}

// Suffix returns the longest common suffix of the provided strings
func Suffix(strs []string) string {
	return longestCommonXfix(strs, false)
}

func longestCommonXfix(strs []string, pre bool) string {
	//short-circuit empty list
	if len(strs) == 0 {
		return ""
	}
	xfix := strs[0]
	//short-circuit single-element list
	if len(strs) == 1 {
		return xfix
	}
	//compare first to rest
	for _, str := range strs[1:] {
		xfixl := len(xfix)
		strl := len(str)
		//short-circuit empty strings
		if xfixl == 0 || strl == 0 {
			return ""
		}
		//maximum possible length
		maxl := xfixl
		if strl < maxl {
			maxl = strl
		}
		//compare letters
		if pre {
			//prefix, iterate left to right
			for i := 0; i < maxl; i++ {
				if xfix[i] != str[i] {
					xfix = xfix[:i]
					break
				}
			}
		} else {
			//suffix, iternate right to left
			for i := 0; i < maxl; i++ {
				xi := xfixl - i - 1
				si := strl - i - 1
				if xfix[xi] != str[si] {
					xfix = xfix[xi+1:]
					break
				}
			}
		}
	}
	return xfix
}

// ================== //
// == Print Pretty == //
// ================== //

// PrintKnoxPolicyJSON function
func PrintKnoxPolicyJSON(data interface{}) (string, error) {
	empty := ""
	tab := "  "

	buffer := new(bytes.Buffer)
	encoder := json.NewEncoder(buffer)
	encoder.SetIndent(empty, tab)

	err := encoder.Encode(data)
	if err != nil {
		return empty, err
	}

	return buffer.String(), nil
}

// ============= //
// == Network == //
// ============= //

// GetIPAddr Function
func GetIPAddr(ifname string) string {
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

// GetExternalInterface Function
func GetExternalInterface() string {
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
	iface := GetExternalInterface()
	if iface != "None" {
		return GetIPAddr(iface)
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

// GetProtocolInt Function
func GetProtocolInt(protocol string) int {
	protocol = strings.ToLower(protocol)
	protocolMap := map[string]int{
		"icmp": 1,
		"tcp":  6,
		"udp":  17,
		"stcp": 132,
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

// GetEnvInt Function
func GetEnvInt(key string, fallback int) int {
	result := 0

	if value, ok := os.LookupEnv(key); ok {
		val, err := strconv.Atoi(value)
		if err != nil {
			return fallback
		}
		result = val
	}

	return result
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
	fileName := GetEnv("POLICY_DIR", "./") + "knox_policies_" + namespace + ".yaml"

	os.Remove(fileName)

	// create policy file
	f, err := os.OpenFile(fileName, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Error().Msg(err.Error())
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
func WriteCiliumPolicyToYamlFile(namespace string, policies []types.CiliumNetworkPolicy) {
	// create policy file
	fileName := GetEnv("POLICY_DIR", "./") + "cilium_policies_" + namespace + ".yaml"

	os.Remove(fileName)

	f, err := os.OpenFile(fileName, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Error().Msg(err.Error())
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

// WriteKnoxPolicyToJSONFile Function
func WriteKnoxPolicyToJSONFile(namespace string, policies []types.KnoxNetworkPolicy) {
	fileName := GetEnv("POLICY_DIR", "./")

	os.Remove(fileName)

	// create policy file
	f, err := os.OpenFile(fileName, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Error().Msg(err.Error())
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

// ConvertUnixTSToDateTime Function for mongoDB
func ConvertUnixTSToDateTime(ts int64) primitive.DateTime {
	t := time.Unix(ts, 0)
	dateTime := primitive.NewDateTimeFromTime(t)
	return dateTime
}

// ConvertStrToUnixTime function: str -> unix seconds for mysql
func ConvertStrToUnixTime(strTime string) int64 {
	if strTime == "now" {
		return time.Now().UTC().Unix()
	}

	t, _ := time.Parse(TimeFormSimple, strTime)
	return t.UTC().Unix()
}
