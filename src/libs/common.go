package libs

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"flag"
	"math/big"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"reflect"
	"strings"
	"syscall"
	"time"

	logger "github.com/accuknox/knoxAutoPolicy/src/logging"
	"github.com/accuknox/knoxAutoPolicy/src/types"
	"github.com/rs/zerolog"
	"github.com/spf13/viper"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"gopkg.in/yaml.v2"
)

var log *zerolog.Logger

var GitCommit string
var GitBranch string
var BuildDate string
var Version string

func printBuildDetails() {
	log.Info().Msgf("BUILD-INFO: commit:%v, branch: %v, date: %v, version: %v",
		GitCommit, GitBranch, BuildDate, Version)
}

func init() {
	log = logger.GetInstance()
	printBuildDetails()
}

// =================== //
// == Configuration == //
// =================== //

func LoadConfigurationFile() {
	version1 := flag.Bool("v", false, "print version and exit")
	version2 := flag.Bool("version", false, "print version and exit")

	configFilePath := flag.String("config-path", "conf/", "conf/")
	flag.Parse()

	if *version1 || *version2 {
		os.Exit(0)
	}

	viper.SetConfigName(GetEnv("CONF_FILE_NAME", "conf"))
	viper.SetConfigType("yaml")
	viper.AddConfigPath(*configFilePath)
	if err := viper.ReadInConfig(); err != nil {
		if readErr, ok := err.(viper.ConfigFileNotFoundError); ok {
			var log *zerolog.Logger = logger.GetInstance()
			log.Panic().Msgf("No config file found at %s\n", *configFilePath)
		} else {
			var log *zerolog.Logger = logger.GetInstance()
			log.Panic().Msgf("Error reading config file: %s\n", readErr)
		}
	}
}

// ================== //
// == Print Pretty == //
// ================== //

func PrintPolicyJSON(data interface{}) (string, error) {
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

func PrintPolicyYaml(data interface{}) (string, error) {
	b, _ := yaml.Marshal(&data)
	return string(b), nil
}

// ============= //
// == Network == //
// ============= //

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

func GetExternalInterface() string {
	route := GetCommandOutput("ip", []string{"route"})
	routeData := strings.Split(strings.Split(route, "\n")[0], " ")

	for idx, word := range routeData {
		if word == "dev" {
			return routeData[idx+1]
		}
	}

	return "None"
}

func GetExternalIPAddr() string {
	iface := GetExternalInterface()
	if iface != "None" {
		return getIPAddr(iface)
	}

	return "None"
}

func GetProtocol(protocol int) string {
	protocolMap := map[int]string{
		1:   "ICMP",
		6:   "TCP",
		17:  "UDP",
		132: "STCP",
	}

	return protocolMap[protocol]
}

// ============ //
// == Common == //
// ============ //

func DeepCopy(dst, src interface{}) {
	byt, err := json.Marshal(src)
	if err != nil {
		log.Error().Msg(err.Error())
	}

	if err := json.Unmarshal(byt, dst); err != nil {
		log.Error().Msg(err.Error())
	}
}

// src map[string]interface{} -> dst types.StructureExample
// usage: MapToStructure(src, &dst)
func MapToStructure(src interface{}, dst interface{}) error {
	b, err := json.Marshal(src)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, dst); err != nil {
		return err
	}
	return nil
}

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

func GetEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}

	return fallback
}

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

func RandSeq(n int) string {
	var lowerLetters = []rune("abcdefghijklmnopqrstuvwxyz")

	b := make([]rune, n)

	for i := range b {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(lowerLetters))))
		if err != nil {
			log.Error().Msg(err.Error())
		}
		b[i] = lowerLetters[n.Int64()]
	}

	return string(b)
}

func GetCommandOutput(cmd string, args []string) string {
	res := exec.Command(cmd, args...)
	out, err := res.Output()
	if err != nil {
		return ""
	}
	return string(out)
}

// ============== //
// == File I/O == //
// ============== //

func writeYamlByte(f *os.File, b []byte) {
	if _, err := f.Write(b); err != nil {
		log.Error().Msg(err.Error())
	}

	if _, err := f.WriteString("---\n"); err != nil {
		log.Error().Msg(err.Error())
	}

	if err := f.Sync(); err != nil {
		log.Error().Msg(err.Error())
	}
}

func WriteKnoxNetPolicyToYamlFile(namespace string, policies []types.KnoxNetworkPolicy) {
	fileName := GetEnv("POLICY_DIR", "./")
	if namespace != "" {
		fileName = fileName + "knox_net_policies_" + namespace + ".yaml"
	} else {
		fileName = fileName + "knox_net_policies.yaml"
	}

	if err := os.Remove(fileName); err != nil {
		if !strings.Contains(err.Error(), "no such file or directory") {
			log.Error().Msg(err.Error())
		}
	}

	// create policy file
	f, err := os.OpenFile(fileName, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		log.Error().Msg(err.Error())
		return
	}

	for i, policy := range policies {
		// set flow ids null
		policy.FlowIDs = nil

		b, err := yaml.Marshal(&policies[i])
		if err != nil {
			log.Error().Msg(err.Error())
		}
		writeYamlByte(f, b)
	}

	if err := f.Close(); err != nil {
		log.Error().Msg(err.Error())
	}
}

func WriteCiliumPolicyToYamlFile(namespace string, policies []types.CiliumNetworkPolicy) {
	fileName := GetEnv("POLICY_DIR", "./")
	if namespace != "" {
		fileName = fileName + "cilium_policies_" + namespace + ".yaml"
	} else {
		fileName = fileName + "cilium_policies.yaml"
	}

	if err := os.Remove(fileName); err != nil {
		if !strings.Contains(err.Error(), "no such file or directory") {
			log.Error().Msg(err.Error())
		}
	}

	f, err := os.OpenFile(fileName, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		log.Error().Msg(err.Error())
		return
	}

	for i := range policies {
		b, err := yaml.Marshal(&policies[i])
		if err != nil {
			log.Error().Msg(err.Error())
		}
		writeYamlByte(f, b)
	}

	if err := f.Close(); err != nil {
		log.Error().Msg(err.Error())
	}
}

func WriteKubeArmorPolicyToYamlFile(namespace string, policies []types.KubeArmorPolicy) {
	fileName := GetEnv("POLICY_DIR", "./")
	if namespace != "" {
		fileName = fileName + "kubearmor_policies_" + namespace + ".yaml"
	} else {
		fileName = fileName + "kubearmor_policies.yaml"
	}

	if err := os.Remove(fileName); err != nil {
		if !strings.Contains(err.Error(), "no such file or directory") {
			log.Error().Msg(err.Error())
		}
	}

	f, err := os.OpenFile(fileName, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		log.Error().Msg(err.Error())
		return
	}

	for i := range policies {
		b, err := yaml.Marshal(&policies[i])
		if err != nil {
			log.Error().Msg(err.Error())
		}
		writeYamlByte(f, b)
	}

	if err := f.Close(); err != nil {
		log.Error().Msg(err.Error())
	}
}

// ========== //
// == Time == //
// ========== //

const (
	TimeForm       string = "2006-01-02T15:04:05.000000"
	TimeFormSimple string = "2006-01-02 15:04:05"
	TimeFormUTC    string = "2006-01-02T15:04:05.000000Z"
	TimeFormHuman  string = "2006-01-02 15:04:05.000000"
	TimeCilium     string = "2006-01-02T15:04:05.000000000Z"
)

func ConvertUnixTSToDateTime(ts int64) primitive.DateTime {
	t := time.Unix(ts, 0)
	dateTime := primitive.NewDateTimeFromTime(t)
	return dateTime
}

func ConvertStrToUnixTime(strTime string) int64 {
	if strTime == "now" {
		return time.Now().UTC().Unix()
	}

	t, _ := time.Parse(TimeFormSimple, strTime)
	return t.UTC().Unix()
}
