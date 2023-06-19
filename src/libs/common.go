package libs

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/clarketm/json"

	"net/http"
	"net/http/pprof"

	cfg "github.com/accuknox/auto-policy-discovery/src/config"
	logger "github.com/accuknox/auto-policy-discovery/src/logging"
	"github.com/accuknox/auto-policy-discovery/src/types"
	"github.com/rs/zerolog"
	"github.com/spf13/viper"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"sigs.k8s.io/yaml"
)

var log *zerolog.Logger

const NoSuchFileOrDir = "no such file or directory"

var GitCommit string
var GitBranch string
var BuildDate string
var Version string

const (
	IPProtoUnknown   = -1
	IPProtocolICMP   = 1
	IPProtocolTCP    = 6
	IPProtocolUDP    = 17
	IPProtocolICMPv6 = 58
	IPProtocolSCTP   = 132
)

const (
	L7ProtocolDNS  = "dns"
	L7ProtocolHTTP = "http"
)

var protocolMap = map[int]string{
	IPProtoUnknown:   "Unknown",
	IPProtocolICMP:   "ICMP",
	IPProtocolTCP:    "TCP",
	IPProtocolUDP:    "UDP",
	IPProtocolICMPv6: "ICMPv6",
	IPProtocolSCTP:   "SCTP",
}

// Array for ICMP type which can be considered as ICMP reply packets.
// TODO: Identity all the ICMP reply types
var ICMPReplyType = []int{
	0, // EchoReply
}

func printBuildDetails() {
	if GitCommit == "" {
		return
	}
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

func SetDefaultConfig() {

	// Observability module
	viper.SetDefault("observability", false)

	// Application->Network config
	viper.SetDefault("application.network.operation-mode", 1)
	viper.SetDefault("application.network.operation-trigger", 100)
	viper.SetDefault("application.network.cron-job-time-interval", "0h0m10s")
	viper.SetDefault("application.network.network-log-limit", 10000)
	viper.SetDefault("application.network.network-log-from", "hubble")
	viper.SetDefault("application.network.network-policy-to", "db|file")
	viper.SetDefault("application.network.network-policy-dir", "./")
	viper.SetDefault("application.network.skip-cert-verification", true)

	// Application->System config
	viper.SetDefault("application.system.operation-mode", 1)
	viper.SetDefault("application.system.operation-trigger", 10)
	viper.SetDefault("application.system.cron-job-time-interval", "0h0m10s")
	viper.SetDefault("application.system.system-log-limit", 10000)
	viper.SetDefault("application.system.system-log-from", "kubearmor")
	viper.SetDefault("application.system.system-policy-to", "db|file")
	viper.SetDefault("application.system.system-policy-dir", "./")
	viper.SetDefault("application.system.system-policy-types", 7)
	viper.SetDefault("application.system.deprecate-old-mode", false)

	// Application->cluster config
	viper.SetDefault("application.cluster.cluster-info-from", "k8sclient")

	// Database config
	viper.SetDefault("database.driver", "mysql")
	viper.SetDefault("database.user", "root")
	viper.SetDefault("database.dbname", "accuknox")
	viper.SetDefault("database.host", "127.0.0.1")
	viper.SetDefault("database.port", "3306")
	viper.SetDefault("database.sqlite-db-path", "./accuknox.db")
	viper.SetDefault("database.table-network-policy", "network_policy")
	viper.SetDefault("database.table-system-policy", "system_policy")

	// logging config
	viper.SetDefault("logging.level", "INFO")

	// cilium config
	viper.SetDefault("cilium-hubble.url", "localhost")
	viper.SetDefault("cilium-hubble.port", "4245")

	// kubearmor config
	viper.SetDefault("kubearmor.url", "localhost")
	viper.SetDefault("kubearmor.port", "32767")

	// feed-consumer config
	viper.SetDefault("feed-consumer.number-of-consumers", "1")
	viper.SetDefault("feed-consumer.event-buffer-size", "50")
	viper.SetDefault("feed-consumer.consumer-group", "knoxautopolicy")
	viper.SetDefault("feed-consumer.message-offset", "latest")
	viper.SetDefault("feed-consumer.kafka.server-address-family", "v4")
	viper.SetDefault("feed-consumer.kafka.session-timeout", "6000")
	viper.SetDefault("feed-consumer.pulsar.connection-timeout", "10")
	viper.SetDefault("feed-consumer.pulsar.operation-timeout", "30")

	// recommend config

	viper.SetDefault("recommend.cron-job-time-interval", "1h0m00s")
	viper.SetDefault("recommend.operation-mode", 1)
	viper.SetDefault("recommend.host-policy", true)
	viper.SetDefault("recommend.admission-controller-policy", true)
	viper.SetDefault("license.enabled", false)

	// pprof
	viper.SetDefault("pprof", false)
}

type cfgArray []string

func (i *cfgArray) String() string {
	return "config-key=config-value"
}

func (i *cfgArray) Set(str string) error {
	kv := strings.Split(str, "=")
	if len(kv) != 2 {
		log.Panic().Msgf("invalid cfg keyval: %s\n", str)
	}
	viper.SetDefault(kv[0], kv[1])
	return nil
}

// Manually recreate routes for profiling
func pprofInit() {
	pprofServeMux := http.NewServeMux()
	pprofServeMux.Handle("/debug/pprof", http.HandlerFunc(pprof.Index))
	pprofServeMux.Handle("/debug/pprof/cmdline", http.HandlerFunc(pprof.Cmdline))
	pprofServeMux.Handle("/debug/pprof/profile", http.HandlerFunc(pprof.Profile))
	pprofServeMux.Handle("/debug/pprof/symbol", http.HandlerFunc(pprof.Symbol))
	pprofServeMux.Handle("/debug/pprof/heap", pprof.Handler("heap"))
	pprofServeMux.Handle("/debug/pprof/block", pprof.Handler("block"))
	pprofServeMux.Handle("/debug/pprof/goroutine", pprof.Handler("goroutine"))
	pprofServeMux.Handle("/debug/pprof/threadcreate", pprof.Handler("threadcreate"))

	server := &http.Server{
		Addr:              "localhost:6060",
		ReadHeaderTimeout: 90 * time.Second,
		ReadTimeout:       90 * time.Second,
		WriteTimeout:      90 * time.Second,
		Handler:           pprofServeMux,
	}

	go func() {
		log.Info().Msgf("Starting pprof... (on port 6060) \n")
		err := server.ListenAndServe()
		if err != nil {
			log.Error().Msg("ListenAndServe: " + err.Error())
		}
	}()
}

/* configuration file values are final values */
func CheckCommandLineConfig() {
	var cmdlineCfg cfgArray

	pprofFlag := flag.Bool("pprof", false, "enable pprof")
	version1 := flag.Bool("ver", false, "print version and exit")
	version2 := flag.Bool("version", false, "print version and exit")
	flag.Var(&cmdlineCfg, "cfg", "Configuration key=val")

	configFilePath := flag.String("config-path", "conf/", "conf/")
	flag.Parse()

	// Reset default routes (removing access to profiling)
	http.DefaultServeMux = http.NewServeMux()

	// enable pprof profiling if enabled
	if *pprofFlag {
		pprofInit()
	}

	if *version1 || *version2 {
		os.Exit(0)
	}

	viper.SetConfigName(GetEnv("CONF_FILE_NAME", "conf"))
	viper.SetConfigType("yaml")
	viper.AddConfigPath(*configFilePath)
	viper.SetConfigFile(*configFilePath)
	if err := viper.ReadInConfig(); err != nil {
		if readErr, ok := err.(viper.ConfigFileNotFoundError); !ok {
			log.Panic().Msgf("Error reading config file: %s\n", readErr)
		}
	}
}

func LoadConfigurationFile() {
	SetDefaultConfig()       // set default values for all config items
	CheckCommandLineConfig() // update config values from command line, if any
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
	return protocolMap[protocol]
}

func IsICMP(protocol int) bool {
	if protocol == IPProtocolICMP || protocol == IPProtocolICMPv6 {
		return true
	}
	return false
}

func IsReplyICMP(icmpType int) bool {
	return ContainsElement(ICMPReplyType, icmpType)

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

func getPolicyDir(cfgPath string) string {
	if cfgPath == "" {
		return GetEnv("POLICY_DIR", "./")
	}
	return cfgPath
}

func writeYamlByte(f *os.File, b []byte) {
	if _, err := f.Write(b); err != nil {
		log.Error().Msg(err.Error())
	}

	if err := f.Sync(); err != nil {
		log.Error().Msg(err.Error())
	}
}

func writeJsonByte(f *os.File, b []byte) {
	if _, err := f.Write(b); err != nil {
		log.Error().Msg(err.Error())
	}

	if err := f.Sync(); err != nil {
		log.Error().Msg(err.Error())
	}
}

func WriteKnoxNetPolicyToYamlFile(namespace string, policies []types.KnoxNetworkPolicy) {
	fileName := getPolicyDir(cfg.CurrentCfg.ConfigNetPolicy.NetworkPolicyDir)
	if namespace != "" {
		fileName = fileName + "knox_net_policies_" + namespace + ".yaml"
	} else {
		fileName = fileName + "knox_net_policies.yaml"
	}

	if err := os.Remove(fileName); err != nil {
		if !strings.Contains(err.Error(), NoSuchFileOrDir) {
			log.Error().Msg(err.Error())
		}
	}

	// create policy file
	f, err := os.OpenFile(filepath.Clean(fileName), os.O_CREATE|os.O_WRONLY, 0600)
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
	fileName := getPolicyDir(cfg.CurrentCfg.ConfigNetPolicy.NetworkPolicyDir)
	if namespace != "" {
		fileName = fileName + "cilium_policies_" + namespace + ".yaml"
	} else {
		fileName = fileName + "cilium_policies.yaml"
	}

	if err := os.Remove(fileName); err != nil {
		if !strings.Contains(err.Error(), NoSuchFileOrDir) {
			log.Error().Msg(err.Error())
		}
	}

	f, err := os.OpenFile(filepath.Clean(fileName), os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		log.Error().Msg(err.Error())
		return
	}

	for i := range policies {
		jsonBytes, err := json.Marshal(&policies[i])
		if err != nil {
			log.Error().Msg(err.Error())
			continue
		}
		yamlBytes, err := yaml.JSONToYAML(jsonBytes)
		if err != nil {
			log.Error().Msg(err.Error())
			continue
		}
		writeYamlByte(f, yamlBytes)
	}

	if err := f.Close(); err != nil {
		log.Error().Msg(err.Error())
	}
}

func WriteKubeArmorPolicyToYamlFile(fname string, policies []types.KubeArmorPolicy) {
	fileName := getPolicyDir(cfg.CurrentCfg.ConfigSysPolicy.SystemPolicyDir)
	fileName = fileName + fname + ".yaml"

	if err := os.Remove(fileName); err != nil {
		if !strings.Contains(err.Error(), NoSuchFileOrDir) {
			log.Error().Msg(err.Error())
		}
	}

	f, err := os.OpenFile(filepath.Clean(fileName), os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		log.Error().Msg(err.Error())
		return
	}

	for i := range policies {
		jsonBytes, err := json.Marshal(&policies[i])
		if err != nil {
			log.Error().Msg(err.Error())
			continue
		}
		yamlBytes, err := yaml.JSONToYAML(jsonBytes)
		if err != nil {
			log.Error().Msg(err.Error())
			continue
		}
		writeYamlByte(f, yamlBytes)
	}

	if err := f.Close(); err != nil {
		log.Error().Msg(err.Error())
	}
}

func WriteSysObsDataToJsonFile(obsData types.SysInsightResponseData) {
	fileName := getPolicyDir(cfg.CurrentCfg.ConfigSysPolicy.SystemPolicyDir)
	fileName = fileName + "sys_observability_data" + ".json"

	if err := os.Remove(fileName); err != nil {
		if !strings.Contains(err.Error(), NoSuchFileOrDir) {
			log.Error().Msg(err.Error())
		}
	}

	f, err := os.OpenFile(filepath.Clean(fileName), os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		log.Error().Msg(err.Error())
		return
	}

	b, err := json.Marshal(&obsData)
	if err != nil {
		log.Error().Msg(err.Error())
	}
	writeJsonByte(f, b)

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

// IsLabelMapSubset check whether m2 is a subset of m1
func IsLabelMapSubset(m1, m2 types.LabelMap) bool {
	match := true
	for k, v := range m2 {
		if m1[k] != v {
			match = false
			break
		}
	}
	return match
}

// LabelMapFromLabelArray converts []string to map[string]string
func LabelMapFromLabelArray(labels []string) types.LabelMap {
	labelMap := types.LabelMap{}
	for _, label := range labels {
		kvPair := strings.FieldsFunc(label, labelKVSplitter)
		if len(kvPair) != 2 {
			continue
		}
		labelMap[kvPair[0]] = kvPair[1]
	}
	return labelMap
}

// LabelMapToLabelArray converts map[string]string to sorted []string
func LabelMapToLabelArray(labelMap types.LabelMap) (labels []string) {
	for k, v := range labelMap {
		labels = append(labels, fmt.Sprintf("%s=%s", k, v))
	}

	sort.Strings(labels)
	return
}

// LabelMapToString converts map[string]string to string
func LabelMapToString(lm types.LabelMap) string {
	return strings.Join(LabelMapToLabelArray(lm), ",")
}

// LabelMapFromString converts string to map[string]string
func LabelMapFromString(labels string) types.LabelMap {
	return LabelMapFromLabelArray(strings.FieldsFunc(labels, labelArrSplitter))
}

func labelKVSplitter(r rune) bool {
	return r == ':' || r == '='
}

func labelArrSplitter(r rune) bool {
	return r == ',' || r == ';'
}

func HashSystemSummary(summary *types.SystemSummary) string {
	h := sha256.New()
	h.Write(
		[]byte(
			summary.ClusterName +
				strconv.Itoa(int(summary.ClusterId)) +
				strconv.Itoa(int(summary.WorkspaceId)) +
				summary.NamespaceName +
				strconv.Itoa(int(summary.NamespaceId)) +
				summary.ContainerName +
				summary.ContainerImage +
				summary.ContainerID +
				summary.PodName +
				summary.Operation +
				summary.Labels +
				summary.Deployment +
				summary.Source +
				summary.Destination +
				summary.DestNamespace +
				summary.DestLabels +
				summary.NwType +
				summary.IP +
				strconv.Itoa(int(summary.Port)) +
				summary.Protocol +
				summary.Action +
				summary.BindPort +
				summary.BindAddress,
		),
	)
	return hex.EncodeToString(h.Sum(nil))
}
