package common

import (
	"bufio"
	"bytes"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"io/ioutil"
	"math/bits"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	types "github.com/seungsoo-lee/knoxAutoPolicy/types"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// =================== //
// == Print Bpf Map == //
// =================== //

// Policy Bitmap
const (
	PolicyICMP        = 1 << 0  // 1
	PolicyTCP         = 1 << 1  // 2
	PolicyTCPNoPort   = 1 << 2  // 4
	PolicyTCPSrcPort  = 1 << 3  // 8
	PolicyUDP         = 1 << 4  // 16
	PolicyUDPNoPort   = 1 << 5  // 32
	PolicyUDPSrcPort  = 1 << 6  // 64
	PolicySCTP        = 1 << 7  // 128
	PolicySCTPNoPort  = 1 << 8  // 256
	PolicySCTPSrcPort = 1 << 9  // 512
	PolicyHTTP        = 1 << 10 // 1024
)

func getPolicyBitmap(policy uint32) string {
	result := ""

	if policy&PolicyICMP > 0 {
		result = result + "|ICMP"
	}
	if policy&PolicyTCP > 0 {
		result = result + "|TCP"
	}
	if policy&PolicyTCPNoPort > 0 {
		result = result + "|TCPNoPort"
	}
	if policy&PolicyTCPSrcPort > 0 {
		result = result + "|TCPSrcPort"
	}
	if policy&PolicyUDP > 0 {
		result = result + "|UDP"
	}
	if policy&PolicyUDPNoPort > 0 {
		result = result + "|UDPNoPort"
	}
	if policy&PolicyUDPSrcPort > 0 {
		result = result + "|UDPSrcPort"
	}
	if policy&PolicySCTP > 0 {
		result = result + "|SCTP"
	}
	if policy&PolicySCTPNoPort > 0 {
		result = result + "|SCTPNoPort"
	}
	if policy&PolicySCTPSrcPort > 0 {
		result = result + "|SCTPSrcPort"
	}
	if policy&PolicyHTTP > 0 {
		result = result + "|HTTP"
	}

	return result
}

func PrintL3Map(l3Map map[uint32]uint32) {
	for k, v := range l3Map {
		action := (v >> 16)
		policy := getPolicyBitmap(v & 0x0000FFFF)
		fmt.Printf("ip:[%s] -> action:[0x%04x] policy:[%s]\n", Int2IP(k), action, policy)
	}
}

func PrintIpMapCni(ipMap map[uint32]uint32) {
	for k, v := range ipMap {
		fmt.Printf("ip:[%s] -> action:[%d]\n", Int2IP(k), v)
	}
}

func PrintL3MapCni(l3Map map[uint64]uint32) {
	for k, v := range l3Map {
		srcip := Int2IP(uint32((k & 0xFFFFFFFF00000000) >> 32))
		dstip := Int2IP(uint32((k & 0x00000000FFFFFFFF)))
		action := (v >> 16)
		policy := getPolicyBitmap(v & 0x0000FFFF)

		fmt.Printf("ip:[%s->%s] -> action:[%d] policy:[%s]\n", srcip, dstip, action, policy)
	}
}

func PrintL4Map(l4Map map[uint64]uint32) {
	for k, v := range l4Map {
		ip := uint32(k >> 24)
		proto := uint8(k >> 16)
		port := uint16(k & 0x000000000000FFFF)

		action := uint32(0)
		policy := ""

		if v&0xFFFF0000 > 0 {
			action = (v >> 16)
			policy = getPolicyBitmap(v & 0x0000FFFF)
		} else {
			action = uint32(v)
		}

		fmt.Printf("ip/proto/port:[%s/%d/%d] -> action:[%d] policy:[%s]\n", Int2IP(ip), proto, port, action, policy)
	}
}

// ============ //
// == Common == //
// ============ //

func RemoveStrFromSlice(s []string, r string) []string {
	for i, v := range s {
		if v == r {
			return append(s[:i], s[i+1:]...)
		}
	}
	return s
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

// IsK8sEnv Function
func IsK8sEnv() bool {
	k8sConfig := os.Getenv("HOME") + "./kube"

	if _, ok := os.LookupEnv("KUBERNETES_PORT"); ok {
		return true
	}

	if exist, _ := Exists(k8sConfig); exist {
		return true
	}

	return false
}

var src = rand.NewSource(time.Now().UnixNano())

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
const (
	letterIdxBits = 6                    // 6 bits to represent a letter index
	letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
	letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
)

// GetRandomStr Function
func GetRandomStr() string {
	n := 10 // default value
	b := make([]byte, n)

	// A src.Int63() generates 63 random bits, enough for letterIdxMax characters!
	for i, cache, remain := n-1, src.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = src.Int63(), letterIdxMax
		}

		if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
			b[i] = letterBytes[idx]
			i--
		}

		cache >>= letterIdxBits
		remain--
	}

	return *(*string)(unsafe.Pointer(&b))
}

// GetHashedId Function
func GetHashedId(policyMeta map[string]string) uint32 {
	seedStr := ""
	if val, ok := policyMeta["path"]; ok {
		seedStr = val
	} else {
		for k, v := range policyMeta {
			seedStr = seedStr + k + v
		}
	}

	h := fnv.New32a()
	h.Write([]byte(seedStr))
	return h.Sum32()
}

// GetEnv Function
func GetEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

// GetEnvBool Function
func GetEnvBool(key string, fallback bool) bool {
	if value, ok := os.LookupEnv(key); ok {
		if value == "TRUE" {
			return true
		} else if value == "FALSE" {
			return false
		}
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

// PrintInnerMapPretty Function
func PrintInnerMapPretty(inMap interface{}) {
	pbytes, err := json.MarshalIndent(inMap, "", "    ")
	if err != nil {
		fmt.Printf("err")
	}
	fmt.Printf("%s\n", string(pbytes))
}

// Exists Function
func Exists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return true, err
}

// ReadAllFromPath Function
func ReadAllFromPath(path string, doStrip bool) (string, error) {
	if _, err := Exists(path); err != nil {
		return "", err
	}

	data, err := ioutil.ReadFile(path)
	if err != nil {
		return "", err
	}

	ret := string(data)

	if doStrip {
		ret = strings.TrimSpace(ret)
	}

	return ret, nil
}

// Clone Function
func Clone(dst, src interface{}) {
	// clone deep-copies src to dst
	// example: Clone(&dst, src)

	buff := new(bytes.Buffer)
	enc := gob.NewEncoder(buff)
	dec := gob.NewDecoder(buff)
	enc.Encode(src)
	dec.Decode(dst)
}

// ========== //
// == Time == //
// ========== //

// Time Format
const (
	TimeForm      string = "2006-01-02T15:04:05.000000"
	TimeFormUTC   string = "2006-01-02T15:04:05.000000Z"
	TimeFormHuman string = "2006-01-02 15:04:05.000000"
)

// GetDateTimeNow Function
func GetDateTimeNow() string {
	time := time.Now().UTC()
	ret := time.Format(TimeFormUTC)
	return ret
}

// GetDateTimeZero Function
func GetDateTimeZero() string {
	return "0001-01-01T00:00:00.000000Z"
}

// GetDateTimeUTC Function
func GetDateTimeUTC(givenTime string) string {
	// 2020-03-04T06:43:05.326422361Z -> 2020-03-04 06:43:05.264223 -> 0000-00-00T00:00:00.000000Z+00:00
	// 2020-03-04T06:43:05Z -> 2020-03-04 06:43:05.000000 -> 0000-00-00T00:00:00.000000Z+00:00

	trimmed := strings.ReplaceAll(strings.ReplaceAll(givenTime, "T", " "), "Z", "")
	splitted := strings.Split(trimmed, ".")

	if len(splitted) > 1 { // milli ~ nano
		if len(splitted[1]) > 6 { // nano
			splitted[1] = splitted[1][:6]
		} else { // milli ~ micro
			count := 6 - len(splitted[1])
			for i := 0; i < count; i++ {
				splitted[1] = splitted[1] + "0"
			}
		}
	} else {
		splitted = append(splitted, "000000")
	}

	givenTime = strings.Join(splitted, ".")
	t, _ := time.Parse(TimeFormHuman, givenTime)

	return t.Format(TimeFormUTC)
}

// ConvertDateTimeToStr Function
func ConvertDateTimeToStr(givenTime primitive.DateTime) string {
	t := givenTime.Time()
	t = t.UTC()
	str := t.Format(TimeFormUTC)
	return str
}

// ConvertStrToDateTime Function
func ConvertStrToDateTime(givenTime string) primitive.DateTime {
	t, _ := time.Parse(TimeFormUTC, givenTime)
	t = t.UTC()
	dateTime := primitive.NewDateTimeFromTime(t)
	return dateTime
}

// GetDateTimeBefore Function
func GetDateTimeBefore(seconds int) (string, string) {
	end := time.Now().UTC()
	end = end.Round(time.Second)
	start := end.Add(-(time.Second * time.Duration(seconds)))
	start = start.Round(time.Second)

	endt := end.Format(TimeFormUTC)
	startt := start.Format(TimeFormUTC)

	return startt, endt
}

// GetUptimeTimestamp Function
func GetUptimeTimestamp() float64 {
	now := time.Now().UTC()

	res := GetCommandOutput("cat", []string{"/proc/uptime"})

	uptimeDiff := strings.Split(res, " ")[0]
	uptimeDiffSec, _ := strconv.Atoi(strings.Split(uptimeDiff, ".")[0]) // second
	uptimeDiffMil, _ := strconv.Atoi(strings.Split(uptimeDiff, ".")[1]) // milli sec.

	uptime := now.Add(-time.Second * time.Duration(uptimeDiffSec))
	uptime = uptime.Add(-time.Millisecond * time.Duration(uptimeDiffMil))

	micro := uptime.UnixNano() / 1000
	up := float64(micro) / 1000000.0

	return up
}

// GetDateTimeFromTimestamp Function
func GetDateTimeFromTimestamp(timestamp float64) string {
	strTS := fmt.Sprintf("%.6f", timestamp)

	secTS := strings.Split(strTS, ".")[0]
	nanoTS := strings.Split(strTS, ".")[1] + "000"

	sec64, err := strconv.ParseInt(secTS, 10, 64)
	if err != nil {
		panic(err)
	}

	nano64, err := strconv.ParseInt(nanoTS, 10, 64)
	if err != nil {
		panic(err)
	}

	tm := time.Unix(sec64, nano64)
	tm = tm.UTC()

	return tm.Format(TimeFormUTC)
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

// GetCommandOutputWithoutErr Function
func GetCommandOutputWithoutErr(cmd string, args []string) string {
	res := exec.Command(cmd, args...)
	out, _ := res.Output()
	return string(out)
}

// GetCommandWithoutOutput Function
func GetCommandWithoutOutput(cmd string, args []string) {
	res := exec.Command(cmd, args...)
	res.Run()
}

// ============= //
// == Network == //
// ============= //

// GetInterfaces Function
func GetInterfaces() []string {
	interfaces := make([]string, 0)

	ipa := GetCommandOutput("ip", []string{"a"})

	ipaData := strings.Split(ipa, "\n")
	for _, line := range ipaData {
		words := strings.Split(line, ": ")
		if len(words) > 1 && strings.Contains(words[1], "veth") ||
			len(words) > 1 && strings.Contains(words[1], "ss1") ||
			len(words) > 1 && strings.Contains(words[1], "ss2") { // for security services
			veth := strings.Split(words[1], "@")[0]
			interfaces = append(interfaces, veth)
		}
	}

	return interfaces
}

// IsExistInterfaces Function
func IsExistInterfaces(name string) bool {
	if interfaces, err := net.Interfaces(); err == nil {
		for _, iface := range interfaces {
			if iface.Name == name {
				return true
			}
		}
	}

	return false
}

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

	return ""
}

// GetMacAddr Function
func GetMacAddr(ifname string) string {
	if interfaces, err := net.Interfaces(); err == nil {
		for _, iface := range interfaces {
			if iface.Name == ifname {
				mac := iface.HardwareAddr.String()
				if mac != "" {
					return mac
				}
			}
		}
	}

	return "00:00:00:00:00:00"
}

// GetGwMacAddr Function
func GetGwMacAddr(ifname string) string {
	gatewayIp := ""
	routef, err := os.Open("/proc/net/route")
	if err != nil {
		return "00:00:00:00:00:00"
	}
	defer routef.Close()

	rd := bufio.NewReader(routef)

	for {
		line, err := rd.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			return "00:00:00:00:00:00"
		}
		line = strings.TrimSpace(line)
		re := regexp.MustCompile("\t")

		words := re.Split(line, -1)
		if words[0] == ifname {
			gatewayIp = words[2]
			break
		}
	}

	i, err := strconv.ParseInt(gatewayIp, 16, 32)
	if err != nil {
		return "00:00:00:00:00:00"
	}
	gatewayIp = Int2IP(uint32(i))

	arpf, err := os.Open("/proc/net/arp")
	if err != nil {
		return "00:00:00:00:00:00"
	}
	defer arpf.Close()

	rd = bufio.NewReader(arpf)

	for {
		line, err := rd.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			return "00:00:00:00:00:00"
		}
		line = strings.TrimSpace(line)
		re := regexp.MustCompile("  +")

		words := re.Split(line, -1)
		if words[0] == gatewayIp && words[len(words)-1] == ifname {
			return words[3]
		}
	}

	return "00:00:00:00:00:00"
}

// GetCIDR Function
func GetCIDR(ifname string) string {
	if interfaces, err := net.Interfaces(); err == nil {
		for _, iface := range interfaces {
			if iface.Name == ifname {
				addrs, err := iface.Addrs()
				if err != nil {
					panic(err)
				}
				ipaddr := strings.Split(addrs[0].String(), "/")[1]
				return ipaddr
			}
		}
	}

	return ""
}

// GetInterfaceIdx Function
func GetInterfaceIdx(interfaceName string) int {
	ipa := GetCommandOutput("ip", []string{"a"})
	ipaData := strings.Split(ipa, "\n")

	for _, line := range ipaData {
		words := strings.Split(line, ": ")
		if len(words) > 1 && strings.Contains(words[1], interfaceName) {
			val, _ := strconv.Atoi(words[0])
			return val
		}
	}

	return 0
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

	return ""
}

// GetExternalIPAddr Function
func GetExternalIPAddr() string {
	iface := GetExternalInterface()
	return GetIPAddr(iface)
}

// GetExternalMacAddr Function
func GetExternalMacAddr() string {
	iface := GetExternalInterface()
	return GetMacAddr(iface)
}

// GetExternalIfaceIndex Function
func GetExternalIfaceIndex() int {
	iface := GetExternalInterface()
	return GetInterfaceIdx(iface)
}

// GetExternalGwMacAddr Function
func GetExternalGwMacAddr() string {
	iface := GetExternalInterface()
	return GetGwMacAddr(iface)
}

// GetExternalIPAddrForLog Function
func GetExternalIPAddrForLog() (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue // interface down
		}

		if iface.Flags&net.FlagLoopback != 0 {
			continue // loopback interface
		}

		addrs, err := iface.Addrs()
		if err != nil {
			return "", err
		}

		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}

			if ip == nil || ip.IsLoopback() {
				continue
			}

			ip = ip.To4()
			if ip == nil {
				continue // not an ipv4 address
			}

			return ip.String(), nil
		}
	}

	return "", errors.New("are you connected to the network?")
}

// ================ //
// == Bridge Map == //
// ================ //

// GetBridgeMap Function
func GetBridgeMap() ([]types.BridgeMap, error) {
	bridgeMap := make([]types.BridgeMap, 0)
	lastIndex := -1

	brctl := GetCommandOutput("brctl", []string{"show"})
	for _, line := range strings.Split(brctl, "\n") {
		words := strings.Fields(line)

		if len(words) > 0 && words[0] == "bridge" {
			continue
		}

		if len(words) == 4 {
			lastIndex = lastIndex + 1
			bridgeMap = append(bridgeMap, types.BridgeMap{})
			bridgeMap[lastIndex].BridgeName = words[0]
			bridgeMap[lastIndex].Interfaces = append(bridgeMap[lastIndex].Interfaces, words[3])
		} else if len(words) == 1 {
			bridgeMap[lastIndex].Interfaces = append(bridgeMap[lastIndex].Interfaces, words[0])
		}
	}

	calicoEnabled := false

	ipa := GetCommandOutput("ip", []string{"a"})
	ipaData := strings.Split(ipa, "\n")

	for _, line := range ipaData {
		words := strings.Split(line, ": ")
		if len(words) > 1 && strings.Contains(words[1], "tunl0") {
			calicoEnabled = true
			break
		}
	}

	if calicoEnabled {
		lastIndex = lastIndex + 1
		bridgeMap = append(bridgeMap, types.BridgeMap{})
		bridgeMap[lastIndex].BridgeName = "tunl0"

		ipa := GetCommandOutput("ip", []string{"a"})
		ipaData := strings.Split(ipa, "\n")

		for _, line := range ipaData {
			words := strings.Split(line, ": ")
			if len(words) > 1 && strings.Contains(words[1], "cali") {
				cali := strings.Split(words[1], "@")
				bridgeMap[lastIndex].Interfaces = append(bridgeMap[lastIndex].Interfaces, cali[0])
			}
		}
	}

	for idx, bridge := range bridgeMap {
		if bridge.BridgeName == "tunl0" { // for calico in k8s
			bridgeMap[idx].IP = "169.254.1.1"
			bridgeMap[idx].CIDRbits = 32
		} else {
			ipaddr := GetIPAddr(bridge.BridgeName)
			cidr := GetCIDR(bridge.BridgeName)
			cidrInt, err := strconv.Atoi(cidr)
			if err != nil {
				return nil, err
			}

			bridgeMap[idx].IP = ipaddr
			bridgeMap[idx].CIDRbits = cidrInt

		}
	}

	return bridgeMap, nil
}

// =================== //
// == Interface Map == //
// =================== //

// GetInterfaceMap Function
func GetInterfaceMap(bridgeMap []types.BridgeMap) (map[int]types.Interface, error) {
	ifaceMap := make(map[int]types.Interface)

	ifnames, err := ioutil.ReadDir("/sys/class/net/")
	if err != nil {
		return nil, err
	}

	for _, ifname := range ifnames {
		if ifname.Name() == "lo" {
			continue
		}

		iface := types.Interface{}
		iface.InterfaceName = ifname.Name()

		ifaceDir := "/sys/class/net/" + ifname.Name()
		if _, err := os.Stat(ifaceDir); os.IsNotExist(err) {
			continue
		}

		macaddr, err := ReadAllFromPath(ifaceDir+"/address", true)
		if err != nil {
			return nil, err
		}
		iface.Mac = macaddr

		index, err := ReadAllFromPath(ifaceDir+"/ifindex", true)
		if err != nil {
			return nil, err
		}
		idx, _ := strconv.Atoi(index)

		ifaceMap[idx] = iface

		for i, br := range bridgeMap {
			if br.BridgeName == iface.InterfaceName {
				if br.BridgeName == "tunl0" {
					bridgeMap[i].Index = idx
					bridgeMap[i].Mac = "ee:ee:ee:ee:ee:ee"
				} else {
					bridgeMap[i].Index = idx
					bridgeMap[i].Mac = macaddr
				}
			}
		}
	}

	return ifaceMap, nil
}

// ==================== //
// == Identity Match == //
// ==================== //

// MatchIdentities Function
func MatchIdentities(identities []string, superIdentities []string) bool {
	matched := true

	if len(identities) == 0 {
		return false
	}

	// if super identities not include indentity, return false
	for _, identity := range identities {
		if !ContainsElement(superIdentities, identity) {
			matched = false
			break
		}
	}

	// otherwise, return true
	return matched
}

// ============= //
// == Ingress == //
// ============= //

// IsDefinedIngress Function
func IsDefinedIngress(ingress types.Ingress) bool {
	// check matchNames
	if len(ingress.MatchNames) > 0 {
		return true
	}

	// check labels
	if len(ingress.MatchLabels) > 0 {
		return true
	}

	// check networks
	if len(ingress.Networks) > 0 {
		return true
	}

	// check fromCIDRs
	if len(ingress.FromCIDRs) > 0 {
		return true
	}

	// check FromPorts
	if len(ingress.FromPorts) > 0 {
		return true
	}

	return false
}

// ============ //
// == Egress == //
// ============ //

// IsDefinedEgress Function
func IsDefinedEgress(egress types.Egress) bool {
	// check matchNames
	if len(egress.MatchNames) > 0 {
		return true
	}

	// check labels
	if len(egress.MatchLabels) > 0 {
		return true
	}

	// check networks
	if len(egress.Networks) > 0 {
		return true
	}

	// check ToCIDRs
	if len(egress.ToCIDRs) > 0 {
		return true
	}

	// check ToPorts
	if len(egress.ToPorts) > 0 {
		return true
	}

	// check ToFQDNs
	if len(egress.ToFQDNs) > 0 {
		return true
	}

	// check ToHTTPs
	if len(egress.ToHTTPs) > 0 {
		return true
	}

	// check k8s Services
	if len(egress.Services) > 0 {
		return true
	}

	return false
}

// ========== //
// == CIDR == //
// ========== //

// GetNetAddrAndCIDRBits Function
func GetNetAddrAndCIDRBits(cidr string) (string, uint32) {
	list := strings.Split(cidr, "/")
	netaddr := list[0]
	bits, _ := strconv.Atoi(list[1])
	uintbits := uint32(bits)
	return netaddr, uintbits
}

// ============ //
// == Tunnel == //
// ============ //

// CNI Name
var CNI string = ""

// GetCniName Function
func GetCniName() string {
	if CNI == "" {
		brctl := GetCommandOutput("brctl", []string{"show"})

		for _, line := range strings.Split(brctl, "\n") {
			words := strings.Fields(line)

			if len(words) == 0 {
				continue
			}

			if words[0] == "weave" {
				CNI = "WeaveNet"
				return CNI
			} else if words[0] == "cni0" {
				CNI = "Flannel"
				return CNI
			}
		}

		ipa := GetCommandOutput("ip", []string{"a"})

		for _, line := range strings.Split(ipa, "\n") {
			words := strings.Split(line, ": ")
			if len(words) > 1 && strings.Contains(words[1], "tunl0") {
				CNI = "Calico"
				return CNI
			}
		}

		return "CNI"
	}

	return CNI
}

func GetCniInterface() string {
	if CNI == "" {
		GetCniName()
	}

	if CNI == "WeaveNet" {
		return "vxlan-6784"
	} else if CNI == "Flannel" {
		return "flannel.1"
	} else if CNI == "Calico" {
		return "tunl0"
	}

	return "None"
}

func GetCniIdx() int {
	if CNI == "" {
		GetCniName()
	}

	if CNI == "WeaveNet" {
		return GetInterfaceIdx("vethwe-datapath")
	} else if CNI == "Flannel" {
		return GetInterfaceIdx("cni0")
	} else if CNI == "Calico" {
		return GetInterfaceIdx("tunl0")
	}

	return 0
}

// ============ //
// == Bitmap == //
// ============ //

// SetProtocol64 Function
func SetProtocol64(protocol string) uint64 {
	value := uint64(0)

	if protocol == "icmp" { // POLICY_ICMP
		value = 1
	} else if protocol == "tcp" || protocol == "http" { // POLICY_TCP
		value = 2
	} else if protocol == "udp" { // POLICY_UDP
		value = 16
	} else if protocol == "sctp" { // POLICY_SCTP
		value = 128
	}

	return value
}

// SetProtocol Function
func SetProtocol(protocol string) uint32 {
	value := uint32(0)

	if protocol == "icmp" { // POLICY_ICMP
		value = 1
	} else if protocol == "tcp" || protocol == "http" { // POLICY_TCP
		value = 2
	} else if protocol == "udp" { // POLICY_UDP
		value = 16
	} else if protocol == "sctp" { // POLICY_SCTP
		value = 128
	}

	return value
}

// GetProtocolNumber Function
func GetProtocolNumber(protocol string) uint32 {
	value := uint32(0)

	if protocol == "icmp" { // POLICY_ICMP
		value = 1
	} else if protocol == "tcp" || protocol == "http" { // POLICY_TCP
		value = 6
	} else if protocol == "udp" { // POLICY_UDP
		value = 17
	} else if protocol == "sctp" { // POLICY_SCTP
		value = 132
	}

	return value
}

// ============ //
// == Action == //
// ============ //

// SetAction64 Function
func SetAction64(action string, sscIdx, vethIdx uint32) uint64 {
	res := uint64(0)

	if sscIdx != 0 {
		res = uint64(sscIdx)
	} else if action == "pass" {
		res = uint64(vethIdx)
	} else if action == "drop" {
		res = 0xFFFF
	} else {
		res = 0xFFF0 // pass to next match
	}

	return res
}

// SetAction Function
func SetAction(action string, sscIdx, vethIdx uint32) uint32 {
	res := uint32(0)

	if sscIdx != 0 {
		res = sscIdx
	} else if action == "pass" {
		res = vethIdx
	} else if action == "drop" {
		res = 0xFFFF
	} else {
		res = 0xFFF0 // pass to next match
	}

	return res
}

// GetStartStopFromRange Function
func GetStartStopFromRange(portSpec string) (int, int) {
	portRange := strings.Split(portSpec, "-")
	start, _ := strconv.Atoi(portRange[0])
	stop, _ := strconv.Atoi(portRange[1])

	return start, stop
}

// ======================== //
// == Network Namespace  == //
// ======================== //

// NetNSPrefix Definition
var NetNSPrefix string = "ns-bastion-" // "ns-bastion-"

// NetNSLocation Definition
var NetNSLocation string = "/var/run/netns" // "/var/run/netns"

// ClearNetNSLinkFromPID Function
func ClearNetNSLinkFromPID(pid int) bool {
	retVal := false

	if ok, _ := Exists(NetNSLocation); !ok {
		return retVal
	}

	files, err := ioutil.ReadDir(NetNSLocation)
	if len(files) == 0 || err != nil {
		return retVal
	}

	for _, file := range files {
		if file.Name() != NetNSPrefix+strconv.Itoa(pid) {
			continue
		}

		candidatePath := NetNSLocation + "/" + file.Name()
		fi, err := os.Stat(candidatePath)
		if err != nil {
			return retVal
		}

		if mode := fi.Mode(); mode.IsDir() {
			continue
		}

		if err := os.Remove(candidatePath); err != nil {
			return retVal
		}
	}

	retVal = true
	return retVal
}

// ClearNetNSLinks Function
func ClearNetNSLinks() bool {
	retVal := false

	if ok, _ := Exists(NetNSLocation); !ok {
		return retVal
	}

	files, err := ioutil.ReadDir(NetNSLocation)
	if len(files) == 0 || err != nil {
		return retVal
	}

	for _, file := range files {
		if !strings.HasPrefix(file.Name(), NetNSPrefix) {
			continue
		}

		candidatePath := NetNSLocation + "/" + file.Name()

		if err := os.Remove(candidatePath); err != nil {
			return retVal
		}
	}

	retVal = true
	return retVal
}

// MakeNetNSLink Function
func MakeNetNSLink(containerPid int) string {
	nsName := NetNSPrefix + strconv.Itoa(containerPid)

	if ok, _ := Exists(NetNSLocation); !ok {
		if err := os.MkdirAll(NetNSLocation, os.ModePerm); err != nil {
			panic(err)
		}
	}

	nsPID := fmt.Sprintf("/proc/%d/ns/net", containerPid)
	if ok, _ := Exists(nsPID); !ok {
		panic(errors.New("make_netns_link: path not found: " + nsPID))
	}

	nsLink := NetNSLocation + "/" + nsName
	if ok, _ := Exists(nsLink); !ok {
		os.Symlink(nsPID, nsLink)
		if ok, _ := Exists(nsLink); !ok {
			msg := fmt.Sprintf("make_netns_link: unable to create symlink: %s -> %s", nsLink, nsPID)
			panic(errors.New(msg))
		}
	}

	return nsName
}

// VethPattern Regex
var VethPattern = regexp.MustCompile(`^(\d+):\s+(.*)@if(\d+):\s+.*$`)

// MacPattern Regex
var MacPattern = regexp.MustCompile(`^\s*link/ether ([\da-fA_F]{2}:[\da-fA_F]{2}:[\da-fA_F]{2}:[\da-fA_F]{2}:[\da-fA_F]{2}:[\da-fA_F]{2}) .*$`)

// GetDevMap Function
func GetDevMap(containerPid int) (map[string]map[string]string, error) {
	devMap := map[string]map[string]string{}

	devPath := fmt.Sprintf("/proc/%d/net/dev", containerPid)
	if _, err := Exists(devPath); err != nil {
		return nil, err
	}

	file, err := os.Open(devPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	rd := bufio.NewReader(file)
	// skip the first two header lines
	rd.ReadString('\n')
	rd.ReadString('\n')

	for {
		line, err := rd.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}

		devName := strings.TrimSpace(strings.Split(line, ":")[0])
		if devName != "lo" {
			devEntry := map[string]string{"name": devName}
			devMap[devName] = devEntry
		}
	}

	// build network namespace
	netns := MakeNetNSLink(containerPid)

	linkShow := GetCommandOutput("ip", []string{"netns", "exec", netns, "ip", "link", "show", "type", "veth"})

	devEntry := map[string]string{}
	for _, lsLine := range strings.Split(linkShow, "\n") {
		lsResult := VethPattern.FindStringSubmatch(lsLine)

		if len(lsResult) != 0 {
			vethPair := lsResult[1]
			vethDev := lsResult[2]
			vethIdx := lsResult[3]

			if val, ok := devMap[vethDev]; !ok {
				devEntry = map[string]string{"name": vethDev}
				devMap[vethDev] = devEntry
			} else {
				devEntry = val
			}

			devEntry["veth_idx"] = vethIdx
			devEntry["veth_pair"] = vethPair
		} else if len(devEntry) != 0 {
			res := MacPattern.FindStringSubmatch(lsLine)
			if len(res) != 0 {
				devEntry["veth_mac"] = res[1]
				devEntry = map[string]string{}
			}
		}
	}

	return devMap, nil
}

// ====================== //
// == Raw Network Info == //
// ====================== //

// GetRawNetworkInfo Function
func GetRawNetworkInfo(containerID string, containerPID int) (types.Network, error) {
	networks := map[string]types.Network{}

	GetCommandWithoutOutput("mkdir", []string{"-p", "/var/run/netns/"})
	GetCommandWithoutOutput("ln", []string{"-sfT", fmt.Sprintf("/proc/%d/ns/net", containerPID), fmt.Sprintf("/var/run/netns/%s", containerID)})

	ipa := GetCommandOutput("ip", []string{"netns", "exec", containerID, "ip", "a"})
	ipaData := strings.Split(ipa, "\n")

	for idx, line := range ipaData {
		words := regexp.MustCompile("/| ").Split(strings.TrimSpace(line), -1)
		if words[0] == "inet" && words[1] != "127.0.0.1" {
			preWords := regexp.MustCompile("/| ").Split(strings.TrimSpace(ipaData[idx-1]), -1)

			cidr, _ := strconv.Atoi(words[2])
			network := types.Network{IP: words[1], Mac: preWords[2], CIDRbits: cidr}
			networks[words[len(words)-1]] = network
		}
	}

	ipa = GetCommandOutput("ip", []string{"netns", "exec", containerID, "ip", "route"})
	ipaData = strings.Split(ipa, "\n")

	for _, line := range ipaData {
		words := regexp.MustCompile("/| ").Split(strings.TrimSpace(line), -1)
		if words[0] == "default" {
			net := networks[words[4]]
			net.Gateway = words[2]
			return net, nil
		}
	}

	return types.Network{}, errors.New("Failed to get raw network info")
}

// ==================== //
// == Network Policy == //
// ==================== //

// GetNetworkPolicy Function
func GetNetworkPolicy(policies []types.NetworkPolicy, id uint32) types.NetworkPolicy {
	for _, policy := range policies {
		if policy.ID == id {
			return policy
		}
	}

	return types.NetworkPolicy{}
}

// SortingNetworkPolicies Function
func SortingNetworkPolicies(networkPolicies []types.NetworkPolicy) []types.NetworkPolicy {
	sortedPolicies := []types.NetworkPolicy{}

	type policyCount struct {
		ID       uint32
		Priority int
	}

	policyCounts := []policyCount{}
	for _, policy := range networkPolicies {
		policyCounts = append(policyCounts, policyCount{policy.ID, policy.Priority})
	}

	sort.Slice(policyCounts, func(i, j int) bool {
		return policyCounts[i].Priority < policyCounts[j].Priority
	})

	for _, policyPriority := range policyCounts {
		policy := GetNetworkPolicy(networkPolicies, policyPriority.ID)
		sortedPolicies = append(sortedPolicies, policy)
	}

	return sortedPolicies
}

// ============ //
// == Tunnel == //
// ============ //

// CreateTunnel Function
func CreateTunnel(tunnelName, localIP, remoteIP string) int {
	GetCommandWithoutOutput("ip", []string{"tunnel", "add", tunnelName, "mode", "ipip", "remote", remoteIP, "local", localIP})
	GetCommandWithoutOutput("ip", []string{"link", "set", tunnelName, "up"})

	return GetInterfaceIdx(tunnelName)
}

// DestroyTunnel Function
func DestroyTunnel(tunnelName string) {
	GetCommandWithoutOutput("ip", []string{"link", "set", tunnelName, "down"})
	GetCommandWithoutOutput("ip", []string{"tunnel", "del", tunnelName})
}

// DestroyTunnels Function
func DestroyTunnels() {
	interfaces := []string{}

	ipa := GetCommandOutput("ip", []string{"a"})
	for _, line := range strings.Split(ipa, "\n") {
		words := strings.Split(line, ": ")
		if len(words) > 1 && strings.Contains(words[1], "btnl") {
			tunnel := strings.Split(words[1], "@")[0]
			interfaces = append(interfaces, tunnel)
		}
	}

	for _, iface := range interfaces {
		DestroyTunnel(iface)
	}
}

// ================ //
// == Byte count == //
// ================ //

func ConvertByteCountSI(b int64) string {
	const unit = 1000
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB",
		float64(b)/float64(div), "kMGTPE"[exp])
}
