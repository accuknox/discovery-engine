package api

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	bl "github.com/seungsoo-lee/knoxAutoPolicy/common"
	types "github.com/seungsoo-lee/knoxAutoPolicy/types"
)

// ================ //
// == Connection == //
// ================ //

var managerIP string
var accessToken string

var client *http.Client

func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

func init() {
	managerIP = bl.GetEnv("MANAGER_IP", bl.GetExternalIPAddr())
	accessToken = "bastion_service"

	if _, ok := os.LookupEnv("TOKEN"); ok {
		accessToken = bl.GetEnv("TOKEN", "bastion_service")
	} else if fileExists("/tmp/bastion") {
		bytes, err := ioutil.ReadFile("/tmp/bastion")
		if err != nil {
			panic(err)
		}
		accessToken = string(bytes[:])
	}

	client = &http.Client{
		Timeout: time.Second * 5,

		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
}

// ============ //
// == Common == //
// ============= //

// GetURL Function
func GetURL() string {
	if managerIP != "" {
		return "https://" + managerIP + ":30520"
	}

	return ""
}

// WaitForAPIServer Function
func WaitForAPIServer() {
	count := 0

	for {
		_, err := client.Get(GetURL())
		if err != nil {
			count++
			time.Sleep(time.Second * 1)
			continue
		}

		break
	}
}

// DoRequest Function
func DoRequest(cmd string, data interface{}, path string) []byte {
	URL := "https://" + managerIP + ":30520"

	pbytes, err := json.Marshal(data)
	if err != nil {
		panic(err)
	}

	req, err := http.NewRequest(cmd, URL+path, bytes.NewBuffer(pbytes))
	if err != nil {
		panic(err)
	}

	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", accessToken))

	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}

	resBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}

	resp.Body.Close()
	return resBody
}

// ResFromJSON Function
func ResFromJSON(resp []byte) (string, error) {
	if strings.Contains(string(resp), "success") {
		return "success", nil
	}

	str := strings.TrimSpace(string(resp))
	return "", errors.New(str)
}

// =========== //
// == Login == //
// =========== //

// basicAuth Function
func basicAuth(username, password string) string {
	auth := username + ":" + password
	return base64.StdEncoding.EncodeToString([]byte(auth))
}

// Login API
func Login(id string, password string) string {
	URL := "https://" + managerIP + ":30520"

	pbytes, err := json.Marshal(nil)
	if err != nil {
		panic(err)
	}

	req, err := http.NewRequest("POST", URL+"/login", bytes.NewBuffer(pbytes))
	if err != nil {
		panic(err)
	}

	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authorization", "Basic "+basicAuth(id, password))

	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}

	resBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}

	resp.Body.Close()

	res := map[string]string{}
	if err := json.Unmarshal(resBody, &res); err != nil {
		return "NONE"
	}

	return res["result"]
}

func VerifyToken(token string) (string, error) {
	data := map[string]interface{}{
		"token": token,
	}

	resBody := DoRequest("POST", data, "/token")
	return ResFromJSON(resBody)
}

// =================== //
// == Configuration == //
// =================== //

// GetDaemonConfig API
func GetDaemonConfig() []byte {
	return DoRequest("GET", nil, "/daemon_config")
}

// SetDaemonConfig API
func SetDaemonConfig(key string, value string) (string, error) {
	data := map[string]interface{}{
		"key":   key,
		"value": value,
	}

	resBody := DoRequest("PUT", data, "/daemon_config")
	return ResFromJSON(resBody)
}

// GetSystemMonitorConfig API
func GetSystemMonitorConfig() []byte {
	return DoRequest("GET", nil, "/system_monitor_config")
}

// SetSystemMonitorConfig API
func SetSystemMonitorConfig(key string, value interface{}) (string, error) {
	data := map[string]interface{}{
		"key":   key,
		"value": value,
	}

	resBody := DoRequest("PUT", data, "/system_monitor_config")
	return ResFromJSON(resBody)
}

// ============= //
// == Host(s) == //
// ============= //

// GetHosts API
func GetHosts(active ...bool) ([]types.Host, error) {
	resBody := make([]byte, 0)

	if len(active) != 0 {
		data := map[string]interface{}{
			"active": active[0],
		}
		resBody = DoRequest("POST", data, "/hosts")
	} else {
		resBody = DoRequest("GET", nil, "/hosts")
	}

	res := types.ResHosts{}
	if err := json.Unmarshal(resBody, &res); err != nil {
		return nil, err
	} else if res.Message != "" {
		return nil, errors.New(res.Message)
	}

	return res.Result, nil
}

// UpdateHosts API
func UpdateHosts(hosts []types.Host) (string, error) {
	data := map[string]interface{}{
		"hosts": hosts,
	}

	resBody := DoRequest("PUT", data, "/hosts")
	return ResFromJSON(resBody)
}

//

// GetHost API
func GetHost(hostName string) ([]types.Host, error) {
	resBody := DoRequest("GET", nil, "/host/"+hostName)

	res := types.ResHosts{}
	if err := json.Unmarshal(resBody, &res); err != nil {
		return nil, err
	} else if res.Message != "" {
		return nil, errors.New(res.Message)
	}

	return res.Result, nil
}

// UpdateHost API
func UpdateHost(hostName string, host types.Host) (string, error) {
	data := map[string]interface{}{
		"host": host,
	}

	resBody := DoRequest("PUT", data, "/host/"+hostName)
	return ResFromJSON(resBody)
}

// ===================== //
// == Microservice(s) == //
// ===================== //

// GetMicroservices API
func GetMicroservices(active ...bool) ([]types.Microservice, error) {
	resBody := make([]byte, 0)

	if len(active) != 0 {
		data := map[string]interface{}{
			"active": active[0],
		}
		resBody = DoRequest("POST", data, "/microservices")
	} else {
		resBody = DoRequest("POST", nil, "/microservices")
	}

	res := types.ResMicroservices{}
	if err := json.Unmarshal(resBody, &res); err != nil {
		return nil, err
	} else if res.Message != "" {
		return nil, errors.New(res.Message)
	}

	return res.Result, nil
}

// UpdateMicroservices API
func UpdateMicroservices(microservices []types.Microservice) (string, error) {
	data := map[string]interface{}{
		"microservices": microservices,
	}

	resBody := DoRequest("PUT", data, "/microservices")
	return ResFromJSON(resBody)
}

//

// GetMicroservice API
func GetMicroservice(microserviceName string) ([]types.Microservice, error) {
	resBody := DoRequest("GET", nil, "/microservice/"+microserviceName)

	res := types.ResMicroservices{}
	if err := json.Unmarshal(resBody, &res); err != nil {
		return nil, err
	} else if res.Message != "" {
		return nil, errors.New(res.Message)
	}

	return res.Result, nil
}

// UpdateMicroservice API
func UpdateMicroservice(microserviceName string, microservice types.Microservice) (string, error) {
	data := map[string]interface{}{
		"microservice": microservice,
	}

	resBody := DoRequest("PUT", data, "/microservice/"+microserviceName)
	return ResFromJSON(resBody)
}

// ======================== //
// == Container Group(s) == //
// ======================== //

// GetContainerGroups API
func GetContainerGroups(microserviceName string, active ...bool) ([]types.ContainerGroup, error) {
	resBody := make([]byte, 0)

	path := "/container_groups"

	if microserviceName != "" {
		path = "/container_groups/" + microserviceName
	}

	if len(active) != 0 {
		data := map[string]interface{}{
			"active": active[0],
		}
		resBody = DoRequest("POST", data, path)
	} else {
		resBody = DoRequest("GET", nil, path)
	}

	res := types.ResContainerGroups{}
	if err := json.Unmarshal(resBody, &res); err != nil {
		return nil, err
	} else if res.Message != "" {
		return nil, errors.New(res.Message)
	}

	return res.Result, nil
}

// UpdateContainerGroups API
func UpdateContainerGroups(containerGroups []types.ContainerGroup) (string, error) {
	data := map[string]interface{}{
		"container_groups": containerGroups,
	}

	path := "/container_groups"

	resBody := DoRequest("PUT", data, path)
	return ResFromJSON(resBody)
}

//

// GetContainerGroup API
func GetContainerGroup(microserviceName string, containerGroupName string) ([]types.ContainerGroup, error) {
	resBody := DoRequest("GET", nil, "/container_group/"+microserviceName+"/"+containerGroupName)

	res := types.ResContainerGroups{}
	if err := json.Unmarshal(resBody, &res); err != nil {
		return nil, err
	} else if res.Message != "" {
		return nil, errors.New(res.Message)
	}

	return res.Result, nil
}

// UpdateContainerGroup API
func UpdateContainerGroup(microserviceName, containerGroupName string, containerGroup types.ContainerGroup) (string, error) {
	data := map[string]interface{}{
		"container_group": containerGroup,
	}

	resBody := DoRequest("PUT", data, "/container_group/"+microserviceName+"/"+containerGroupName)
	return ResFromJSON(resBody)
}

// ================== //
// == Container(s) == //
// ================== //

// GetContainers API
func GetContainers(microserviceName string, active ...bool) ([]types.Container, error) {
	resBody := make([]byte, 0)

	path := "/containers"

	if microserviceName != "" {
		path = "/containers/" + microserviceName
	}

	if len(active) != 0 {
		data := map[string]interface{}{
			"active": active[0],
		}
		resBody = DoRequest("POST", data, path)
	} else {
		resBody = DoRequest("GET", nil, path)
	}

	res := types.ResContainers{}
	if err := json.Unmarshal(resBody, &res); err != nil {
		return nil, err
	} else if res.Message != "" {
		return nil, errors.New(res.Message)
	}

	return res.Result, nil
}

// UpdateContainers API
func UpdateContainers(containers []types.Container) (string, error) {
	data := map[string]interface{}{
		"containers": containers,
	}

	path := "/containers"

	resBody := DoRequest("PUT", data, path)
	return ResFromJSON(resBody)
}

//

// GetContainer API
func GetContainer(microserviceName string, containerName string) ([]types.Container, error) {
	resBody := DoRequest("GET", nil, "/container/"+microserviceName+"/"+containerName)

	res := types.ResContainers{}
	if err := json.Unmarshal(resBody, &res); err != nil {
		return nil, err
	} else if res.Message != "" {
		return nil, errors.New(res.Message)
	}

	return res.Result, nil
}

// UpdateContainer API
func UpdateContainer(microserviceName, containerName string, container types.Container) (string, error) {
	data := map[string]interface{}{
		"container": container,
	}

	resBody := DoRequest("PUT", data, "/container/"+microserviceName+"/"+containerName)
	return ResFromJSON(resBody)
}

// ============== //
// == Image(s) == //
// ============== //

// GetImages API
func GetImages(hostName string, active ...bool) ([]types.Image, error) {
	resBody := make([]byte, 0)

	path := "/images"

	if hostName != "" {
		path = "/images/" + hostName
	}

	if len(active) != 0 {
		data := map[string]interface{}{
			"active": active[0],
		}
		resBody = DoRequest("POST", data, path)
	} else {
		resBody = DoRequest("GET", nil, path)
	}

	res := types.ResImages{}
	if err := json.Unmarshal(resBody, &res); err != nil {
		return nil, err
	} else if res.Message != "" {
		return nil, errors.New(res.Message)
	}

	return res.Result, nil
}

// UpdateImages API
func UpdateImages(images []types.Image) (string, error) {
	data := map[string]interface{}{
		"images": images,
	}

	resBody := DoRequest("PUT", data, "/images")
	return ResFromJSON(resBody)
}

//

// GetImage API
func GetImage(hostName, imageName string) ([]types.Image, error) {
	imageName = strings.ReplaceAll(imageName, "/", "+")
	resBody := DoRequest("GET", nil, "/image/"+hostName+"/"+imageName)

	res := types.ResImages{}
	if err := json.Unmarshal(resBody, &res); err != nil {
		return nil, err
	} else if res.Message != "" {
		return nil, errors.New(res.Message)
	}

	return res.Result, nil
}

// UpdateImage API
func UpdateImage(hostName, imageName string, image types.Image) (string, error) {
	data := map[string]interface{}{
		"image": image,
	}

	imageName = strings.ReplaceAll(imageName, "/", "+")
	resBody := DoRequest("PUT", data, "/image/"+hostName+"/"+imageName)
	return ResFromJSON(resBody)
}

// ======================= //
// == Security Stack(s) == //
// ======================= //

// GetSecurityStacks API
func GetSecurityStacks(microserviceName string, active ...bool) ([]types.SecurityStack, error) {
	resBody := make([]byte, 0)

	path := "/security_stacks"

	if microserviceName != "" {
		path = "/security_stacks/" + microserviceName
	}

	if len(active) != 0 {
		data := map[string]interface{}{
			"active": active[0],
		}
		resBody = DoRequest("POST", data, path)
	} else {
		resBody = DoRequest("GET", nil, path)
	}

	res := types.ResSecurityStacks{}
	if err := json.Unmarshal(resBody, &res); err != nil {
		return nil, err
	} else if res.Message != "" {
		return nil, errors.New(res.Message)
	}

	return res.Result, nil
}

// UpdateSecurityStacks API
func UpdateSecurityStacks(microserviceName string, stacks []types.SecurityStack) (string, error) {
	data := map[string]interface{}{
		"security_stacks": stacks,
	}

	path := "/security_stacks"

	resBody := DoRequest("PUT", data, path)
	return ResFromJSON(resBody)
}

//

// GetSecurityStack API
func GetSecurityStack(microserviceName, containerGroupName string, active bool) ([]types.SecurityStack, error) {
	resBody := DoRequest("GET", nil, "/security_stack/"+microserviceName+"/"+containerGroupName)

	res := types.ResSecurityStacks{}
	if err := json.Unmarshal(resBody, &res); err != nil {
		return nil, err
	} else if res.Message != "" {
		return nil, errors.New(res.Message)
	}

	return res.Result, nil
}

// UpdateSecurityStack API
func UpdateSecurityStack(microserviceName, containerGroupName string, stack types.SecurityStack) (string, error) {
	data := map[string]interface{}{
		"security_stack": stack,
	}

	resBody := DoRequest("PUT", data, "/security_stack/"+microserviceName+"/"+containerGroupName)
	return ResFromJSON(resBody)
}

// ========================= //
// == Security Service(s) == //
// ========================= //

// GetSecurityServices API
func GetSecurityServices(hostName string, active ...bool) ([]types.SecurityService, error) {
	resBody := make([]byte, 0)

	path := "/security_services"

	if hostName != "" {
		path = "/security_services/" + hostName
	}

	if len(active) != 0 {
		data := map[string]interface{}{
			"active": active[0],
		}
		resBody = DoRequest("POST", data, path)
	} else {
		resBody = DoRequest("GET", nil, path)
	}

	res := types.ResSecurityServices{}
	if err := json.Unmarshal(resBody, &res); err != nil {
		return nil, err
	} else if res.Message != "" {
		return nil, errors.New(res.Message)
	}

	return res.Result, nil
}

// UpdateSecurityServices API
func UpdateSecurityServices(hostName string, securityServices []types.SecurityService) (string, error) {
	data := map[string]interface{}{
		"security_services": securityServices,
	}

	path := "/security_services"

	resBody := DoRequest("PUT", data, path)
	return ResFromJSON(resBody)
}

//

// GetSecurityService API
func GetSecurityService(hostName, serviceName string, active bool) ([]types.SecurityService, error) {
	resBody := DoRequest("GET", nil, "/security_service/"+hostName+"/"+serviceName)

	res := types.ResSecurityServices{}
	if err := json.Unmarshal(resBody, &res); err != nil {
		return nil, err
	} else if res.Message != "" {
		return nil, errors.New(res.Message)
	}

	return res.Result, nil
}

// UpdateSecurityService API
func UpdateSecurityService(hostName, serviceName string, service types.SecurityService) (string, error) {
	data := map[string]interface{}{
		"security_service": service,
	}

	resBody := DoRequest("PUT", data, "/security_service/"+hostName+"/"+serviceName)
	return ResFromJSON(resBody)
}

// ================== //
// == Network Maps == //
// ================== //

// GetNetworkMaps Function
func GetNetworkMaps() ([]types.NetworkMap, error) {
	resBody := DoRequest("GET", nil, "/network_maps")

	res := types.ResNetworkMaps{}
	if err := json.Unmarshal(resBody, &res); err != nil {
		return nil, err
	} else if res.Message != "" {
		return nil, errors.New(res.Message)
	}

	return res.Result, nil
}

// UpdateNetworkMaps Function
func UpdateNetworkMaps(netMaps []types.NetworkMap) (string, error) {
	data := map[string]interface{}{
		"network_maps": netMaps,
	}

	resBody := DoRequest("PUT", data, "/network_maps")
	return ResFromJSON(resBody)
}

// DeleteNetworkMaps Function
func DeleteNetworkMaps(netMaps []types.NetworkMap) (string, error) {
	data := map[string]interface{}{
		"network_maps": netMaps,
	}

	resBody := DoRequest("DELETE", data, "/network_maps")
	return ResFromJSON(resBody)
}

// ============== //
// == Services == //
// ============== //

// GetK8sServices Function
func GetK8sServices(microserviceName string) ([]types.K8sService, error) {
	path := "/k8s_services"
	if microserviceName != "" {
		path = "/k8s_services/" + microserviceName
	}

	resBody := DoRequest("GET", nil, path)

	res := types.ResServices{}
	if err := json.Unmarshal(resBody, &res); err != nil {
		return nil, err
	} else if res.Message != "" {
		return nil, errors.New(res.Message)
	}

	return res.Result, nil
}

// UpdateK8sServices Function
func UpdateK8sServices(services []types.K8sService) (string, error) {
	data := map[string]interface{}{
		"services": services,
	}

	resBody := DoRequest("PUT", data, "/k8s_services")
	return ResFromJSON(resBody)
}

// DeleteK8sServices Function
func DeleteK8sServices(services []types.K8sService) (string, error) {
	data := map[string]interface{}{
		"services": services,
	}

	resBody := DoRequest("DELETE", data, "/k8s_services")
	return ResFromJSON(resBody)
}

// == ///

// GetK8sService Function
func GetK8sService(microserviceName, serviceName string) ([]types.K8sService, error) {
	path := "/k8s_service/" + microserviceName + "/" + serviceName

	resBody := DoRequest("GET", nil, path)

	res := types.ResServices{}
	if err := json.Unmarshal(resBody, &res); err != nil {
		return nil, err
	} else if res.Message != "" {
		return nil, errors.New(res.Message)
	}

	return res.Result, nil
}

// UpdateK8sService Function
func UpdateK8sService(service []types.K8sService) (string, error) {
	data := map[string]interface{}{
		"service": service,
	}

	resBody := DoRequest("PUT", data, "/k8s_service")
	return ResFromJSON(resBody)
}

// DeleteK8sService Function
func DeleteK8sService(service []types.K8sService) (string, error) {
	data := map[string]interface{}{
		"service": service,
	}

	resBody := DoRequest("DELETE", data, "/k8s_service")
	return ResFromJSON(resBody)
}

// =============== //
// == Endpoints == //
// =============== //

// GetK8sEndpoints Function
func GetK8sEndpoints(microserviceName string) ([]types.K8sEndpoint, error) {
	path := "/k8s_endpoints"
	if microserviceName != "" {
		path = "/k8s_endpoints/" + microserviceName
	}

	resBody := DoRequest("GET", nil, path)

	res := types.ResEndpoints{}
	if err := json.Unmarshal(resBody, &res); err != nil {
		return nil, err
	} else if res.Message != "" {
		return nil, errors.New(res.Message)
	}

	return res.Result, nil
}

// UpdateK8sEndpoints Function
func UpdateK8sEndpoints(endpoints []types.K8sEndpoint) (string, error) {
	data := map[string]interface{}{
		"endpoints": endpoints,
	}

	resBody := DoRequest("PUT", data, "/k8s_endpoints")
	return ResFromJSON(resBody)
}

// DeleteK8sEndpoints Function
func DeleteK8sEndpoints(endpoints []types.K8sEndpoint) (string, error) {
	data := map[string]interface{}{
		"endpoints": endpoints,
	}

	resBody := DoRequest("DELETE", data, "/k8s_endpoints")
	return ResFromJSON(resBody)
}

// == //

// GetK8sEndpoint Function
func GetK8sEndpoint(microserviceName, endpointName string) ([]types.K8sEndpoint, error) {
	path := "/k8s_endpoint/" + microserviceName + "/" + endpointName

	resBody := DoRequest("GET", nil, path)

	res := types.ResEndpoints{}
	if err := json.Unmarshal(resBody, &res); err != nil {
		return nil, err
	} else if res.Message != "" {
		return nil, errors.New(res.Message)
	}

	return res.Result, nil
}

// UpdateK8sEndpoint Function
func UpdateK8sEndpoint(endpoint []types.K8sEndpoint) (string, error) {
	data := map[string]interface{}{
		"endpoint": endpoint,
	}

	resBody := DoRequest("PUT", data, "/k8s_endpoint")
	return ResFromJSON(resBody)
}

// DeleteK8sEndpoint Function
func DeleteK8sEndpoint(endpoint []types.K8sEndpoint) (string, error) {
	data := map[string]interface{}{
		"endpoint": endpoint,
	}

	resBody := DoRequest("DELETE", data, "/k8s_endpoint")
	return ResFromJSON(resBody)
}

// ======================== //
// == ServiceToEndpoints == //
// ======================== //

// GetSvcToEndpoints Function
func GetSvcToEndpoints() ([]types.K8sSvcToEndpoint, error) {
	resBody := DoRequest("GET", nil, "/service_to_endpoints")

	res := types.ResSvcToEndpoints{}
	if err := json.Unmarshal(resBody, &res); err != nil {
		return nil, err
	} else if res.Message != "" {
		return nil, errors.New(res.Message)
	}

	return res.Result, nil
}

// ========== //
// == Logs == //
// ========== //

// InsertLogs API
func InsertLogs(colName string, logs interface{}) (string, error) {
	data := map[string]interface{}{
		"logs": logs,
	}

	resBody := DoRequest("PUT", data, "/logs/"+colName)
	return ResFromJSON(resBody)
}

// GetLogs API
func GetLogs(colName string, filter map[string]interface{}, sort string, limit int) ([]map[string]interface{}, error) {
	data := map[string]interface{}{}
	var resBody []byte

	if filter == nil && sort == "" && limit == 0 {
		resBody = DoRequest("GET", nil, "/logs/"+colName)
	} else {
		data["options"] = filter
		data["sort"] = sort
		data["limit"] = limit

		resBody = DoRequest("POST", data, "/logs/"+colName)
	}

	res := types.ResMaps{}
	if err := json.Unmarshal(resBody, &res); err != nil {
		return nil, err
	} else if res.Message != "" {
		return nil, errors.New(res.Message)
	}

	return res.Result, nil
}

// =================== //
// == Network Stats == //
// =================== //

// InsertNetworkStatsRaw API
func InsertNetworkStatsRaw(networkStats interface{}) (string, error) {
	data := map[string]interface{}{
		"network_stats_raw": networkStats,
	}

	resBody := DoRequest("PUT", data, "/network_stats_raw/")
	return ResFromJSON(resBody)
}

// GetNetworkStats API
func GetNetworkStats(microserviceName, conGroupName string, second int) ([]map[string]interface{}, error) {
	var resBody []byte

	if microserviceName == "" && conGroupName == "" {
		resBody = DoRequest("GET", nil, "/network_stats/"+strconv.Itoa(second))
	} else if microserviceName != "" && conGroupName == "" {
		resBody = DoRequest("GET", nil, "/network_stats/"+microserviceName+"/"+strconv.Itoa(second))
	} else if microserviceName != "" && conGroupName != "" {
		resBody = DoRequest("GET", nil, "/network_stats/"+microserviceName+"/"+conGroupName+"/"+strconv.Itoa(second))
	}

	res := types.ResMaps{}
	if err := json.Unmarshal(resBody, &res); err != nil {
		return nil, err
	} else if res.Message != "" {
		return nil, errors.New(res.Message)
	}

	return res.Result, nil
}
