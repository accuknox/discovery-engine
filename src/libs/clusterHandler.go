package libs

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"

	logger "github.com/accuknox/knoxAutoPolicy/src/logging"
	"github.com/accuknox/knoxAutoPolicy/src/types"

	"github.com/rs/zerolog"
	"github.com/spf13/viper"
)

var BaseURL string
var BearerToken string
var log *zerolog.Logger

func init() {
	log = logger.GetInstance()
}

func getResponseBytes(mothod string, url string, data map[string]interface{}) []byte {
	if BaseURL == "" {
		BaseURL = viper.GetString("application.accuknox-cluster-mgmt")
	}

	// prepare full url
	url = BaseURL + url

	// prepare input data
	jsonData, err := json.Marshal(data)
	if err != nil {
		return nil
	}

	// create a new request using http [method; POST, GET]
	req, err := http.NewRequest(mothod, url, bytes.NewBuffer(jsonData))
	if err != nil {
		log.Error().Msgf("http reqeust error:", err)
		return nil
	}

	// add header to the req
	req.Header.Add("Accept", "application/json")
	req.Header.Add("knox-internal", "true")

	// send req using http Client
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Error().Msgf("Error on response.\n[ERROR] - %s", err)
		return nil
	}
	defer resp.Body.Close()

	// read response to []byte
	resByte, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Error().Msgf("Error while reading the response bytes: %s", err)
		return nil
	}

	if !strings.Contains(string(resByte), "result") {
		log.Error().Msgf("There is no results from the url: %s, msg: %s", url, string(resByte))
		return nil
	}

	// unmarshal []byte to map
	var result map[string]interface{}
	if err := json.Unmarshal(resByte, &result); err != nil {
		log.Error().Msgf("Error while unmarshaling the result: %s", err)
		return nil
	}

	// marshal map["result"] to []byte again
	resultByte, err := json.Marshal(result["result"])
	if err != nil {
		log.Error().Msgf("Error while marshaling the response bytes: %s", err)
		return nil
	}

	return resultByte
}

// =========== //
// == Login == //
// =========== //

func authLogin() error {
	user := viper.GetString("accuknox-cluster-mgmt.username")
	password := viper.GetString("accuknox-cluster-mgmt.password")
	autourl := viper.GetString("accuknox-cluster-mgmt.url-auth")

	values := map[string]string{"username": user, "password": password}
	json_data, err := json.Marshal(values)
	if err != nil {
		return err
	}

	resp, err := http.Post(autourl, "application/json",
		bytes.NewBuffer(json_data))

	if err != nil {
		return err
	}

	var res map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&res)
	BearerToken = res["access_token"].(string)

	return nil
}

// ============= //
// == Cluster == //
// ============= //

// GetClustersFromClusterNames Function
func GetClustersFromClusterNames(clusterNames []string) []types.Cluster {
	results := []types.Cluster{}

	url := "/cm/api/v1/cluster-management/get-cluster-ids"
	data := map[string]interface{}{
		"cluster_names": clusterNames,
	}

	res := getResponseBytes("POST", url, data)
	if res != nil {
		json.Unmarshal(res, &results)
	}

	return results
}

// GetClusterFromClusterName Function
func GetClusterFromClusterName(clusterName string) types.Cluster {
	results := []types.Cluster{}

	url := "/cm/api/v1/cluster-management/get-cluster-ids"
	data := map[string]interface{}{
		"cluster_names": []string{clusterName},
	}

	res := getResponseBytes("POST", url, data)
	if res != nil {
		json.Unmarshal(res, &results)
	}

	if len(results) == 1 {
		return results[0]
	}

	return types.Cluster{}
}

// GetAllClusterResources Function
func GetAllClusterResources(cluster types.Cluster) ([]string, []types.Service, []types.Endpoint, []types.Pod) {
	namespaces := GetNamespacesFromCluster(cluster)
	services := GetServicesFromCluster(cluster)
	endpoints := GetEndpointsFromCluster(cluster)
	pods := GetPodsFromCluster(cluster)

	return namespaces, services, endpoints, pods
}

// =============== //
// == Namespace == //
// =============== //

// GetNamespacesFromCluster Function
func GetNamespacesFromCluster(cluster types.Cluster) []string {
	results := []string{}

	url := "/cm/api/v1/cluster-management/all-namespaces"
	data := map[string]interface{}{
		"workspace_id": cluster.WorkspaceID,
		"cluster_id":   []int{cluster.ClusterID},
	}

	res := getResponseBytes("POST", url, data)
	namespaces := []map[string]interface{}{}
	if res != nil {
		json.Unmarshal(res, &namespaces)
	}

	for _, v := range namespaces {
		results = append(results, v["namespace"].(string))
	}

	return results
}

// ============= //
// == Service == //
// ============= //

// GetServicesFromCluster Function
func GetServicesFromCluster(cluster types.Cluster) []types.Service {
	results := []types.Service{}

	url := "/cm/api/v1/cluster-management/get-service-details"
	data := map[string]interface{}{
		"WorkspaceID": cluster.WorkspaceID,
		"ClusterID":   []int{cluster.ClusterID},
	}

	res := getResponseBytes("POST", url, data)

	services := []map[string]interface{}{}
	if res != nil {
		json.Unmarshal(res, &services)
	}

	for _, v := range services {
		svcCluster := types.ServiceCluster{}
		b, _ := json.Marshal(v)
		json.Unmarshal(b, &svcCluster)

		svc := types.Service{
			Namespace:   svcCluster.Namespace,
			ServiceName: svcCluster.ServiceName,
			Type:        svcCluster.Types,
			Labels:      []string{},
		}

		for _, label := range svcCluster.Labels {
			svc.Labels = append(svc.Labels, label["name"]+"="+label["value"])
		}

		for _, mapping := range svcCluster.Mappings {
			svc.ClusterIP = mapping["IP"]
			svc.Protocol = mapping["Protocol"]

			svcPort := mapping["ServicePort"]
			if svcPortInt, err := strconv.Atoi(svcPort); err != nil {
				svc.ServicePort = 0
			} else {
				svc.ServicePort = svcPortInt
			}

			nodePort := mapping["NodePort"]
			if nodePortInt, err := strconv.Atoi(nodePort); err != nil {
				svc.NodePort = 0
			} else {
				svc.NodePort = nodePortInt
			}

			targetPort := mapping["TargetPort"]
			if targetPortInt, err := strconv.Atoi(targetPort); err != nil {
				svc.TargetPort = 0
			} else {
				svc.TargetPort = targetPortInt
			}

			results = append(results, svc)
		}
	}

	return results
}

// ============== //
// == Endpoint == //
// ============== //

// GetEndpointsFromCluster Function
func GetEndpointsFromCluster(cluster types.Cluster) []types.Endpoint {
	results := []types.Endpoint{}

	url := "/cm/api/v1/cluster-management/get-endpoints-details"
	data := map[string]interface{}{
		"WorkspaceID": cluster.WorkspaceID,
		"ClusterID":   []int{cluster.ClusterID},
	}

	res := getResponseBytes("POST", url, data)
	endpoints := []map[string]interface{}{}
	if res != nil {
		json.Unmarshal(res, &endpoints)
	}

	for _, v := range endpoints {
		epCluster := types.EndpointCluster{}
		b, _ := json.Marshal(v)
		json.Unmarshal(b, &epCluster)

		fmt.Println(epCluster)
	}

	return results
}

// ========= //
// == Pod == //
// ========= //

// GetPodsFromCluster Function
func GetPodsFromCluster(cluster types.Cluster) []types.Pod {
	results := []types.Pod{}

	url := "/cm/api/v1/cluster-management/pods-in-node"
	data := map[string]interface{}{
		"WorkspaceID": cluster.WorkspaceID,
		"ClusterID":   []int{cluster.ClusterID},
		"Time":        0,
	}

	res := getResponseBytes("POST", url, data)
	pods := []map[string]interface{}{}
	if res != nil {
		json.Unmarshal(res, &pods)
	}

	for _, v := range pods {
		podCluster := types.PodCluster{}
		b, _ := json.Marshal(v)
		json.Unmarshal(b, &podCluster)

		pod := types.Pod{
			Namespace: podCluster.Namespace,
			PodName:   podCluster.PodName,
			Labels:    []string{},
		}

		for _, label := range podCluster.Labels {
			pod.Labels = append(pod.Labels, label["name"]+"="+label["value"])
		}
	}

	return results
}
