package admissioncontrollerpolicy

import (
	"context"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/accuknox/auto-policy-discovery/src/cluster"
	cfg "github.com/accuknox/auto-policy-discovery/src/config"
	"github.com/accuknox/auto-policy-discovery/src/libs"
	logger "github.com/accuknox/auto-policy-discovery/src/logging"
	obs "github.com/accuknox/auto-policy-discovery/src/observability"
	opb "github.com/accuknox/auto-policy-discovery/src/protobuf/v1/observability"
	wpb "github.com/accuknox/auto-policy-discovery/src/protobuf/v1/worker"
	"github.com/accuknox/auto-policy-discovery/src/types"
	"github.com/clarketm/json"
	kyvernov1 "github.com/kyverno/kyverno/api/kyverno/v1"
	"github.com/rs/zerolog"
	corev1 "k8s.io/api/core/v1"
	apiextv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"
)

var log *zerolog.Logger

// CfgDB is the global variable representing the configuration of the database
var CfgDB types.ConfigDB

type containerMountPathServiceAccountToken struct {
	podName          string
	podNamespace     string
	containerName    string
	saTokenMountPath string
}

func init() {
	log = logger.GetInstance()
}

// InitAdmissionControllerPolicyDiscoveryConfiguration initializes the configuration of the database
// by assigning it to the global variable CfgDB
func InitAdmissionControllerPolicyDiscoveryConfiguration() {
	CfgDB = cfg.GetCfgDB()
}

// UpdateOrInsertKyvernoPolicies updates or inserts kyverno policies to DB
func UpdateOrInsertKyvernoPolicies(kyvernoPolicies []kyvernov1.PolicyInterface, labels types.LabelMap, generic bool) {
	UpdateOrInsertPolicyYamlToDB(kyvernoPolicies, labels, generic)
}

// DeleteKyvernoPolicies deletes kyverno policies from DB
func DeleteKyvernoPolicies(kyvernoPolicies []string, namespace string, labels map[string]string) {
	for _, kyvernoPolicy := range kyvernoPolicies {
		err := libs.DeletePolicyBasedOnPolicyName(CfgDB, kyvernoPolicy, namespace, libs.LabelMapToString(labels))
		if err != nil {
			log.Warn().Msgf("deleting policy from DB failed err=%v", err.Error())
		}
	}
}

// UpdateOrInsertPolicyYamlToDB upserts admission controller policies to DB
func UpdateOrInsertPolicyYamlToDB(kyvernoPolicies []kyvernov1.PolicyInterface, labels types.LabelMap, generic bool) {

	var res []types.PolicyYaml
	for _, kyvernoPolicyInterface := range kyvernoPolicies {
		var jsonBytes []byte
		var yamlBytes []byte
		var err error

		switch kyvernoPolicyInterface.(type) {
		case *kyvernov1.ClusterPolicy:
			kyvernoClusterPolicy := kyvernoPolicyInterface.(*kyvernov1.ClusterPolicy)
			jsonBytes, err = json.Marshal(*kyvernoClusterPolicy)
			if err != nil {
				log.Error().Msg(err.Error())
				continue
			}
		case *kyvernov1.Policy:
			kyvernoPolicy := kyvernoPolicyInterface.(*kyvernov1.Policy)
			jsonBytes, err = json.Marshal(*kyvernoPolicy)
			if err != nil {
				log.Error().Msg(err.Error())
				continue
			}
		}
		yamlBytes, err = yaml.JSONToYAML(jsonBytes)
		if err != nil {
			log.Error().Msg(err.Error())
			continue
		}

		policyType := types.PolicyTypeAdmissionController
		if generic {
			policyType = types.PolicyTypeAdmissionControllerGeneric
		}

		policyYaml := types.PolicyYaml{
			Type:        policyType,
			Kind:        kyvernoPolicyInterface.GetKind(),
			Name:        kyvernoPolicyInterface.GetName(),
			Namespace:   kyvernoPolicyInterface.GetNamespace(),
			Cluster:     cfg.GetCfgClusterName(),
			WorkspaceId: cfg.GetCfgWorkspaceId(),
			ClusterId:   cfg.GetCfgClusterId(),
			Labels:      labels,
			Yaml:        yamlBytes,
		}
		res = append(res, policyYaml)
	}

	if err := libs.UpdateOrInsertPolicyYamls(CfgDB, res); err != nil {
		log.Error().Msgf(err.Error())
	}
}

// GetAdmissionControllerPolicy returns admission controller policies
func GetAdmissionControllerPolicy(namespace, clusterName, labels, policyType string) []kyvernov1.Policy {
	var kyvernoPolicies []kyvernov1.Policy
	filterOptions := types.PolicyFilter{
		Cluster:   clusterName,
		Namespace: namespace,
		Labels:    libs.LabelMapFromString(labels),
	}
	policyYamls, err := libs.GetPolicyYamls(CfgDB, policyType, filterOptions)
	if err != nil {
		log.Error().Msgf("fetching policy yaml from DB failed err=%v", err.Error())
		return nil
	}
	for _, policyYaml := range policyYamls {
		var kyvernoPolicy kyvernov1.Policy
		err := yaml.Unmarshal(policyYaml.Yaml, &kyvernoPolicy)
		if err != nil {
			log.Error().Msgf("unmarshalling policy yaml failed err=%v", err.Error())
			continue
		}
		kyvernoPolicies = append(kyvernoPolicies, kyvernoPolicy)
	}
	return kyvernoPolicies
}

// ConvertPoliciesToWorkerResponse converts kyverno policies to worker response
func ConvertPoliciesToWorkerResponse(policies []kyvernov1.Policy) *wpb.WorkerResponse {
	var response wpb.WorkerResponse

	for i := range policies {
		kyvernoPolicy := wpb.Policy{}

		val, err := json.Marshal(&policies[i])
		if err != nil {
			log.Error().Msgf("kyvernoPolicy json marshal failed err=%v", err.Error())
			continue
		}
		kyvernoPolicy.Data = val

		response.AdmissionControllerPolicy = append(response.AdmissionControllerPolicy, &kyvernoPolicy)
	}
	response.Res = "OK"

	return &response
}

// AutoGenPrecondition generates a preconditions matching on particular labels for kyverno policy
func AutoGenPrecondition(patternToBeInsertedForReachingLabels string, labels types.LabelMap, precondition apiextv1.JSON) apiextv1.JSON {
	var preconditionMap map[string]interface{}
	err := json.Unmarshal(precondition.Raw, &preconditionMap)
	if err != nil {
		log.Error().Msgf("unmarshalling precondition failed err=%v", err.Error())
		return precondition
	}
	for key, value := range labels {
		newPrecondition := map[string]interface{}{
			"key":      "{{ request.object.spec." + patternToBeInsertedForReachingLabels + ".metadata.labels." + key + " || '' }}",
			"operator": "Equals",
			"value":    value,
		}
		existingSlice := preconditionMap["all"].([]interface{})
		preconditionMap["all"] = append(existingSlice, newPrecondition)
	}
	newPrecondition, err := json.Marshal(preconditionMap)
	if err != nil {
		log.Error().Msgf("marshalling precondition failed err=%v", err.Error())
		return precondition
	}
	return apiextv1.JSON{
		Raw: newPrecondition,
	}
}

// AutoGenPattern generates a pattern changing validation pattern from Pod to high level controller
//
//	patternToBeAppended is the pattern to be appended to the current pattern
//	example:
//	patternToBeAppended: spec.template
//	patternToBeAppended: spec.jobTemplate.spec.template
//
// Only linear patterns are supported, patterns like spec.[*].template are not supported
func AutoGenPattern(patternToBeAppended string, pattern apiextv1.JSON) apiextv1.JSON {
	newPattern := joinPatterns(patternToBeAppended, pattern)
	newPatternBytes, err := json.Marshal(newPattern)
	if err != nil {
		log.Error().Msgf("marshalling pattern failed err=%v", err.Error())
		return pattern
	}
	return apiextv1.JSON{
		Raw: newPatternBytes,
	}
}

func joinPatterns(patternToBeAppended string, pattern apiextv1.JSON) map[string]interface{} {
	mapKeys := strings.Split(patternToBeAppended, ".")
	var result map[string]interface{}
	for i := len(mapKeys) - 1; i >= 0; i-- {
		if i == len(mapKeys)-1 {
			result = map[string]interface{}{
				mapKeys[i]: pattern,
			}
		} else {
			result = map[string]interface{}{
				mapKeys[i]: result,
			}
		}
	}
	return result
}

// ShouldSATokenBeAutoMounted returns true if service account token should be auto mounted
func ShouldSATokenBeAutoMounted(namespace string, labels types.LabelMap) bool {
	client := cluster.ConnectK8sClient()

	podList, err := client.CoreV1().Pods(namespace).List(context.TODO(), metav1.ListOptions{
		LabelSelector: libs.LabelMapToString(labels),
	})

	if err != nil {
		log.Warn().Msg(err.Error())
		return true
	}

	if len(podList.Items) > 0 {
		// Only inspect the first pod in the list as deployment pods have same behavior
		pod := podList.Items[0]
		containersSATokenMountPath, err := getSATokenMountPath(&pod)
		if err != nil && strings.Contains(err.Error(), "service account token not mounted") {
			log.Warn().Msg(err.Error())
			return false
		}
		var sumResponses []*opb.Response
		for _, container := range pod.Spec.Containers {
			sumResp, err := obs.GetSummaryData(&opb.Request{
				PodName:       pod.Name,
				NameSpace:     pod.Namespace,
				ContainerName: container.Name,
				Type:          "process,file",
			})
			if err != nil {
				log.Warn().Msgf("Error getting summary data for pod %s, container %s, namespace %s: %s", pod.Name, container.Name, pod.Namespace, err.Error())
				return true
			}
			log.Info().Msgf("Fetched Summary data for pod %s, container %s, namespace %s", pod.Name, container.Name, pod.Namespace)
			sumResponses = append(sumResponses, sumResp)
		}
		return serviceAccountTokenUsed(containersSATokenMountPath, sumResponses)
	}

	log.Warn().Msg("No pods found for the given labels")

	return true
}

func getSATokenMountPath(pod *corev1.Pod) ([]containerMountPathServiceAccountToken, error) {
	volumes := pod.Spec.Volumes
	var tokenPath string
	var projectedVolumeName string
	var result = make([]containerMountPathServiceAccountToken, 0)
	for _, volume := range volumes {
		if volume.Projected == nil {
			continue
		}
		for _, projectedSources := range volume.Projected.Sources {
			serviceAccountToken := projectedSources.ServiceAccountToken
			if serviceAccountToken != nil {
				tokenPath = serviceAccountToken.Path
				projectedVolumeName = volume.Name
				break
			}
		}
		if tokenPath != "" {
			break
		}
	}

	if tokenPath == "" || projectedVolumeName == "" {
		return result,
			fmt.Errorf("service account token not mounted for %s in namespace %s", pod.Name, pod.Namespace)
	}

	containers := pod.Spec.Containers
	for _, container := range containers {
		volumeMounts := container.VolumeMounts
		for _, volumeMount := range volumeMounts {
			if volumeMount.Name == projectedVolumeName {
				result = append(result, containerMountPathServiceAccountToken{
					podName:          pod.Name,
					podNamespace:     pod.Namespace,
					containerName:    container.Name,
					saTokenMountPath: volumeMount.MountPath + string(filepath.Separator) + tokenPath,
				})
			}
		}
	}
	return result, nil
}

func serviceAccountTokenUsed(containersSATokenMountPath []containerMountPathServiceAccountToken, sumResponses []*opb.Response) bool {
	for _, containerSATokenMountPath := range containersSATokenMountPath {
		for _, sumResp := range sumResponses {
			for _, fileData := range sumResp.FileData {
				if sumResp.ContainerName == containerSATokenMountPath.containerName {
					// Even if one container uses the service account token, we should allow auto mounting
					if matchesSATokenPath(containerSATokenMountPath.saTokenMountPath, fileData.Destination) {
						return true
					}
				}
			}
		}
	}
	return false
}

func matchesSATokenPath(saTokenPath, sumRespPath string) bool {
	saTokenPathParts := strings.Split(saTokenPath, string(filepath.Separator))
	sumRespPathParts := strings.Split(sumRespPath, string(filepath.Separator))

	// VolumeMount path is linked to path starting with the following regex
	// Known k8s feature/issue: https://stackoverflow.com/q/50685385/15412365
	// KubeArmor return summary path after resolving symlinks
	pattern := "..[0-9]{4}_[0-9]{2}_[0-9]{2}.*"

	sumRespPathPartsWithoutDoubleDot := removeMatchingElements(sumRespPathParts, pattern)
	sumpRespPathWithoutDoubleDot := strings.Join(sumRespPathPartsWithoutDoubleDot, string(filepath.Separator))

	// Typical SA token path /var/run/secrets/kubernetes.io/serviceaccount/token
	// is also compared after removing first part i.e. /run/secrets/kubernetes.io/serviceaccount/token
	// due to KubeArmor symlink resolution issue
	saTokenPathWithoutFirstPathPart := strings.Join(append(saTokenPathParts[0:1],
		saTokenPathParts[2:]...), string(filepath.Separator))

	if saTokenPath == sumpRespPathWithoutDoubleDot ||
		saTokenPathWithoutFirstPathPart == sumpRespPathWithoutDoubleDot {
		return true
	}
	return false
}

func removeMatchingElements(slice []string, pattern string) []string {
	r := regexp.MustCompile(pattern)
	result := make([]string, 0)

	for _, s := range slice {
		if !r.MatchString(s) {
			result = append(result, s)
		}
	}

	return result
}
