package recommendpolicy

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/clarketm/json"
	v1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"

	"github.com/accuknox/auto-policy-discovery/src/cluster"
	cfg "github.com/accuknox/auto-policy-discovery/src/config"
	"github.com/accuknox/auto-policy-discovery/src/types"
	"sigs.k8s.io/yaml"
)

var policyRules []types.MatchSpec

func updateRulesYAML(yamlFile []byte) string {
	policyRules = []types.MatchSpec{}
	policyRulesJSON, err := yaml.YAMLToJSON(yamlFile)
	if err != nil {
		log.Error().Msgf("failed to convert policy rules yaml to json")
	}
	var jsonRaw map[string]json.RawMessage
	err = json.Unmarshal(policyRulesJSON, &jsonRaw)
	if err != nil {
		log.Error().Msgf("failed to unmarshal policy rules json")
	}
	err = json.Unmarshal(jsonRaw["policyRules"], &policyRules)
	if err != nil {
		log.Error().Msgf("failed to unmarshal policy rules")
	}
	return string(jsonRaw["version"])
}

func getNextRule(idx *int) (types.MatchSpec, error) {
	if *idx < 0 {
		(*idx)++
	}
	if *idx >= len(policyRules) {
		return types.MatchSpec{}, errors.New("no rule at idx")
	}
	r := policyRules[*idx]
	(*idx)++
	return r, nil
}

func genericPolicy(precondition []string) bool {

	for _, preCondition := range precondition {
		if strings.Contains(preCondition, "OPTSCAN") {
			return true
		}
	}
	return false
}

func generatePolicy(name, namespace string, labels LabelMap) ([]types.KnoxSystemPolicy, error) {

	var ms types.MatchSpec
	var err error
	var policies []types.KnoxSystemPolicy
	idx := 0
	ms, err = getNextRule(&idx)
	for ; err == nil; ms, err = getNextRule(&idx) {
		if genericPolicy(ms.Precondition) {
			policy, err := createPolicy(ms, name, namespace, labels)
			if err != nil {
				log.Error().Msg(err.Error())
				return []types.KnoxSystemPolicy{}, err
			}
			policies = append(policies, policy)
		} else if ms.Kind == types.KindKubeArmorHostPolicy && cfg.GetCfgRecommendHostPolicy() {

			nodeList, err := cluster.GetNodesFromK8sClient()
			if err != nil {
				log.Error().Msg(err.Error())
				return []types.KnoxSystemPolicy{}, err
			}
			for _, node := range nodeList.Items {
				policy, err := createPolicy(ms, node.Name, "", node.Labels)
				if err != nil {
					log.Error().Msg(err.Error())
					return []types.KnoxSystemPolicy{}, err
				}
				policies = append(policies, policy)
			}
		}
	}

	return policies, nil

}

func createPolicy(ms types.MatchSpec, name, namespace string, labels LabelMap) (types.KnoxSystemPolicy, error) {
	policy := types.KnoxSystemPolicy{
		Spec: types.KnoxSystemSpec{
			Severity: 1, // by default
			Selector: types.Selector{
				MatchLabels: map[string]string{}},
		},
	}
	policy.APIVersion = "v1"
	policy.Kind = ms.Kind

	if policy.Kind != types.KindKubeArmorHostPolicy {
		policy.Metadata = map[string]string{
			"name":      fmt.Sprintf("%v-%v-%v", types.HardeningPolicy, name, ms.Name),
			"namespace": namespace,
		}
	} else {
		policy.Metadata = map[string]string{
			"name": fmt.Sprintf("%v-host-%v-%v", types.HardeningPolicy, name, ms.Name),
		}
	}

	policy.Spec.Action = ms.Spec.Action
	policy.Spec.Severity = ms.Spec.Severity
	if ms.Spec.Message != "" {
		policy.Spec.Message = ms.Spec.Message
	}
	if len(ms.Spec.Tags) > 0 {
		policy.Spec.Tags = ms.Spec.Tags
	}

	policy.Spec.Selector.MatchLabels = labels

	addPolicyRule(&policy, &ms.Spec)
	return policy, nil
}

func addPolicyRule(policy *types.KnoxSystemPolicy, r *types.KnoxSystemSpec) {

	if r.File.MatchDirectories != nil || r.File.MatchPaths != nil {
		policy.Spec.File = r.File
	}
	if r.Process.MatchPaths != nil || r.Process.MatchDirectories != nil {
		policy.Spec.Process = r.Process
	}
	if r.Network.MatchProtocols != nil {
		policy.Spec.Network = r.Network
	}

}

func initDeploymentWatcher() {
	clientset := cluster.ConnectK8sClient()
	watcher, err := clientset.K8sClient.AppsV1().Deployments("").Watch(context.TODO(), metav1.ListOptions{})

	if err != nil {
		log.Error().Msg(err.Error())
		return
	}
	defer watcher.Stop()

	for event := range watcher.ResultChan() {
		found := false
		var index int
		switch event.Type {
		case watch.Added:
			for _, data := range DeployNsName {
				if data.Name == event.Object.(*v1.Deployment).Name && data.Namespace == event.Object.(*v1.Deployment).Namespace {
					found = true
					break
				}
			}
			if !found {
				log.Info().Msgf("Found Deployment %v in %v namespace", event.Object.(*v1.Deployment).Name, event.Object.(*v1.Deployment).Namespace)
				generateHardenPolicy(event.Object.(*v1.Deployment).Name, event.Object.(*v1.Deployment).Namespace, event.Object.(*v1.Deployment).Spec.Template.Labels)
			}
		case watch.Deleted:
			for i, data := range DeployNsName {
				if data.Name == event.Object.(*v1.Deployment).Name && data.Namespace == event.Object.(*v1.Deployment).Namespace {
					found = true
					index = i
					break
				}
			}
			if found {
				log.Info().Msgf("Deployment: %v deleted from namespace: %v", event.Object.(*v1.Deployment).Name, event.Object.(*v1.Deployment).Namespace)
				DeployNsName = append(DeployNsName[:index], DeployNsName[index+1:]...)
				log.Info().Msgf("Deployments in watchlist : %v ", DeployNsName)
			}

		}
	}
}
