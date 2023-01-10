package recommendpolicy

import (
	"errors"
	"fmt"
	"strings"

	"github.com/clarketm/json"

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
			}
			policies = append(policies, policy)
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
	policy.Kind = "KubeArmorPolicy"

	policy.Metadata = map[string]string{
		"name":      fmt.Sprintf("%v-%v-%v", types.HardeningPolicy, name, ms.Name),
		"namespace": namespace,
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
