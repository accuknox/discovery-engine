package recommendpolicy

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/accuknox/auto-policy-discovery/src/admissioncontrollerpolicy"
	"github.com/accuknox/auto-policy-discovery/src/cluster"
	cfg "github.com/accuknox/auto-policy-discovery/src/config"
	"github.com/accuknox/auto-policy-discovery/src/types"
	"github.com/clarketm/json"
	kyvernov1 "github.com/kyverno/kyverno/api/kyverno/v1"
	v1 "k8s.io/api/apps/v1"
	apiextv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	"sigs.k8s.io/yaml"
)

var policyRules []types.MatchSpec

func updateRulesYAML(yamlFile []byte) string {
	policyRules = []types.MatchSpec{}
	policyRulesJSON, err := yaml.YAMLToJSON(yamlFile)
	if err != nil {
		log.Error().Msgf("failed to convert policy rules yaml to json: %v", err)
		return ""
	}
	var jsonRaw map[string]json.RawMessage
	err = json.Unmarshal(policyRulesJSON, &jsonRaw)
	if err != nil {
		log.Error().Msgf("failed to unmarshal policy rules json: %v", err)
		return ""
	}

	var policyRulesInterface []interface{}
	err = json.Unmarshal(jsonRaw["policyRules"], &policyRulesInterface)
	if err != nil {
		log.Error().Msgf("failed to unmarshal policy rules: %v", err)
		return ""
	}
	for _, policyRuleInterface := range policyRulesInterface {
		policyRuleJSON, err := json.Marshal(policyRuleInterface)
		if err != nil {
			log.Error().Msgf("failed to marshal policy rule: %v", err)
			continue
		}
		var policyRule types.MatchSpec
		policyRule, err = unmarshalMatchSpec(policyRuleJSON)
		if err != nil {
			log.Error().Msgf("failed to unmarshal policy rule: %v", err)
			continue
		}
		policyRules = append(policyRules, policyRule)
	}
	return string(jsonRaw["version"])
}

func unmarshalMatchSpec(matchSpecJSONBytes []byte) (types.MatchSpec, error) {
	type intermediateMatchSpec struct {
		Name              string               `json:"name" yaml:"name"`
		Precondition      []string             `json:"precondition" yaml:"precondition"`
		Description       types.Description    `json:"description" yaml:"description"`
		Yaml              string               `json:"yaml" yaml:"yaml"`
		Spec              types.KnoxSystemSpec `json:"spec,omitempty" yaml:"spec,omitempty"`
		Kind              string               `json:"kind,omitempty" yaml:"kind,omitempty" bson:"kind,omitempty"`
		KyvernoPolicy     interface{}          `json:"kyvernoPolicy,omitempty" yaml:"kyvernoPolicy,omitempty"`
		KyvernoPolicyTags []string             `json:"kyvernoPolicyTags,omitempty" yaml:"kyvernoPolicyTags,omitempty"`
	}

	var intermediateStructValue intermediateMatchSpec
	err := json.Unmarshal(matchSpecJSONBytes, &intermediateStructValue)
	if err != nil {
		return types.MatchSpec{}, err
	}

	matchSpec := types.MatchSpec{
		Name:              intermediateStructValue.Name,
		Precondition:      intermediateStructValue.Precondition,
		Description:       intermediateStructValue.Description,
		Yaml:              intermediateStructValue.Yaml,
		Spec:              intermediateStructValue.Spec,
		Kind:              intermediateStructValue.Kind,
		KyvernoPolicy:     nil,
		KyvernoPolicyTags: intermediateStructValue.KyvernoPolicyTags,
	}

	if intermediateStructValue.KyvernoPolicy != nil {
		var kyvernoPolicyBytes []byte
		kyvernoPolicyBytes, err = yaml.Marshal(intermediateStructValue.KyvernoPolicy)
		if err != nil {
			return types.MatchSpec{}, err
		}
		var policy map[string]interface{}
		err = yaml.Unmarshal(kyvernoPolicyBytes, &policy)
		if err != nil {
			return types.MatchSpec{}, err
		}
		policyKind := policy["kind"].(string)
		var kyvernoPolicyInterface kyvernov1.PolicyInterface
		kyvernoPolicyInterface, err = getKyvernoPolicy(policyKind, kyvernoPolicyBytes)
		if err != nil {
			return types.MatchSpec{}, err
		}
		matchSpec.KyvernoPolicy = &kyvernoPolicyInterface
	}
	return matchSpec, nil
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

func generateKnoxSystemPolicy(name, namespace string, labels LabelMap) ([]types.KnoxSystemPolicy, error) {

	var ms types.MatchSpec
	var err error
	var policies []types.KnoxSystemPolicy
	idx := 0
	ms, err = getNextRule(&idx)
	for ; err == nil; ms, err = getNextRule(&idx) {
		if ms.KyvernoPolicy == nil {
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
	}

	return policies, nil

}

func generateKyvernoPolicy(name, namespace string, labels LabelMap) ([]kyvernov1.PolicyInterface, []string) {
	var ms types.MatchSpec
	var err error
	var policies []kyvernov1.PolicyInterface
	var policiesToBeDeleted []string
	idx := 0
	ms, err = getNextRule(&idx)
	for ; err == nil; ms, err = getNextRule(&idx) {
		if ms.KyvernoPolicy == nil {
			continue
		}
		switch ms.Name {
		case "restrict-automount-sa-token":
			if !admissioncontrollerpolicy.ShouldSATokenBeAutoMounted(namespace, labels) {
				automountSATokenPolicy := createRestrictAutomountSATokenPolicy(ms, name, namespace, labels)
				if !containsRequiredAnnotations(automountSATokenPolicy.GetAnnotations()) {
					log.Warn().Msgf("Skipping admission controller policy for deployment: %v in namespace: %v as it does not contain required annotations", name, namespace)
					continue
				}
				log.Info().Msgf("Generating admission controller policy for deployment: %v in namespace: %v", name, namespace)
				policies = append(policies, automountSATokenPolicy)
			} else {
				policiesToBeDeleted = append(policiesToBeDeleted, name+"-"+ms.Name)
			}

		}
	}
	return policies, policiesToBeDeleted
}

// createRestrictAutomountSATokenPolicy modifies and converts the original policy matching on pods to be suitable for Deployment
func createRestrictAutomountSATokenPolicy(ms types.MatchSpec, name, namespace string, labels LabelMap) kyvernov1.PolicyInterface {
	policyInterface := *(ms.KyvernoPolicy)
	policy := (policyInterface.(*kyvernov1.Policy)).DeepCopy()
	policy.Annotations[types.RecommendedPolicyTagsAnnotation] = strings.Join(ms.KyvernoPolicyTags, ",")
	policy.Name = name + "-" + ms.Name
	policy.Namespace = namespace

	policySpec := policy.Spec

	// Update kind from pod -> deployment
	policySpec.Rules[0].MatchResources.Any[0].ResourceDescription.Kinds = []string{"Deployment"}

	// Add precondition to match on particular labels
	preconditions := policySpec.Rules[0].RawAnyAllConditions
	autogenPreconditions := admissioncontrollerpolicy.AutoGenPrecondition("template", labels, *preconditions)
	policySpec.Rules[0].RawAnyAllConditions = &autogenPreconditions
	logAutogenPreconditions(autogenPreconditions)

	// Update pattern to match from pod -> deployment (autogen)
	pattern := policySpec.Rules[0].Validation.RawPattern
	autogenPattern := admissioncontrollerpolicy.AutoGenPattern("spec.template", *pattern)
	policySpec.Rules[0].Validation.RawPattern = &autogenPattern
	logAutogenPattern(autogenPattern)

	policy.Spec = policySpec
	updatedPolicyInterface := kyvernov1.PolicyInterface(policy)
	return updatedPolicyInterface
}

func generateGenericKyvernoPolicy(genericAdmissionControllerPolicyList []string) []kyvernov1.PolicyInterface {
	var ms types.MatchSpec
	var err error
	var policies []kyvernov1.PolicyInterface

	genericAdmissionControllerPolicySet := make(map[string]bool)
	for _, policy := range genericAdmissionControllerPolicyList {
		genericAdmissionControllerPolicySet[policy] = true
	}

	idx := 0
	ms, err = getNextRule(&idx)
	for ; err == nil; ms, err = getNextRule(&idx) {
		if ms.KyvernoPolicy == nil {
			continue
		}
		if _, ok := genericAdmissionControllerPolicySet[ms.Name]; ok {
			policy := createGenericKyvernoPolicy(ms)
			if policy != nil {
				if !containsRequiredAnnotations(policy.GetAnnotations()) {
					log.Error().Msgf("Skipping generic admission controller policy: %v as it does not contain required annotations", ms.Name)
					continue
				}
				log.Info().Msgf("Generating generic admission controller policy: %v", ms.Name)
				policies = append(policies, policy)
			}
		}
	}
	return policies
}

func createGenericKyvernoPolicy(ms types.MatchSpec) kyvernov1.PolicyInterface {
	policyInterface := *(ms.KyvernoPolicy)
	switch policyInterface.(type) {
	case *kyvernov1.ClusterPolicy:
		policy := (policyInterface.(*kyvernov1.ClusterPolicy)).DeepCopy()
		policy.Annotations[types.RecommendedPolicyTagsAnnotation] = strings.Join(ms.KyvernoPolicyTags, ",")
		return kyvernov1.PolicyInterface(policy)
	case *kyvernov1.Policy:
		policy := (policyInterface.(*kyvernov1.Policy)).DeepCopy()
		policy.Annotations[types.RecommendedPolicyTagsAnnotation] = strings.Join(ms.KyvernoPolicyTags, ",")
		return kyvernov1.PolicyInterface(policy)
	default:
		log.Error().Msgf("Unknown kyverno policy type: %v", policyInterface)
		return nil
	}
}

func logAutogenPattern(autogenPattern apiextv1.JSON) {
	var autogenPatternMap map[string]interface{}
	err := json.Unmarshal(autogenPattern.Raw, &autogenPatternMap)
	if err != nil {
		log.Error().Msgf("unmarshalling pattern failed err=%v", err.Error())
	} else {
		log.Info().Msgf("auto-gen pattern: %v", autogenPatternMap)
	}
}

func logAutogenPreconditions(autogenPreconditions apiextv1.JSON) {
	var autogenPreconditionsMap map[string]interface{}
	err := json.Unmarshal(autogenPreconditions.Raw, &autogenPreconditionsMap)
	if err != nil {
		log.Error().Msgf("unmarshalling precondition failed err=%v", err.Error())
	} else {
		log.Info().Msgf("auto-gen precondition: %v", autogenPreconditionsMap)
	}
}

func containsRequiredAnnotations(annotations map[string]string) bool {
	if annotations == nil {
		return false
	}
	if _, ok := annotations[types.RecommendedPolicyTagsAnnotation]; !ok {
		return false
	}
	if _, ok := annotations[types.RecommendedPolicyTitleAnnotation]; !ok {
		return false
	}
	if _, ok := annotations[types.RecommendedPolicyDescriptionAnnotation]; !ok {
		return false
	}
	return true
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

	if clientset == nil {
		return
	}

	watcher, err := clientset.AppsV1().Deployments("").Watch(context.TODO(), metav1.ListOptions{})

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

func isNamespaceAllowed(namespace string, nsNotFilter, nsFilter []string) bool {
	if len(nsFilter) > 0 {
		for _, ns := range nsFilter {
			if namespace == ns {
				return true
			}
		}
		return false
	} else if len(nsNotFilter) > 0 {
		for _, ns := range nsNotFilter {
			if namespace == ns {
				return false
			}
		}
	}
	return true
}

func getKyvernoPolicy(policyKind string, policyYaml []byte) (kyvernov1.PolicyInterface, error) {
	var kyvernoPolicyInterface kyvernov1.PolicyInterface
	switch policyKind {
	case "Policy":
		var kyvernoPolicy kyvernov1.Policy
		err := yaml.Unmarshal(policyYaml, &kyvernoPolicy)
		if err != nil {
			return nil, err
		}
		kyvernoPolicyInterface = &kyvernoPolicy
	case "ClusterPolicy":
		var kyvernoClusterPolicy kyvernov1.ClusterPolicy
		err := yaml.Unmarshal(policyYaml, &kyvernoClusterPolicy)
		if err != nil {
			return nil, err
		}
		kyvernoPolicyInterface = &kyvernoClusterPolicy
	default:
		return nil, fmt.Errorf("unexpected policy kind: %s", policyKind)
	}
	return kyvernoPolicyInterface, nil
}
