package api

import (
	"encoding/json"
	"errors"

	types "github.com/seungsoo-lee/knoxAutoPolicy/types"
)

// ========================== //
// == Network Policy(-ies) == //
// ========================== //

// GetNetworkPolicies API
func GetNetworkPolicies() ([]types.NetworkPolicy, error) {
	resBody := DoRequest("GET", nil, "/network_policies")

	res := types.ResNetPolicies{}
	if err := json.Unmarshal(resBody, &res); err != nil {
		return nil, err
	} else if res.Message != "" {
		return nil, errors.New(res.Message)
	}

	return res.Result, nil
}

// AddNetworkPolicies API
func AddNetworkPolicies(policies []types.NetworkPolicy) (string, error) {
	data := map[string]interface{}{
		"network_policies": policies,
	}

	resBody := DoRequest("POST", data, "/network_policies")
	return ResFromJSON(resBody)
}

// UpdateNetworkPolicies API
func UpdateNetworkPolicies(policies []types.NetworkPolicy) (string, error) {
	data := map[string]interface{}{
		"network_policies": policies,
	}

	resBody := DoRequest("PUT", data, "/network_policies")
	return ResFromJSON(resBody)
}

// DeleteNetworkPolicies API
func DeleteNetworkPolicies(policies []types.NetworkPolicy) (string, error) {
	data := map[string]interface{}{
		"network_policies": policies,
	}

	resBody := DoRequest("DELETE", data, "/network_policies")
	return ResFromJSON(resBody)
}

//

// GetNetworkPolicy API
func GetNetworkPolicy(policyName string) ([]types.NetworkPolicy, error) {
	resBody := DoRequest("GET", nil, "/network_policy/"+policyName)

	res := types.ResNetPolicies{}
	if err := json.Unmarshal(resBody, &res); err != nil {
		return nil, err
	} else if res.Message != "" {
		return nil, errors.New(res.Message)
	}

	return res.Result, nil
}

// AddNetworkPolicy API
func AddNetworkPolicy(policy types.NetworkPolicy) (string, error) {
	data := map[string]interface{}{
		"network_policy": policy,
	}

	resBody := DoRequest("POST", data, "/network_policy")
	return ResFromJSON(resBody)
}

// UpdateNetworkPolicy API
func UpdateNetworkPolicy(policy types.NetworkPolicy) (string, error) {
	data := map[string]interface{}{
		"network_policy": policy,
	}

	resBody := DoRequest("PUT", data, "/network_policy")
	return ResFromJSON(resBody)
}

// DeleteNetworkPolicy API
func DeleteNetworkPolicy(policy types.NetworkPolicy) (string, error) {
	data := map[string]interface{}{
		"network_policy": policy,
	}

	resBody := DoRequest("DELETE", data, "/network_policy")
	return ResFromJSON(resBody)
}

// GenerateNetworkPolicies API
func GenerateNetworkPolicies(microserviceName string) (string, error) {
	resBody := DoRequest("GET", nil, "/network_policies/generation/"+microserviceName)
	return ResFromJSON(resBody)
}

// ================================ //
// == Service Chain Policy(-ies) == //
// ================================ //

// GetServiceChainPolicies API
func GetServiceChainPolicies() ([]types.ServiceChainPolicy, error) {
	resBody := DoRequest("GET", nil, "/service_chain_policies")

	res := types.ResServiceChainPolicies{}
	if err := json.Unmarshal(resBody, &res); err != nil {
		return nil, err
	} else if res.Message != "" {
		return nil, errors.New(res.Message)
	}

	return res.Result, nil
}

// AddServiceChainPolicies API
func AddServiceChainPolicies(policies []types.ServiceChainPolicy) (string, error) {
	data := map[string]interface{}{
		"service_chain_policies": policies,
	}

	resBody := DoRequest("POST", data, "/service_chain_policies")
	return ResFromJSON(resBody)
}

// UpdateServiceChainPolicies API
func UpdateServiceChainPolicies(policies []types.ServiceChainPolicy) (string, error) {
	data := map[string]interface{}{
		"service_chain_policies": policies,
	}

	resBody := DoRequest("PUT", data, "/service_chain_policies")
	return ResFromJSON(resBody)
}

// DeleteServiceChainPolicies API
func DeleteServiceChainPolicies(policies []types.ServiceChainPolicy) (string, error) {
	data := map[string]interface{}{
		"service_chain_policies": policies,
	}

	resBody := DoRequest("DELETE", data, "/service_chain_policies")
	return ResFromJSON(resBody)
}

//

// GetServiceChainPolicy API
func GetServiceChainPolicy(policyName string) ([]types.ServiceChainPolicy, error) {
	resBody := DoRequest("GET", nil, "/service_chain_policy/"+policyName)

	res := types.ResServiceChainPolicies{}
	if err := json.Unmarshal(resBody, &res); err != nil {
		return nil, err
	} else if res.Message != "" {
		return nil, errors.New(res.Message)
	}

	return res.Result, nil
}

// AddServiceChainPolicy API
func AddServiceChainPolicy(policy types.ServiceChainPolicy) (string, error) {
	data := map[string]interface{}{
		"service_chain_policy": policy,
	}

	resBody := DoRequest("POST", data, "/service_chain_policy")
	return ResFromJSON(resBody)
}

// UpdateServiceChainPolicy API
func UpdateServiceChainPolicy(policy []types.ServiceChainPolicy) (string, error) {
	data := map[string]interface{}{
		"service_chain_policy": policy,
	}

	resBody := DoRequest("PUT", data, "/service_chain_policy")
	return ResFromJSON(resBody)
}

// DeleteServiceChainPolicy API
func DeleteServiceChainPolicy(policy []types.ServiceChainPolicy) (string, error) {
	data := map[string]interface{}{
		"service_chain_policy": policy,
	}

	resBody := DoRequest("DELETE", data, "/service_chain_policy")
	return ResFromJSON(resBody)
}

// ========================= //
// == System Policy(-ies) == //
// ========================= //

// GetSystemPolicies API
func GetSystemPolicies() ([]types.SystemPolicy, error) {
	resBody := DoRequest("GET", nil, "/system_policies")

	res := types.ResSystemPolicies{}
	if err := json.Unmarshal(resBody, &res); err != nil {
		return nil, err
	} else if res.Message != "" {
		return nil, errors.New(res.Message)
	}

	return res.Result, nil
}

// AddSystemPolicies API
func AddSystemPolicies(policies []types.SystemPolicy) (string, error) {
	data := map[string]interface{}{
		"service_chain_policies": policies,
	}

	resBody := DoRequest("POST", data, "/system_policies")
	return ResFromJSON(resBody)
}

// UpdateSystemPolicies API
func UpdateSystemPolicies(policies []types.SystemPolicy) (string, error) {
	data := map[string]interface{}{
		"service_chain_policies": policies,
	}

	resBody := DoRequest("PUT", data, "/system_policies")
	return ResFromJSON(resBody)
}

// DeleteSystemPolicies API
func DeleteSystemPolicies(policies []types.SystemPolicy) (string, error) {
	data := map[string]interface{}{
		"service_chain_policies": policies,
	}

	resBody := DoRequest("DELETE", data, "/system_policies")
	return ResFromJSON(resBody)
}

//

// GetSystemPolicy API
func GetSystemPolicy(policyName string) ([]types.SystemPolicy, error) {
	resBody := DoRequest("GET", nil, "/system_policy/"+policyName)

	res := types.ResSystemPolicies{}
	if err := json.Unmarshal(resBody, &res); err != nil {
		return nil, err
	} else if res.Message != "" {
		return nil, errors.New(res.Message)
	}

	return res.Result, nil
}

// AddSystemPolicy API
func AddSystemPolicy(policy types.SystemPolicy) (string, error) {
	data := map[string]interface{}{
		"service_chain_policy": policy,
	}

	resBody := DoRequest("POST", data, "/system_policy")
	return ResFromJSON(resBody)
}

// UpdateSystemPolicy API
func UpdateSystemPolicy(policy []types.SystemPolicy) (string, error) {
	data := map[string]interface{}{
		"service_chain_policy": policy,
	}

	resBody := DoRequest("PUT", data, "/system_policy")
	return ResFromJSON(resBody)
}

// DeleteSystemPolicy API
func DeleteSystemPolicy(policy []types.SystemPolicy) (string, error) {
	data := map[string]interface{}{
		"service_chain_policy": policy,
	}

	resBody := DoRequest("DELETE", data, "/system_policy")
	return ResFromJSON(resBody)
}

// ========================= //
// == Runtime Policy(-ies) == //
// ========================= //

// GetRuntimePolicies API
func GetRuntimePolicies() ([]types.RuntimePolicy, error) {
	resBody := DoRequest("GET", nil, "/runtime_policies")

	res := types.ResRuntimePolicies{}
	if err := json.Unmarshal(resBody, &res); err != nil {
		return nil, err
	} else if res.Message != "" {
		return nil, errors.New(res.Message)
	}

	return res.Result, nil
}

// AddRuntimePolicies API
func AddRuntimePolicies(policies []types.RuntimePolicy) (string, error) {
	data := map[string]interface{}{
		"service_chain_policies": policies,
	}

	resBody := DoRequest("POST", data, "/runtime_policies")
	return ResFromJSON(resBody)
}

// UpdateRuntimePolicies API
func UpdateRuntimePolicies(policies []types.RuntimePolicy) (string, error) {
	data := map[string]interface{}{
		"service_chain_policies": policies,
	}

	resBody := DoRequest("PUT", data, "/runtime_policies")
	return ResFromJSON(resBody)
}

// DeleteRuntimePolicies API
func DeleteRuntimePolicies(policies []types.RuntimePolicy) (string, error) {
	data := map[string]interface{}{
		"service_chain_policies": policies,
	}

	resBody := DoRequest("DELETE", data, "/runtime_policies")
	return ResFromJSON(resBody)
}

//

// GetRuntimePolicy API
func GetRuntimePolicy(policyName string) ([]types.RuntimePolicy, error) {
	resBody := DoRequest("GET", nil, "/runtime_policy/"+policyName)

	res := types.ResRuntimePolicies{}
	if err := json.Unmarshal(resBody, &res); err != nil {
		return nil, err
	} else if res.Message != "" {
		return nil, errors.New(res.Message)
	}

	return res.Result, nil
}

// AddRuntimePolicy API
func AddRuntimePolicy(policy types.RuntimePolicy) (string, error) {
	data := map[string]interface{}{
		"service_chain_policy": policy,
	}

	resBody := DoRequest("POST", data, "/runtime_policy")
	return ResFromJSON(resBody)
}

// UpdateRuntimePolicy API
func UpdateRuntimePolicy(policy []types.RuntimePolicy) (string, error) {
	data := map[string]interface{}{
		"service_chain_policy": policy,
	}

	resBody := DoRequest("PUT", data, "/runtime_policy")
	return ResFromJSON(resBody)
}

// DeleteRuntimePolicy API
func DeleteRuntimePolicy(policy []types.RuntimePolicy) (string, error) {
	data := map[string]interface{}{
		"service_chain_policy": policy,
	}

	resBody := DoRequest("DELETE", data, "/runtime_policy")
	return ResFromJSON(resBody)
}

// ======================= //
// == AppArmor Profiles == //
// ======================= //

// GetAppArmorProfiles API
func GetAppArmorProfiles() ([]types.AppArmorProfile, error) {
	resBody := DoRequest("GET", nil, "/apparmor_profiles")

	res := types.ResAppArmorProfiles{}
	if err := json.Unmarshal(resBody, &res); err != nil {
		return nil, err
	} else if res.Message != "" {
		return nil, errors.New(res.Message)
	}

	return res.Result, nil
}

// AddAppArmorProfile API
func AddAppArmorProfile(profileName string) (string, error) {
	resBody := DoRequest("POST", nil, "/apparmor_profile/"+profileName)
	return ResFromJSON(resBody)
}

// LockAppArmorProfile API
func LockAppArmorProfile(profileName string) (string, error) {
	resBody := DoRequest("PUT", nil, "/apparmor_profile/lock/"+profileName)
	return ResFromJSON(resBody)
}

// ReleaseAppArmorProfile API
func ReleaseAppArmorProfile(profileName string) (string, error) {
	resBody := DoRequest("PUT", nil, "/apparmor_profile/release/"+profileName)
	return ResFromJSON(resBody)
}

// DeleteAppArmorProfile  API
func DeleteAppArmorProfile(profileName string) (string, error) {
	resBody := DoRequest("DELETE", nil, "/apparmor_profile/"+profileName)
	return ResFromJSON(resBody)
}

// ==================== //
// == Suricata Rules == //
// ==================== //

// GetSuricataRules API
func GetSuricataRules() ([]types.SuricataRule, error) {
	resBody := DoRequest("GET", nil, "/suricata_rules")

	res := types.ResSuricataRules{}
	if err := json.Unmarshal(resBody, &res); err != nil {
		return nil, err
	} else if res.Message != "" {
		return nil, errors.New(res.Message)
	}

	return res.Result, nil
}

// AddSuricataRules API
func AddSuricataRules(rules []types.SuricataRule) (string, error) {
	data := map[string]interface{}{
		"suricata_rules": rules,
	}

	resBody := DoRequest("POST", data, "/suricata_rules")
	return ResFromJSON(resBody)
}

// DeleteSuricataRules  API
func DeleteSuricataRules(rules []types.SuricataRule) (string, error) {
	data := map[string]interface{}{
		"suricata_rules": rules,
	}

	resBody := DoRequest("DELETE", data, "/suricata_rules")
	return ResFromJSON(resBody)
}
