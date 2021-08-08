package systempolicy

import (
	"sort"
	"strings"
	"time"

	"github.com/accuknox/knoxAutoPolicy/src/config"
	"github.com/accuknox/knoxAutoPolicy/src/libs"
	types "github.com/accuknox/knoxAutoPolicy/src/types"
	"github.com/google/go-cmp/cmp"
)

// ==================== //
// == Exact Matching == //
// ==================== //

func IsExistingPolicy(existingPolicies []types.KnoxSystemPolicy, newPolicy types.KnoxSystemPolicy) bool {
	for _, exist := range existingPolicies {
		if exist.Metadata["clusterName"] == newPolicy.Metadata["clusterName"] &&
			exist.Metadata["namespace"] == newPolicy.Metadata["namespace"] &&
			cmp.Equal(&exist.Spec, &newPolicy.Spec) {
			return true
		}
	}

	return false
}

// ======================= //
// == Policy Name Check == //
// ======================= //

func existPolicyName(policyNamesMap map[string]bool, name string) bool {
	if _, ok := policyNamesMap[name]; ok {
		return true
	}

	return false
}

func GeneratePolicyName(policyNamesMap map[string]bool, policy types.KnoxSystemPolicy, clusterName string) types.KnoxSystemPolicy {
	procPrefix := "autopol-process-"
	filePrefix := "autopol-file-"
	netPrefix := "autopol-network-"

	polType := strings.ToLower(policy.Metadata["type"])
	name := "autopol-" + polType + "-" + libs.RandSeq(15)

	for existPolicyName(policyNamesMap, name) {
		if polType == "file" {
			name = filePrefix + libs.RandSeq(15)
		} else if polType == "process" {
			name = procPrefix + libs.RandSeq(15)
		} else { // network
			name = netPrefix + libs.RandSeq(15)
		}
	}

	policyNamesMap[name] = true
	policy.Metadata["name"] = name
	policy.Metadata["clusterName"] = clusterName

	return policy
}

// ======================= //
// == Process Operation == //
// ======================= //

func UpdateProcessOperation(newPolicy types.KnoxSystemPolicy, existingPolicies []types.KnoxSystemPolicy) (types.KnoxSystemPolicy, bool) {
	latestPolicies := GetLatestPolicy(existingPolicies, newPolicy)
	if len(latestPolicies) == 0 {
		return newPolicy, false
	}

	latestPolicy := latestPolicies[0]
	src := ""
	if val, ok := latestPolicy.Metadata["fromSource"]; ok {
		src = val
	}

	// step 1: latest matchDirectories -> new matchDirectories
	for _, latestMatchDir := range latestPolicy.Spec.Process.MatchDirectories {
		included := false
		for _, newMatchDir := range newPolicy.Spec.Process.MatchDirectories {
			if latestMatchDir.Dir == newMatchDir.Dir {
				included = true
				break
			}
		}

		if !included {
			newPolicy.Spec.Process.MatchDirectories = append(newPolicy.Spec.Process.MatchDirectories, latestMatchDir)
		}
	}

	// step 2: get the matchDirectories
	dirs := []string{}
	for _, newMatchDir := range newPolicy.Spec.Process.MatchDirectories {
		if !libs.ContainsElement(dirs, newMatchDir.Dir) {
			dirs = append(dirs, newMatchDir.Dir)
		}
	}

	// step 3: get the matchPaths
	paths := []string{}
	for _, newMatchPath := range newPolicy.Spec.Process.MatchPaths {
		if !libs.ContainsElement(dirs, newMatchPath.Path) {
			paths = append(dirs, newMatchPath.Path)
		}
	}

	mergedSysPaths := MergeAndAggregatePaths(dirs, paths)

	// step 4: init and updated proecss spec
	newPolicy.Spec.Process = types.KnoxSys{} // init
	for _, pathSpec := range mergedSysPaths {
		if pathSpec.isDir {
			matchDirs := types.KnoxMatchDirectories{
				Dir: pathSpec.Path,
			}

			if src != "" {
				matchDirs.FromSource = []types.KnoxFromSource{
					types.KnoxFromSource{
						Path: src,
					},
				}

			}

			if len(newPolicy.Spec.Process.MatchDirectories) == 0 {
				newPolicy.Spec.Process.MatchDirectories = []types.KnoxMatchDirectories{matchDirs}
			} else {
				newPolicy.Spec.Process.MatchDirectories = append(newPolicy.Spec.Process.MatchDirectories, matchDirs)
			}
		} else {
			matchPaths := types.KnoxMatchPaths{
				Path: pathSpec.Path,
			}

			if src != "" {
				matchPaths.FromSource = []types.KnoxFromSource{
					types.KnoxFromSource{
						Path: src,
					},
				}
			}

			if len(newPolicy.Spec.Process.MatchPaths) == 0 {
				newPolicy.Spec.Process.MatchPaths = []types.KnoxMatchPaths{matchPaths}
			} else {
				newPolicy.Spec.Process.MatchPaths = append(newPolicy.Spec.Process.MatchPaths, matchPaths)
			}
		}
	}

	// step 5: update latest -> outdated
	libs.UpdateOutdatedSystemPolicy(config.GetCfgDB(), latestPolicy.Metadata["name"], newPolicy.Metadata["name"])

	return newPolicy, true
}

// ==================== //
// == File Operation == //
// ==================== //

func includeSelectorLabels(newSelectorLabels map[string]string, existSelectorLabels map[string]string) bool {
	includeSelector := true

	for k, v := range newSelectorLabels {
		if val, ok := existSelectorLabels[k]; !ok {
			includeSelector = false
			break
		} else {
			if val != v {
				includeSelector = false
				break
			}
		}
	}

	return includeSelector
}

func GetLatestPolicy(existingPolicies []types.KnoxSystemPolicy, policy types.KnoxSystemPolicy) []types.KnoxSystemPolicy {
	latestPolicies := []types.KnoxSystemPolicy{}

	for _, exist := range existingPolicies {
		existPolicyType := exist.Metadata["type"]

		if exist.Metadata["namespace"] == policy.Metadata["namespace"] &&
			existPolicyType == policy.Metadata["type"] &&
			exist.Metadata["status"] == "latest" {

			if strings.Contains(policy.Metadata["type"], "fromSource") {
				if exist.Metadata["fromSource"] != policy.Metadata["fromSource"] {
					continue
				}
			}

			// check selector matchLabels, if not matched, next existing rule
			if !includeSelectorLabels(policy.Spec.Selector.MatchLabels, exist.Spec.Selector.MatchLabels) {
				continue
			}

			latestPolicies = append(latestPolicies, exist)
		}
	}

	return latestPolicies
}

func UpdateFileOperation(newPolicy types.KnoxSystemPolicy, existingPolicies []types.KnoxSystemPolicy) (types.KnoxSystemPolicy, bool) {
	latestPolicies := GetLatestPolicy(existingPolicies, newPolicy)
	if len(latestPolicies) == 0 {
		return newPolicy, false
	}

	latestPolicy := latestPolicies[0]
	src := ""
	if val, ok := latestPolicy.Metadata["fromSource"]; ok {
		src = val
	}

	// step 1: latest matchDirectories -> new matchDirectories
	for _, latestMatchDir := range latestPolicy.Spec.File.MatchDirectories {
		included := false
		for _, newMatchDir := range newPolicy.Spec.File.MatchDirectories {
			if latestMatchDir.Dir == newMatchDir.Dir {
				included = true
				break
			}
		}

		if !included {
			newPolicy.Spec.File.MatchDirectories = append(newPolicy.Spec.File.MatchDirectories, latestMatchDir)
		}
	}

	// step 2: get the matchDirectories
	dirs := []string{}
	for _, newMatchDir := range newPolicy.Spec.File.MatchDirectories {
		if !libs.ContainsElement(dirs, newMatchDir.Dir) {
			dirs = append(dirs, newMatchDir.Dir)
		}
	}

	// step 3: get the matchPaths
	paths := []string{}
	for _, newMatchPath := range newPolicy.Spec.File.MatchPaths {
		if !libs.ContainsElement(dirs, newMatchPath.Path) {
			paths = append(dirs, newMatchPath.Path)
		}
	}

	mergedSysPaths := MergeAndAggregatePaths(dirs, paths)

	// step 4: init and updated file spec
	newPolicy.Spec.File = types.KnoxSys{} // init
	for _, pathSpec := range mergedSysPaths {
		if pathSpec.isDir {
			matchDirs := types.KnoxMatchDirectories{
				Dir: pathSpec.Path,
			}

			if src != "" {
				matchDirs.FromSource = []types.KnoxFromSource{
					types.KnoxFromSource{
						Path: src,
					},
				}
			}

			if len(newPolicy.Spec.File.MatchDirectories) == 0 {
				newPolicy.Spec.File.MatchDirectories = []types.KnoxMatchDirectories{matchDirs}
			} else {
				newPolicy.Spec.File.MatchDirectories = append(newPolicy.Spec.File.MatchDirectories, matchDirs)
			}
		} else {
			matchPaths := types.KnoxMatchPaths{
				Path: pathSpec.Path,
			}

			if src != "" {
				matchPaths.FromSource = []types.KnoxFromSource{
					types.KnoxFromSource{
						Path: src,
					},
				}
			}

			if len(newPolicy.Spec.File.MatchPaths) == 0 {
				newPolicy.Spec.File.MatchPaths = []types.KnoxMatchPaths{matchPaths}
			} else {
				newPolicy.Spec.File.MatchPaths = append(newPolicy.Spec.File.MatchPaths, matchPaths)
			}
		}
	}

	// step 5: update latest -> outdated
	libs.UpdateOutdatedSystemPolicy(config.GetCfgDB(), latestPolicy.Metadata["name"], newPolicy.Metadata["name"])

	return newPolicy, true
}

// ====================================== //
// == Update Duplicated Network Policy == //
// ====================================== //

func UpdateDuplicatedPolicy(existingPolicies []types.KnoxSystemPolicy, discoveredPolicies []types.KnoxSystemPolicy, clusterName string) []types.KnoxSystemPolicy {
	newPolicies := []types.KnoxSystemPolicy{}

	// update policy name map
	policyNamesMap := map[string]bool{}
	for _, exist := range existingPolicies {
		policyNamesMap[exist.Metadata["name"]] = true
	}

	// enumerate discovered network policy
	for _, policy := range discoveredPolicies {
		// step 1: compare the total network policy spec
		if IsExistingPolicy(existingPolicies, policy) {
			continue
		}

		// step 2: generate policy name
		namedPolicy := GeneratePolicyName(policyNamesMap, policy, clusterName)

		// step 3: update fild operation system policy
		if policy.Metadata["type"] == SYS_OP_FILE {
			if updatedPolicy, updated := UpdateFileOperation(namedPolicy, existingPolicies); updated {
				namedPolicy = updatedPolicy
			}
		}

		// step 4: update process operation system policy
		if policy.Metadata["type"] == SYS_OP_PROCESS {
			if updatedPolicy, updated := UpdateProcessOperation(namedPolicy, existingPolicies); updated {
				namedPolicy = updatedPolicy
			}
		}

		// step 5: update status
		namedPolicy.Metadata["status"] = "latest"

		// step 6: update generated time
		namedPolicy.GeneratedTime = time.Now().Unix()

		newPolicies = append(newPolicies, namedPolicy)
	}

	sort.Slice(newPolicies, func(i, j int) bool {
		return newPolicies[i].Metadata["name"] < newPolicies[j].Metadata["name"]
	})

	return newPolicies
}
