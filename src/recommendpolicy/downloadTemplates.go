// Package recommendpolicy for recommendation
package recommendpolicy

import (
	"archive/zip"
	"context"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/accuknox/auto-policy-discovery/src/types"
	"github.com/cavaliergopher/grab/v3"
	"github.com/google/go-github/github"
	"sigs.k8s.io/yaml"
)

const (
	org   = "kubearmor"
	repo  = "policy-templates"
	url   = "https://github.com/kubearmor/policy-templates/archive/refs/tags/"
	cache = ".cache/karmor/"
)

func getCachePath() string {
	cache := fmt.Sprintf("%s/%s", UserHome(), cache)
	return cache

}

// UserHome function returns users home directory
func UserHome() string {
	if runtime.GOOS == "windows" {
		home := os.Getenv("HOMEDRIVE") + os.Getenv("HOMEPATH")
		if home == "" {
			home = os.Getenv("USERPROFILE")
		}
		return home
	}
	return os.Getenv("HOME")
}

func latestRelease() string {
	latestRelease, _, err := github.NewClient(nil).Repositories.GetLatestRelease(context.Background(), org, repo)
	if err != nil {
		log.Error().Msg(err.Error())
		return ""
	}
	return *latestRelease.TagName
}

// CurrentRelease gets the current release of policy-templates
func CurrentRelease() string {

	path, err := os.ReadFile(fmt.Sprintf("%s%s", getCachePath(), "rules.yaml"))
	if err != nil {
		CurrentVersion = strings.Trim(updateRulesYAML([]byte{}), "\"")
	} else {

		CurrentVersion = strings.Trim(updateRulesYAML(path), "\"")
	}

	return CurrentVersion
}

func isLatest() bool {

	if LatestVersion == "" && CurrentVersion == "" {
		return false
	} else if LatestVersion == "" {
		// error while fetching latest release tag
		// assume the current release is the latest one
		return true
	}
	return (CurrentVersion == LatestVersion)
}

func removeData(file string) error {
	err := os.RemoveAll(file)
	return err
}

func init() {

}

// DownloadAndUnzipRelease downloads the latest version of policy-templates
func DownloadAndUnzipRelease() (string, error) {

	if LatestVersion == "" {
		LatestVersion = latestRelease()
	}
	_ = removeData(getCachePath())
	err := os.MkdirAll(filepath.Dir(getCachePath()), 0740)
	if err != nil {
		return "", err
	}
	downloadURL := fmt.Sprintf("%s%s.zip", url, LatestVersion)
	resp, err := grab.Get(getCachePath(), downloadURL)
	if err != nil {
		_ = removeData(getCachePath())
		return "", err
	}
	err = unZip(resp.Filename, getCachePath())
	if err != nil {
		return "", err
	}
	err = removeData(resp.Filename)
	if err != nil {
		return "", err
	}
	err = updatePolicyRules(strings.TrimSuffix(resp.Filename, ".zip"))
	if err != nil {
		log.Error().Msgf("Failed to update policy rules %s", err.Error())
		return "", err
	}
	CurrentVersion = CurrentRelease()
	log.Info().Msgf("Latest recommendation downloaded and updated")
	return LatestVersion, nil
}

// Sanitize archive file pathing from "G305: Zip Slip vulnerability"
func sanitizeArchivePath(d, t string) (v string, err error) {
	v = filepath.Join(d, t)
	if strings.HasPrefix(v, filepath.Clean(d)) {
		return v, nil
	}

	return "", fmt.Errorf("%s: %s", "content filepath is tainted", t)
}

func unZip(source, dest string) error {
	read, err := zip.OpenReader(source)
	if err != nil {
		return err
	}
	defer read.Close()
	for _, file := range read.File {
		if file.Mode().IsDir() {
			continue
		}
		open, err := file.Open()
		if err != nil {
			return err
		}
		name, err := sanitizeArchivePath(dest, file.Name)
		if err != nil {
			return err
		}
		_ = os.MkdirAll(path.Dir(name), 0740)
		create, err := os.Create(filepath.Clean(name))
		if err != nil {
			return err
		}
		_, err = create.ReadFrom(open)
		if err != nil {
			return err
		}
		if err = create.Close(); err != nil {
			return err
		}
		defer func() {
			if err := open.Close(); err != nil {
				log.Warn().Msgf("Error closing file %s\n", err)
			}
		}()
	}
	return nil
}

func updatePolicyRules(filePath string) error {

	var files []string
	err := filepath.Walk(filePath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && info.Name() == "metadata.yaml" {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return err
	}
	rulesYamlPath := filepath.Join(getCachePath(), "rules.yaml")
	f, err := os.Create(filepath.Clean(rulesYamlPath))
	if err != nil {
		log.Error().Msgf("Failed to create %s ", rulesYamlPath)
	}

	var yamlFile []byte
	var completePolicy []types.MatchSpec
	var version string

	for _, file := range files {
		idx := 0
		yamlFile, err = os.ReadFile(filepath.Clean(file))
		if err != nil {
			return err
		}
		version = updateRulesYAML(yamlFile)
		ms, err := getNextRule(&idx)
		for ; err == nil; ms, err = getNextRule(&idx) {
			if ms.Yaml != "" {
				var policy map[string]interface{}
				newYaml, err := os.ReadFile(filepath.Clean(fmt.Sprintf("%s%s", strings.TrimSuffix(file, "metadata.yaml"), ms.Yaml)))
				if err != nil {
					newYaml, err = os.ReadFile(filepath.Clean(fmt.Sprintf("%s/%s", filePath, ms.Yaml)))
					if err != nil {
						log.Error().Msgf("Failed to read yaml file %v", err)
						return err
					}
				}
				err = yaml.Unmarshal(newYaml, &policy)
				if err != nil {
					return err
				}
				apiVersion := policy["apiVersion"].(string)
				if strings.Contains(apiVersion, "kyverno") {
					policyKind := policy["kind"].(string)
					kyvernoPolicyInterface, err := getKyvernoPolicy(policyKind, newYaml)
					if err != nil {
						return err
					}
					ms.KyvernoPolicy = &kyvernoPolicyInterface
					ms.Kind = kyvernoPolicyInterface.GetKind()
				} else if strings.Contains(apiVersion, "kubearmor") {
					var knoxSystemPolicy types.KnoxSystemPolicy
					err = yaml.Unmarshal(newYaml, &knoxSystemPolicy)
					if err != nil {
						return err
					}
					ms.Kind = knoxSystemPolicy.Kind
					ms.Spec = knoxSystemPolicy.Spec
				}
				ms.Yaml = ""
			}
			completePolicy = append(completePolicy, ms)
		}
	}
	yamlFile, err = yaml.Marshal(completePolicy)
	if err != nil {
		return err
	}
	version = strings.Trim(version, "\"")
	yamlFile = []byte(fmt.Sprintf("version: %s\npolicyRules:\n%s", version, yamlFile))
	if _, err := f.WriteString(string(yamlFile)); err != nil {
		log.Error().Msg("WriteString failed")
	}
	if err := f.Sync(); err != nil {
		log.Error().Msg("file sync failed")
	}
	if err := f.Close(); err != nil {
		log.Error().Msg("file close failed")
	}
	return nil
}
