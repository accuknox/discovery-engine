package main_test

import (
	"testing"
	"io/ioutil"
  "log"
	"gopkg.in/yaml.v2"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestTesting(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Testing Suite")
}

type Metadata struct {
    Name string `yaml:"name"`
    Namespace string `yaml:"namespace"`
}

type MatchLabels struct {
    Container string `yaml:"container"`
}

type Selector struct {
    MatchLabels MatchLabels `yaml:"matchLabels"`
}

type FromSource struct {
    Path string `yaml:"path"`
}

type MatchProtocol struct {
    Protocol string `yaml:"protocol"`
    FromSource []FromSource `yaml:"fromSource"`
}

type Network struct {
    MatchProtocols []MatchProtocol `yaml:"matchProtocols"`
}

type Spec struct {
    Severity int `yaml:"severity"`
    Selector Selector `yaml:"selector"`
    Network Network `yaml:"network"`
    Action string `yaml:"action"`
}

type Instance struct {
    ApiVersion string `yaml:"apiVersion"`
    Kind string `yaml:"kind"`
    Metadata Metadata `yaml:"metadata"`
    Spec Spec `yaml:"spec"`
}

func ReadInstanceYaml(obj *Instance)  {

		var files []string

    root := "/home/runner/work/vagrants/vagrants"
    err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
        files = append(files, path)
        return nil
    })

    if err != nil {
        panic(err)
    }

    for _, file := range files {
        fmt.Println(file)

				res := strings.Contains(file, "kubearmor_policies_default_explorer_knoxautopolicy")
				res := true
				if res == true {
					source, err1 := ioutil.ReadFile(file)

				  if err1 != nil {
				    log.Printf("Error: %v", err1.Error())
				  }

				  err1 = yaml.Unmarshal(source, &obj)
				  if err1 != nil {
				    log.Printf("Error: %v", err1.Error())
				  }
				}
    }
}

func (f *Instance) hasApiVersion()  bool{
  if f.ApiVersion != "" {
    return true
  } else {
    return false
  }
}

var _ = Describe("Instance.hasApiVersion()" , func() {
		Context("If Instance has Api version", func ()  {
				It("return true", func ()  {
						f := Instance{}
						ReadInstanceYaml(&f)

						response := f.hasApiVersion()

						Expect(response).To(BeTrue())
				})
		})
})
