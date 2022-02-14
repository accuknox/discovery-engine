package testingpolicies_test

import (
	"testing"
	"io/ioutil"
  "log"
	"gopkg.in/yaml.v2"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"github.com/accuknox/auto-policy-discovery/src/testingpolicies/policies"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestTestingpolicies(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Testingpolicies Suite")
}

func ReadInstanceYaml(obj *policy.KubeArmorPolicy)  {

		var files []string
		var count int = 0

    root := "/home/runner/work/auto-policy-discovery/auto-policy-discovery"
    err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
        files = append(files, path)
        return nil
    })

    if err != nil {
        panic(err)
    }

    for _, file := range files {
        fmt.Println(file)

				var res = strings.Contains(file, "kubearmor_policies_default_explorer_knoxautopolicy")
				if res == true {
					source, err1 := ioutil.ReadFile(file)

				  if err1 != nil {
				    log.Printf("Error: %v", err1.Error())
				  }

				  err1 = yaml.Unmarshal(source, &obj)
				  if err1 != nil {
				    log.Printf("Error: %v", err1.Error())
				  }
					count++;
					break;
				}

    }

		for _, file := range files {
        fmt.Println(file)

				var res = strings.Contains(file, "kubearmor_policies_default_explorer_mysql")
				if res == true {
					source, err1 := ioutil.ReadFile(file)

				  if err1 != nil {
				    log.Printf("Error: %v", err1.Error())
				  }

				  err1 = yaml.Unmarshal(source, &obj)
				  if err1 != nil {
				    log.Printf("Error: %v", err1.Error())
				  }
					count++;
					break;
				}
    }

		for _, file := range files {
        fmt.Println(file)

				var res = strings.Contains(file, "kubearmor_policies_default_wordpress-mysql_mysql")
				if res == true {
					source, err1 := ioutil.ReadFile(file)

				  if err1 != nil {
				    log.Printf("Error: %v", err1.Error())
				  }

				  err1 = yaml.Unmarshal(source, &obj)
				  if err1 != nil {
				    log.Printf("Error: %v", err1.Error())
				  }
					count++;
					break;
				}
    }

		for _, file := range files {
        fmt.Println(file)

				var res = strings.Contains(file, "kubearmor_policies_default_wordpress-mysql_wordpress")
				if res == true {
					source, err1 := ioutil.ReadFile(file)

				  if err1 != nil {
				    log.Printf("Error: %v", err1.Error())
				  }

				  err1 = yaml.Unmarshal(source, &obj)
				  if err1 != nil {
				    log.Printf("Error: %v", err1.Error())
				  }
					count++;
					break;
				}
    }
}

func HasApiVersion(f *policy.KubeArmorPolicy)  bool{
	if f.APIVersion != "" {
    return true
  } else {
    return false
  }
}

var _ = Describe("KubeArmorPolicy.hasApiVersion()" , func() {
		Context("If KubeArmorPolicy has Api version", func ()  {
				It("return true", func ()  {
						f := policy.KubeArmorPolicy{}
						ReadInstanceYaml(&f)

						Expect(f.APIVersion).NotTo(Equal(""))
				})
		})
})
