package main

import (
	"fmt"
	"os"

	"github.com/accuknox/knoxAutoPolicy/core"
	"github.com/accuknox/knoxAutoPolicy/libs"
	"github.com/accuknox/knoxAutoPolicy/localtest"
	"github.com/accuknox/knoxAutoPolicy/types"

	"gopkg.in/yaml.v2"
)

func PrintSimplePolicy(policy types.CiliumNetworkPolicy) {
	fmt.Print(policy.Metadata["name"], "\t", policy.Spec.Selector, "\t")

	if policy.Spec.Egress != nil && len(policy.Spec.Egress) > 0 {
		fmt.Println(policy.Spec.Egress)
	} else {
		fmt.Println(policy.Spec.Ingress)
	}
}

func Generate() {
	f, err := os.Create("./policies.yaml")
	if err != nil {
		fmt.Println(err)
	}
	defer f.Close()

	// define target namespace
	targetNamespace := "default"

	// 1. get network traffic from  knox aggregation Databse
	trafficList, _ := localtest.GetTrafficFlow()

	// 2. convert network traffic -> network log
	networkLogs := libs.ConvertTrafficToLogs(trafficList)

	// 3. get k8s services
	services := libs.K8s.GetServices(targetNamespace)

	// 4. get pod information
	pods := libs.K8s.GetConGroups(targetNamespace)

	// 5. generate network policies
	policies := core.GenerateNetworkPolicies(targetNamespace, 24, networkLogs, services, pods)
	for _, policy := range policies {
		ciliumPolicy := libs.ToCiliumNetworkPolicy(policy) // if you want to convert it to Cilium policy
		// PrintSimplePolicy(ciliumPolicy)	// simple print in terminal
		b, _ := yaml.Marshal(&ciliumPolicy)
		f.Write(b)
		f.WriteString("---\n")
		f.Sync()
	}

	println("done")
}

func main() {
	Generate()
}
