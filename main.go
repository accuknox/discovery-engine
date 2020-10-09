package main

import (
	"fmt"

	autopol "github.com/seungsoo-lee/knoxAutoPolicy/autodiscovery"
)

func main() {
	fmt.Println("hello")
	autopol.TestGenerateNetworkPolicies()
}
