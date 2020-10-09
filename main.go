package main

import (
	"fmt"
)

var (
	Version, Build, Revision string
)

func init() {
	fmt.Printf(
		"\n[%s],\n%s (ver.%s, bld.%s, rev.%s)\n",
		"STRAIT-GATE", "CLI-API server",
		Version, Build, Revision, // -ldflags -X 옵션으로 넘긴 값들
	)
}

func main() {
	fmt.Println("hello")
}
