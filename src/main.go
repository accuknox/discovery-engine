package main

import (
	"github.com/accuknox/knoxAutoPolicy/src/libs"
)

func main() {
	// core.StartToDiscover()

	libs.SetAnnotations("default", map[string]string{"io.cilium.proxy-visibility": "dd"})
}
