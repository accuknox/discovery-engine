package main

import(
  "io/ioutil"
  "log"

  "gopkg.in/yaml.v2"
)

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

func ReadInstanceYaml(serversDataFile string, obj *Instance)  {
  source, err := ioutil.ReadFile(serversDataFile)

  if err != nil {
    log.Printf("Error: %v", err.Error())
  }

  err = yaml.Unmarshal(source, &obj)
  if err != nil {
    log.Printf("Error: %v", err.Error())
  }
}

var f = Instance{}

func main() {
  ReadInstanceYaml("test1.yml", &f)
}
