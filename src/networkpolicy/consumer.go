package networkpolicy

import (
	"sync"

	"github.com/accuknox/auto-policy-discovery/src/libs"
	types "github.com/accuknox/auto-policy-discovery/src/types"
)

var PolicyStore libs.PolicyStore

func init() {
	PolicyStore = libs.PolicyStore{
		Consumers: make(map[*libs.PolicyConsumer]struct{}),
		Mutex:     sync.Mutex{},
	}
}

func GetPolicyYamlFromDB(consumer *libs.PolicyConsumer) []types.PolicyYaml {
	// TODO: Use policy filters for network policies
	policyYamls, err := libs.GetPolicyYamls(CfgDB, types.PolicyTypeNetwork, types.PolicyFilter{})
	if err != nil {
		log.Error().Msgf("fetching policy yaml from DB failed err=%v", err.Error())
		return nil
	}
	return libs.FilterPolicyYamls(policyYamls, consumer)
}
