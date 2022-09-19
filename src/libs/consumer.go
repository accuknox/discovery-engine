package libs

import (
	"sync"

	"github.com/accuknox/auto-policy-discovery/src/types"
	"google.golang.org/grpc"

	dpb "github.com/accuknox/auto-policy-discovery/src/protobuf/v1/discovery"
)

// PolicyConsumer stores filter information provided in v1.Discovery.GetFlow RPC request
type PolicyConsumer struct {
	policyType []string
	Kind       []string
	Filter     types.PolicyFilter
	Events     chan *types.PolicyYaml
}

func (pc *PolicyConsumer) IsTypeNetwork() bool {
	return ContainsElement(pc.policyType, types.PolicyTypeNetwork)
}

func (pc *PolicyConsumer) IsTypeSystem() bool {
	return ContainsElement(pc.policyType, types.PolicyTypeSystem)
}

func NewPolicyConsumer(req *dpb.GetPolicyRequest) *PolicyConsumer {
	kind := req.GetKind()
	return &PolicyConsumer{
		Kind:       kind,
		policyType: getPolicyTypeFromKind(kind),
		Filter:     convertGrpcRequestToPolicyFilter(req),
		Events:     make(chan *types.PolicyYaml, 64),
	}
}

func getPolicyTypeFromKind(kind []string) []string {
	isTypeNetwork := false
	isTypeSystem := false

	for _, k := range kind {
		switch k {
		case types.KindCiliumNetworkPolicy,
			types.KindK8sNetworkPolicy,
			types.KindCiliumClusterwideNetworkPolicy:
			isTypeNetwork = true
		case types.KindKubeArmorPolicy,
			types.KindKubeArmorHostPolicy:
			isTypeSystem = true
		}
	}

	var res []string
	if isTypeNetwork {
		res = append(res, types.PolicyTypeNetwork)
	}
	if isTypeSystem {
		res = append(res, types.PolicyTypeSystem)
	}

	return res
}

// PolicyStore is used for support v1.Discovery.GetFlow RPC requests
type PolicyStore struct {
	Consumers map[*PolicyConsumer]struct{}
	Mutex     sync.Mutex
}

// AddConsumer adds a new PolicyConsumer to the store
func (pc *PolicyStore) AddConsumer(c *PolicyConsumer) {
	pc.Mutex.Lock()
	defer pc.Mutex.Unlock()

	pc.Consumers[c] = struct{}{}
	return
}

// RemoveConsumer removes a PolicyConsumer from the store
func (pc *PolicyStore) RemoveConsumer(c *PolicyConsumer) {
	pc.Mutex.Lock()
	defer pc.Mutex.Unlock()

	delete(pc.Consumers, c)
}

// Publish converts the given KnoxPolicy to PolicyYaml and pushes to consumer's channels
func (pc *PolicyStore) Publish(policy *types.PolicyYaml) {
	pc.Mutex.Lock()
	defer pc.Mutex.Unlock()

	for consumer := range pc.Consumers {
		if matchPolicyYaml(policy, consumer) {
			consumer.Events <- policy
		}
	}
}

func FilterPolicyYamls(policyYamls []types.PolicyYaml, consumer *PolicyConsumer) []types.PolicyYaml {
	result := []types.PolicyYaml{}

	for i := range policyYamls {
		if matchPolicyYaml(&policyYamls[i], consumer) {
			result = append(result, policyYamls[i])
		}
	}

	return result
}

func matchPolicyYaml(p *types.PolicyYaml, c *PolicyConsumer) bool {
	filter := c.Filter

	if filter.Cluster != "" && filter.Cluster != p.Cluster {
		return false
	}

	if filter.Namespace != "" && filter.Cluster != p.Namespace {
		return false
	}

	if len(filter.Labels) != 0 && !IsLabelMapSubset(p.Labels, filter.Labels) {
		return false
	}

	if !ContainsElement(c.Kind, p.Kind) {
		return false
	}

	return true
}

func convertGrpcRequestToPolicyFilter(req *dpb.GetPolicyRequest) types.PolicyFilter {
	return types.PolicyFilter{
		Cluster:   req.GetCluster(),
		Namespace: req.GetNamespace(),
		Labels:    LabelMapFromLabelArray(req.GetLabel()),
	}
}

func convertPolicyYamlToGrpcResponse(p *types.PolicyYaml) *dpb.GetPolicyResponse {
	return &dpb.GetPolicyResponse{
		Kind:      p.Kind,
		Name:      p.Name,
		Cluster:   p.Cluster,
		Namespace: p.Namespace,
		Label:     LabelMapToLabelArray(p.Labels),
		Yaml:      p.Yaml,
	}
}

func SendPolicyYamlInGrpcStream(stream grpc.ServerStream, policy *types.PolicyYaml) error {
	resp := convertPolicyYamlToGrpcResponse(policy)
	err := stream.SendMsg(resp)
	if err != nil {
		log.Error().Msgf("sending network policy yaml in grpc stream failed err=%v", err.Error())
		return err
	}
	return nil
}

func RelayPolicyEventToGrpcStream(stream grpc.ServerStream, consumer *PolicyConsumer) error {
	for {
		select {
		case <-stream.Context().Done():
			// client disconnected
			return nil
		case policy, ok := <-consumer.Events:
			if !ok {
				// channel closed and all items are consumed
				return nil
			}
			err := SendPolicyYamlInGrpcStream(stream, policy)
			if err != nil {
				return err
			}
		}
	}
}
