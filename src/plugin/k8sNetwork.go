package plugin

import (
	"strconv"

	"github.com/accuknox/auto-policy-discovery/src/types"
	v1 "k8s.io/api/core/v1"
	nv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func ConvertKnoxNetPolicyToK8sNetworkPolicy(clustername, namespace string, knoxNetPolicies []types.KnoxNetworkPolicy) []nv1.NetworkPolicy {

	log.Info().Msgf("No. of knox network policies - %d", len(knoxNetPolicies))

	if len(knoxNetPolicies) <= 0 {
		return nil
	}

	res := []nv1.NetworkPolicy{}

	for _, knp := range knoxNetPolicies {
		k8NetPol := nv1.NetworkPolicy{}

		k8NetPol.APIVersion = types.K8sNwPolicyAPIVersion
		k8NetPol.Kind = types.K8sNwPolicyKind
		k8NetPol.Name = knp.Metadata["name"]
		k8NetPol.Namespace = knp.Metadata["namespace"]
		k8NetPol.ClusterName = knp.Metadata["cluster_name"]
		k8NetPol.Labels = knp.Spec.Selector.MatchLabels

		if len(knp.Spec.Egress) > 0 {

			for _, eg := range knp.Spec.Egress {
				var egressRule nv1.NetworkPolicyEgressRule
				port := nv1.NetworkPolicyPort{}
				to := nv1.NetworkPolicyPeer{}
				var protocol v1.Protocol

				if eg.ToPorts[0].Protocol == string(v1.ProtocolTCP) {
					protocol = v1.ProtocolTCP
				} else if eg.ToPorts[0].Protocol == string(v1.ProtocolUDP) {
					protocol = v1.ProtocolUDP
				}

				portVal, _ := strconv.ParseInt(eg.ToPorts[0].Port, 10, 32)

				if portVal != 0 {
					port = nv1.NetworkPolicyPort{
						Port: &intstr.IntOrString{
							Type:   intstr.Int,
							IntVal: int32(portVal),
						},
						Protocol: &protocol,
					}
				} else {
					port = nv1.NetworkPolicyPort{
						Protocol: &protocol,
					}
				}

				if len(eg.ToCIDRs) == 0 {
					to = nv1.NetworkPolicyPeer{
						PodSelector: &metav1.LabelSelector{
							MatchLabels: eg.MatchLabels,
						},
					}
				} else {
					to = nv1.NetworkPolicyPeer{
						IPBlock: &nv1.IPBlock{
							CIDR: eg.ToCIDRs[0].CIDRs[0],
						},
					}
				}

				egressRule.Ports = append(egressRule.Ports, port)
				egressRule.To = append(egressRule.To, to)

				k8NetPol.Spec.Egress = append(k8NetPol.Spec.Egress, egressRule)
			}

			k8NetPol.Spec.PolicyTypes = append(k8NetPol.Spec.PolicyTypes, nv1.PolicyType(nv1.PolicyTypeEgress))
		}

		if len(knp.Spec.Ingress) > 0 {
			for _, ing := range knp.Spec.Ingress {
				var ingressRule nv1.NetworkPolicyIngressRule
				port := nv1.NetworkPolicyPort{}
				var protocol v1.Protocol
				from := nv1.NetworkPolicyPeer{}

				if ing.ToPorts[0].Protocol == string(v1.ProtocolTCP) {
					protocol = v1.ProtocolTCP
				} else if ing.ToPorts[0].Protocol == string(v1.ProtocolUDP) {
					protocol = v1.ProtocolUDP
				}

				portVal, _ := strconv.ParseInt(ing.ToPorts[0].Port, 10, 32)

				if portVal != 0 {
					port = nv1.NetworkPolicyPort{
						Port: &intstr.IntOrString{
							Type:   intstr.Int,
							IntVal: int32(portVal),
						},
						Protocol: &protocol,
					}
				} else {
					port = nv1.NetworkPolicyPort{
						Protocol: &protocol,
					}
				}

				if len(ing.FromCIDRs) == 0 {
					from = nv1.NetworkPolicyPeer{
						PodSelector: &metav1.LabelSelector{
							MatchLabels: ing.MatchLabels,
						},
					}
				} else {
					from = nv1.NetworkPolicyPeer{
						IPBlock: &nv1.IPBlock{
							CIDR: ing.FromCIDRs[0].CIDRs[0],
						},
					}
				}

				ingressRule.Ports = append(ingressRule.Ports, port)
				ingressRule.From = append(ingressRule.From, from)

				k8NetPol.Spec.Ingress = append(k8NetPol.Spec.Ingress, ingressRule)
			}
			k8NetPol.Spec.PolicyTypes = append(k8NetPol.Spec.PolicyTypes, nv1.PolicyType(nv1.PolicyTypeIngress))
		}

		res = append(res, k8NetPol)
	}

	return res
}
