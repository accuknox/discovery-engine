// Code generated by client-gen. DO NOT EDIT.

package fake

import (
	"context"

	securitykubearmorcomv1 "github.com/accuknox/auto-policy-discovery/pkg/discoveredpolicy/api/security.kubearmor.com/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	labels "k8s.io/apimachinery/pkg/labels"
	schema "k8s.io/apimachinery/pkg/runtime/schema"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	testing "k8s.io/client-go/testing"
)

// FakeDiscoveredPolicies implements DiscoveredPolicyInterface
type FakeDiscoveredPolicies struct {
	Fake *FakeSecurityV1
	ns   string
}

var discoveredpoliciesResource = schema.GroupVersionResource{Group: "security.kubearmor.com", Version: "v1", Resource: "discoveredpolicies"}

var discoveredpoliciesKind = schema.GroupVersionKind{Group: "security.kubearmor.com", Version: "v1", Kind: "DiscoveredPolicy"}

// Get takes name of the discoveredPolicy, and returns the corresponding discoveredPolicy object, and an error if there is any.
func (c *FakeDiscoveredPolicies) Get(ctx context.Context, name string, options v1.GetOptions) (result *securitykubearmorcomv1.DiscoveredPolicy, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewGetAction(discoveredpoliciesResource, c.ns, name), &securitykubearmorcomv1.DiscoveredPolicy{})

	if obj == nil {
		return nil, err
	}
	return obj.(*securitykubearmorcomv1.DiscoveredPolicy), err
}

// List takes label and field selectors, and returns the list of DiscoveredPolicies that match those selectors.
func (c *FakeDiscoveredPolicies) List(ctx context.Context, opts v1.ListOptions) (result *securitykubearmorcomv1.DiscoveredPolicyList, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewListAction(discoveredpoliciesResource, discoveredpoliciesKind, c.ns, opts), &securitykubearmorcomv1.DiscoveredPolicyList{})

	if obj == nil {
		return nil, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &securitykubearmorcomv1.DiscoveredPolicyList{ListMeta: obj.(*securitykubearmorcomv1.DiscoveredPolicyList).ListMeta}
	for _, item := range obj.(*securitykubearmorcomv1.DiscoveredPolicyList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested discoveredPolicies.
func (c *FakeDiscoveredPolicies) Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewWatchAction(discoveredpoliciesResource, c.ns, opts))

}

// Create takes the representation of a discoveredPolicy and creates it.  Returns the server's representation of the discoveredPolicy, and an error, if there is any.
func (c *FakeDiscoveredPolicies) Create(ctx context.Context, discoveredPolicy *securitykubearmorcomv1.DiscoveredPolicy, opts v1.CreateOptions) (result *securitykubearmorcomv1.DiscoveredPolicy, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewCreateAction(discoveredpoliciesResource, c.ns, discoveredPolicy), &securitykubearmorcomv1.DiscoveredPolicy{})

	if obj == nil {
		return nil, err
	}
	return obj.(*securitykubearmorcomv1.DiscoveredPolicy), err
}

// Update takes the representation of a discoveredPolicy and updates it. Returns the server's representation of the discoveredPolicy, and an error, if there is any.
func (c *FakeDiscoveredPolicies) Update(ctx context.Context, discoveredPolicy *securitykubearmorcomv1.DiscoveredPolicy, opts v1.UpdateOptions) (result *securitykubearmorcomv1.DiscoveredPolicy, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewUpdateAction(discoveredpoliciesResource, c.ns, discoveredPolicy), &securitykubearmorcomv1.DiscoveredPolicy{})

	if obj == nil {
		return nil, err
	}
	return obj.(*securitykubearmorcomv1.DiscoveredPolicy), err
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
func (c *FakeDiscoveredPolicies) UpdateStatus(ctx context.Context, discoveredPolicy *securitykubearmorcomv1.DiscoveredPolicy, opts v1.UpdateOptions) (*securitykubearmorcomv1.DiscoveredPolicy, error) {
	obj, err := c.Fake.
		Invokes(testing.NewUpdateSubresourceAction(discoveredpoliciesResource, "status", c.ns, discoveredPolicy), &securitykubearmorcomv1.DiscoveredPolicy{})

	if obj == nil {
		return nil, err
	}
	return obj.(*securitykubearmorcomv1.DiscoveredPolicy), err
}

// Delete takes name of the discoveredPolicy and deletes it. Returns an error if one occurs.
func (c *FakeDiscoveredPolicies) Delete(ctx context.Context, name string, opts v1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewDeleteAction(discoveredpoliciesResource, c.ns, name), &securitykubearmorcomv1.DiscoveredPolicy{})

	return err
}

// DeleteCollection deletes a collection of objects.
func (c *FakeDiscoveredPolicies) DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error {
	action := testing.NewDeleteCollectionAction(discoveredpoliciesResource, c.ns, listOpts)

	_, err := c.Fake.Invokes(action, &securitykubearmorcomv1.DiscoveredPolicyList{})
	return err
}

// Patch applies the patch and returns the patched discoveredPolicy.
func (c *FakeDiscoveredPolicies) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *securitykubearmorcomv1.DiscoveredPolicy, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewPatchSubresourceAction(discoveredpoliciesResource, c.ns, name, pt, data, subresources...), &securitykubearmorcomv1.DiscoveredPolicy{})

	if obj == nil {
		return nil, err
	}
	return obj.(*securitykubearmorcomv1.DiscoveredPolicy), err
}
