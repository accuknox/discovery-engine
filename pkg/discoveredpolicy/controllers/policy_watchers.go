package controllers

import (
	"context"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	patchTypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/dynamic/dynamicinformer"
	"k8s.io/client-go/tools/cache"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

var (
	// resources
	kspResource = schema.GroupVersionResource{
		Group:    "security.kubearmor.com",
		Version:  "v1",
		Resource: "kubearmorpolicies",
	}
	ciliumPolicyResource = schema.GroupVersionResource{
		Group:    "cilium.io",
		Version:  "v2",
		Resource: "ciliumnetworkpolicies",
	}
	networkPolicyResource = schema.GroupVersionResource{
		Group:    "networking.k8s.io",
		Version:  "v1",
		Resource: "networkpolicies",
	}
	dspResource = schema.GroupVersionResource{
		Group:    "security.kubearmor.com",
		Version:  "v1",
		Resource: "discoveredpolicies",
	}
)

// PolicyWatcher type
type PolicyWatcher struct {
	Log                   logr.Logger
	Client                *dynamic.DynamicClient
	KspInformer           cache.SharedIndexInformer
	CiliumInformer        cache.SharedIndexInformer
	NetworkPolicyInformer cache.SharedIndexInformer
}

// NewPolicyWatcher func
func NewPolicyWatcher() (*PolicyWatcher, error) {
	var err error
	pw := &PolicyWatcher{}
	pw.Client, err = initDynamicClient()
	if err != nil {
		return nil, err
	}
	pw.Log = log.FromContext(context.TODO())
	pw.KspInformer, err = pw.CreateInformer(kspResource)
	if err != nil {
		return nil, err
	}
	pw.CiliumInformer, err = pw.CreateInformer(ciliumPolicyResource)
	if err != nil {
		return nil, err
	}
	pw.NetworkPolicyInformer, err = pw.CreateInformer(networkPolicyResource)
	if err != nil {
		return nil, err
	}
	return pw, nil
}

func initDynamicClient() (*dynamic.DynamicClient, error) {
	client, err := dynamic.NewForConfig(ctrl.GetConfigOrDie())
	if err != nil {
		return nil, err
	}
	return client, nil
}

// CreateInformer func
func (p *PolicyWatcher) CreateInformer(gvr schema.GroupVersionResource) (cache.SharedIndexInformer, error) {
	// Create an informer factory using the dynamic client.
	informerFactory := dynamicinformer.NewDynamicSharedInformerFactory(p.Client, time.Second*30)

	// informers
	Informer := informerFactory.ForResource(gvr).Informer()

	// event handlers for kspInformer
	if _, err := Informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		DeleteFunc: func(obj interface{}) {
			// update dsp policy status
			pol := obj.(*unstructured.Unstructured)
			dsp, err := p.Client.
				Resource(dspResource).
				Namespace(pol.GetNamespace()).
				Get(context.TODO(), pol.GetName(), metav1.GetOptions{})
			if err != nil {
				if errors.IsNotFound(err) {
					// nothing to be done here
					return
				}
				p.Log.Error(err, "Unable to get discovered policy resource")
				return
			}
			// update dsp policy status to inactive
			patch := []byte(`{"spec": {"status": "Inactive"}}`)
			_, err = p.Client.Resource(dspResource).
				Namespace(dsp.GetNamespace()).
				Patch(context.TODO(), dsp.GetName(), patchTypes.MergePatchType, patch, metav1.PatchOptions{})
			if err != nil {
				p.Log.Error(err, "Unable to revert discovered policy status back to inactive")
				return
			}

		},
	}); err != nil {
		return nil, err
	}

	return Informer, nil

}

// StartWatchers func
func (p *PolicyWatcher) StartWatchers(stopCh <-chan struct{}) error {
	if p.IsAPIResourceAvailable(kspResource) {
		if p.KspInformer == nil {
			return fmt.Errorf("Failed to initialize informer")
		}
		go p.KspInformer.Run(stopCh)
		// Wait for the informer to sync.
		if ok := cache.WaitForCacheSync(stopCh, p.KspInformer.HasSynced); !ok {
			return fmt.Errorf("Failed to wait for cache sync")
		}
	}

	if p.IsAPIResourceAvailable(ciliumPolicyResource) {
		if p.CiliumInformer == nil {
			return fmt.Errorf("Failed to initialize informer")
		}
		go p.CiliumInformer.Run(stopCh)
		// Wait for the informer to sync.
		if ok := cache.WaitForCacheSync(stopCh, p.CiliumInformer.HasSynced); !ok {
			return fmt.Errorf("Failed to wait for cache sync")
		}
	}

	if p.IsAPIResourceAvailable(networkPolicyResource) {
		if p.NetworkPolicyInformer == nil {
			return fmt.Errorf("Failed to initialize informer")
		}
		go p.NetworkPolicyInformer.Run(stopCh)
		// Wait for the informer to sync.
		if ok := cache.WaitForCacheSync(stopCh, p.NetworkPolicyInformer.HasSynced); !ok {
			return fmt.Errorf("Failed to wait for cache sync")
		}
	}

	return nil
}

// IsAPIResourceAvailable func
func (p *PolicyWatcher) IsAPIResourceAvailable(gvr schema.GroupVersionResource) bool {
	// create a discovery client for the given config
	dc, err := discovery.NewDiscoveryClientForConfig(ctrl.GetConfigOrDie())
	if err != nil {
		p.Log.Error(err, "Error creating discovery client")
		return false
	}
	apiResources, err := dc.ServerResourcesForGroupVersion(gvr.GroupVersion().String())
	if err != nil {
		errMsg := fmt.Sprintf("Error getting server resources: %s", gvr.Resource)
		p.Log.Error(err, errMsg)
		return false
	}

	// check if the ciliumnetworkpolicies resource is available
	for _, resource := range apiResources.APIResources {
		if resource.Name == gvr.Resource {
			p.Log.Info("api resource is available", "apiResource", gvr.Resource)
			return true
		}
	}

	return false
}
