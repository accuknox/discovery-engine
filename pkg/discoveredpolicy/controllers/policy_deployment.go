package controllers

import (
	"context"
	"reflect"
	"time"

	securityv1 "github.com/accuknox/auto-policy-discovery/pkg/discoveredpolicy/api/security.kubearmor.com/v1"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	kspv1 "github.com/kubearmor/KubeArmor/pkg/KubeArmorController/api/security.kubearmor.com/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

func (r *DiscoveredPolicyReconciler) handleKubeArmorPolicy(ctx context.Context, request ctrl.Request, instance *securityv1.DiscoveredPolicy) (*ctrl.Result, error) {
	cl := log.FromContext(ctx)
	// Convert the CRD manifest to an Runtime object
	// kspv1.AddToScheme(scheme.Scheme)
	decoder := scheme.Codecs.UniversalDeserializer()
	obj, _, err := decoder.Decode(instance.Spec.Policy.Raw, nil, nil)
	if err != nil {
		cl.Error(err, "Unable to parse the policy")

		// update dsp status
		r.updateDiscoveredPolicyStatus(ctx, instance, "Failed", "Unknown", ParsingFailed, err.Error())
		return &ctrl.Result{}, nil
	}
	crd := obj.(*kspv1.KubeArmorPolicy)

	// validate if policy NamespacedName matches with dsp NamespacedName
	if crd.Name != instance.Name || crd.Namespace != instance.Namespace {
		cl.Error(nil, "Validation Failed, policy NamespacedName should match with dsp NamespacedName")
		// update dsp status
		r.updateDiscoveredPolicyStatus(ctx, instance, "Failed", crd.Kind, ValidationFailed, ValidationFailedReason)
		return &ctrl.Result{}, nil
	}

	// TODO: update ksp crd to make capabilities and network as optional rules
	crd.Spec.Capabilities = kspv1.CapabilitiesType{
		MatchCapabilities: append([]kspv1.MatchCapabilitiesType{}, crd.Spec.Capabilities.MatchCapabilities...),
	}
	crd.Spec.Network = kspv1.NetworkType{
		MatchProtocols: append([]kspv1.MatchNetworkProtocolType{}, crd.Spec.Network.MatchProtocols...),
	}
	switch instance.Spec.PolicyStatus {
	case "Inactive", "inactive":
		// if status is "Inactive"
		// make sure the policy should be exists
		pol := &kspv1.KubeArmorPolicy{}
		key := types.NamespacedName{
			Namespace: crd.Namespace,
			Name:      crd.Name,
		}
		if err = r.Client.Get(context.TODO(), key, pol); err != nil {
			if errors.IsNotFound(err) {
				// policy not found,
				// return and don't requeue

				// update dsp status
				r.updateDiscoveredPolicyStatus(ctx, instance, "Success", crd.Kind, DspCreated, PolicyIsInactive)
				return &ctrl.Result{}, nil
			}
			cl.Error(err, "Unable to get status of the policy")

			// update dsp status
			r.updateDiscoveredPolicyStatus(ctx, instance, "Unknown", crd.Kind, UnknownStatus, err.Error())
			return &ctrl.Result{}, err
		}
		// policy found; delete the policy
		if err = r.Client.Delete(context.TODO(), pol); err != nil {
			cl.Error(err, "Unable to delete the policy")

			// update dsp status
			r.updateDiscoveredPolicyStatus(ctx, instance, "Failed", crd.Kind, InactivationFailed, err.Error())
			return &ctrl.Result{}, err
		}
		r.updateDiscoveredPolicyStatus(ctx, instance, "Success", crd.Kind, DspCreated, PolicyIsInactive)
		return &ctrl.Result{}, nil
	case "Active", "active":
		// if policy is "Active"
		// make sure there's a policy with specified rules
		pol := &kspv1.KubeArmorPolicy{}
		key := types.NamespacedName{
			Namespace: crd.Namespace,
			Name:      crd.Name,
		}
		if err = r.Client.Get(context.TODO(), key, pol); err != nil {
			if errors.IsNotFound(err) {
				// policy not found; create one
				err = r.Client.Create(context.TODO(), crd, &client.CreateOptions{})
				if err != nil {
					cl.Error(err, "Unable to Create Policy")

					// update dsp status
					r.updateDiscoveredPolicyStatus(ctx, instance, "Failed", crd.Kind, ActivationFailed, err.Error())
					return &ctrl.Result{}, err
				}
				r.updateDiscoveredPolicyStatus(ctx, instance, "Success", crd.Kind, Activated, "")
				return &ctrl.Result{}, nil
			}
		}
		// policy found; update the policy
		// check if policy rules are updated
		if !reflect.DeepEqual(crd.Spec, pol.Spec) {
			// update the policy
			patch := client.MergeFrom(pol.DeepCopy())
			pol.Spec = crd.Spec
			if err = r.Client.Patch(ctx, pol, patch); err != nil {
				cl.Error(err, "Unable to Update the Policy")
				// update dsp status
				r.updateDiscoveredPolicyStatus(ctx, instance, "Failed", crd.Kind, UpdationFailed, err.Error())
				return &ctrl.Result{}, err
			}
		}
		// nothing to be done; update dsp status
		r.updateDiscoveredPolicyStatus(ctx, instance, "Success", crd.Kind, Activated, "")
	}

	return &ctrl.Result{}, nil
}

func (r *DiscoveredPolicyReconciler) handleK8sNetworkPolicy(ctx context.Context, request ctrl.Request, instance *securityv1.DiscoveredPolicy) (*ctrl.Result, error) {
	cl := log.FromContext(ctx)
	// Convert the CRD manifest to an Runtime object
	// networkingv1.AddToScheme(scheme.Scheme)
	decoder := scheme.Codecs.UniversalDeserializer()
	obj, _, err := decoder.Decode(instance.Spec.Policy.Raw, nil, nil)
	if err != nil {
		cl.Error(err, "Unable to parse the policy")

		// update dsp status
		r.updateDiscoveredPolicyStatus(ctx, instance, "Failed", "Unknown", ParsingFailed, err.Error())
		return &ctrl.Result{}, nil
	}
	crd := obj.(*networkingv1.NetworkPolicy)

	// validate if policy NamespacedName matches with dsp NamespacedName
	if crd.Name != instance.Name || crd.Namespace != instance.Namespace {
		cl.Error(nil, "Validation Failed, policy NamespacedName should match with dsp NamespacedName")
		// update dsp status
		r.updateDiscoveredPolicyStatus(ctx, instance, "Failed", crd.Kind, ValidationFailed, ValidationFailedReason)
		return &ctrl.Result{}, nil
	}

	switch instance.Spec.PolicyStatus {
	case "Inactive", "inactive":
		// if status is "Inactive"
		// make sure the policy should be exists
		pol := &networkingv1.NetworkPolicy{}
		key := types.NamespacedName{
			Namespace: crd.Namespace,
			Name:      crd.Name,
		}
		if err = r.Client.Get(context.TODO(), key, pol); err != nil {
			if errors.IsNotFound(err) {
				// policy not found,
				// return and don't requeue
				// update dsp status
				r.updateDiscoveredPolicyStatus(ctx, instance, "Success", crd.Kind, DspCreated, PolicyIsInactive)
				return &ctrl.Result{}, nil
			}
			cl.Error(err, "Unable to get status of the policy")

			// update dsp status
			r.updateDiscoveredPolicyStatus(ctx, instance, "Unknown", crd.Kind, UnknownStatus, err.Error())
			return &ctrl.Result{}, err
		}
		// policy found; delete the policy
		if err = r.Client.Delete(context.TODO(), pol); err != nil {
			cl.Error(err, "Unable to delete the policy")
			// update dsp status
			r.updateDiscoveredPolicyStatus(ctx, instance, "Failed", crd.Kind, InactivationFailed, err.Error())
			return &ctrl.Result{}, err
		}
		r.updateDiscoveredPolicyStatus(ctx, instance, "Success", crd.Kind, DspCreated, PolicyIsInactive)
		return &ctrl.Result{}, nil
	case "Active", "active":
		// if policy is "Active"
		// make sure there's a policy with specified rules
		pol := &networkingv1.NetworkPolicy{}
		key := types.NamespacedName{
			Namespace: crd.Namespace,
			Name:      crd.Name,
		}
		if err = r.Client.Get(context.TODO(), key, pol); err != nil {
			if errors.IsNotFound(err) {
				// policy not found; create one
				err = r.Client.Create(context.TODO(), crd, &client.CreateOptions{})
				if err != nil {
					cl.Error(err, "Unable to Create Policy")
					// update dsp status
					r.updateDiscoveredPolicyStatus(ctx, instance, "Failed", crd.Kind, ActivationFailed, err.Error())
					return &ctrl.Result{}, err
				}
				r.updateDiscoveredPolicyStatus(ctx, instance, "Success", crd.Kind, Activated, "")
				return &ctrl.Result{}, nil
			}
		}
		// policy found; update the policy
		// check if policy rules are updated
		if !reflect.DeepEqual(crd.Spec, pol.Spec) {
			// update the policy
			patch := client.MergeFrom(pol.DeepCopy())
			pol.Spec = crd.Spec
			if err = r.Client.Patch(ctx, pol, patch); err != nil {
				cl.Error(err, "Unable to Update the Policy")
				// update dsp status
				r.updateDiscoveredPolicyStatus(ctx, instance, "Failed", crd.Kind, UpdationFailed, err.Error())
				return &ctrl.Result{}, err
			}
		}
		// nothing to be done; update dsp status
		r.updateDiscoveredPolicyStatus(ctx, instance, "Success", crd.Kind, Activated, "")
	}

	return &ctrl.Result{}, nil
}

func (r *DiscoveredPolicyReconciler) handleCiliumNetworkPolicy(ctx context.Context, request ctrl.Request, instance *securityv1.DiscoveredPolicy) (*ctrl.Result, error) {
	cl := log.FromContext(ctx)
	// Convert the CRD manifest to an Runtime object
	// ciliumv2.AddToScheme(scheme.Scheme)
	decoder := scheme.Codecs.UniversalDeserializer()
	obj, _, err := decoder.Decode(instance.Spec.Policy.Raw, nil, nil)
	if err != nil {
		cl.Error(err, "Unable to parse the policy")
		// update dsp status
		r.updateDiscoveredPolicyStatus(ctx, instance, "Failed", "Unknown", ParsingFailed, err.Error())
		return &ctrl.Result{}, nil
	}
	crd := obj.(*ciliumv2.CiliumNetworkPolicy)

	// validate if policy NamespacedName matches with dsp NamespacedName
	if crd.Name != instance.Name || crd.Namespace != instance.Namespace {
		cl.Error(nil, "Validation Failed, policy NamespacedName should match with dsp NamespacedName")
		// update dsp status
		r.updateDiscoveredPolicyStatus(ctx, instance, "Failed", crd.Kind, ValidationFailed, ValidationFailedReason)
		return &ctrl.Result{}, nil
	}

	switch instance.Spec.PolicyStatus {
	case "Inactive", "inactive":
		// if status is "Inactive"
		// make sure the policy should be exists
		pol := &ciliumv2.CiliumNetworkPolicy{}
		key := types.NamespacedName{
			Namespace: crd.Namespace,
			Name:      crd.Name,
		}
		if err = r.Client.Get(context.TODO(), key, pol); err != nil {
			if errors.IsNotFound(err) {
				// policy not found,
				// return and don't requeue
				r.updateDiscoveredPolicyStatus(ctx, instance, "Success", crd.Kind, DspCreated, PolicyIsInactive)
				return &ctrl.Result{}, nil
			}
			cl.Error(err, "Unable to get status of the policy")

			// update dsp status
			r.updateDiscoveredPolicyStatus(ctx, instance, "Unknown", crd.Kind, UnknownStatus, err.Error())
			return &ctrl.Result{}, err
		}
		// policy found; delete the policy
		if err = r.Client.Delete(context.TODO(), pol); err != nil {
			cl.Error(err, "Unable to delete the policy")
			// update dsp status
			r.updateDiscoveredPolicyStatus(ctx, instance, "Failed", crd.Kind, InactivationFailed, err.Error())
			return &ctrl.Result{}, err
		}
		r.updateDiscoveredPolicyStatus(ctx, instance, "Success", crd.Kind, DspCreated, PolicyIsInactive)
		return &ctrl.Result{}, nil
	case "Active", "active":
		// if policy is "Active"
		// make sure there's a policy with specified rules
		pol := &ciliumv2.CiliumNetworkPolicy{}
		key := types.NamespacedName{
			Namespace: crd.Namespace,
			Name:      crd.Name,
		}
		if err = r.Client.Get(context.TODO(), key, pol); err != nil {
			if errors.IsNotFound(err) {
				// policy not found; create one
				err = r.Client.Create(context.TODO(), crd, &client.CreateOptions{})
				if err != nil {
					cl.Error(err, "Unable to Create Policy")
					// update dsp status
					r.updateDiscoveredPolicyStatus(ctx, instance, "Failed", crd.Kind, ActivationFailed, err.Error())
					return &ctrl.Result{}, err
				}
				r.updateDiscoveredPolicyStatus(ctx, instance, "Success", crd.Kind, Activated, "")
				return &ctrl.Result{}, nil
			}
		}
		// policy found; update the policy
		// check if policy rules are updated
		if !reflect.DeepEqual(crd.Spec, pol.Spec) {
			// update the policy
			patch := client.MergeFrom(pol.DeepCopy())
			pol.Spec = crd.Spec
			if err = r.Client.Patch(ctx, pol, patch); err != nil {
				cl.Error(err, "Unable to Update the Policy")
				// update dsp status
				r.updateDiscoveredPolicyStatus(ctx, instance, "Failed", crd.Kind, UpdationFailed, err.Error())
				return &ctrl.Result{}, err
			}
		}
		// nothing to be done; update dsp status
		r.updateDiscoveredPolicyStatus(ctx, instance, "Success", crd.Kind, Activated, "")
	}

	return &ctrl.Result{}, nil
}

func (r *DiscoveredPolicyReconciler) updateDiscoveredPolicyStatus(ctx context.Context, instance *securityv1.DiscoveredPolicy, phase securityv1.PolicyPhaseType, kind, message, reason string) {
	cl := log.FromContext(ctx)

	// check if status changed

	if !isStatusChanged(instance, phase, kind, message, reason) {
		return
	}

	// update dsp status if it's changed
	patch := client.MergeFrom(instance.DeepCopy())
	instance.Status.PolicyPhase = phase
	instance.Status.PolicyKind = kind
	instance.Status.LastUpdatedTime = metav1.NewTime(time.Now())
	instance.Status.Message = message
	instance.Status.Reason = reason

	if err := r.Client.Status().Patch(ctx, instance, patch); err != nil {
		cl.Error(err, "Unable to update the status")
	}
}

func isStatusChanged(instance *securityv1.DiscoveredPolicy, phase securityv1.PolicyPhaseType, kind, message, reason string) bool {
	if instance.Status.PolicyPhase != phase {
		return true
	}
	if instance.Status.PolicyKind != kind {
		return true
	}
	if instance.Status.Message != message {
		return true
	}
	if instance.Status.Reason != reason {
		return true
	}
	return false
}

func init() {
	utilruntime.Must(kspv1.AddToScheme(scheme.Scheme))
	utilruntime.Must(ciliumv2.AddToScheme(scheme.Scheme))
	utilruntime.Must(networkingv1.AddToScheme(scheme.Scheme))
}
