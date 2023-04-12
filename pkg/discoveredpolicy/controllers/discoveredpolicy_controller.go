package controllers

import (
	"context"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	securityv1 "github.com/accuknox/auto-policy-discovery/pkg/discoveredpolicy/api/security.kubearmor.com/v1"
)

// DiscoveredPolicyReconciler reconciles a DiscoveredPolicy object
type DiscoveredPolicyReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

//+kubebuilder:rbac:groups=security.kubearmor.com,resources=discoveredpolicies,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=security.kubearmor.com,resources=discoveredpolicies/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=security.kubearmor.com,resources=discoveredpolicies/finalizers,verbs=update
//+kubebuilder:rbac:groups=security.kubearmor.com,resources=kubearmorpolicies,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=cilium.io,resources=ciliumnetworkpolicies,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=networking.k8s.io,resources=networkpolicies,verbs=get;list;watch;create;update;patch;delete

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the DiscoveredPolicy object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.14.1/pkg/reconcile
func (r *DiscoveredPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	_ = log.FromContext(ctx)

	cr := &securityv1.DiscoveredPolicy{}
	if err := r.Get(ctx, req.NamespacedName, cr); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Check if the resource is being deleted
	if !cr.ObjectMeta.DeletionTimestamp.IsZero() {
		return r.DeletionReconciler(ctx, cr)
	}
	// The resource is being created or updated
	return r.CreateOrUpdateReconciler(ctx, req, cr)
}

func (r *DiscoveredPolicyReconciler) CreateOrUpdateReconciler(ctx context.Context, req ctrl.Request, crInstance *securityv1.DiscoveredPolicy) (ctrl.Result, error) {
	// first Check if Policy is PendingUpdates, if it is then nothing to be done here
	if crInstance.Spec.PolicyStatus == "PendingUpdates" {
		return ctrl.Result{}, nil
	}

	obj := &unstructured.Unstructured{}
	_, gvk, _ := unstructured.UnstructuredJSONScheme.Decode([]byte(crInstance.Spec.Policy.Raw), nil, obj)

	switch gvk.Kind {
	case "KubeArmorPolicy":
		res, err := r.handleKubeArmorPolicy(ctx, req, crInstance)
		if err != nil && isRecoverableError(err) {
			return *res, err
		}
	case "CiliumNetworkPolicy":
		res, err := r.handleCiliumNetworkPolicy(ctx, req, crInstance)
		if err != nil && isRecoverableError(err) {
			return *res, err
		}
	case "NetworkPolicy":
		res, err := r.handleK8sNetworkPolicy(ctx, req, crInstance)
		if err != nil && isRecoverableError(err) {
			return *res, err
		}
	default:
		r.updateDiscoveredPolicyStatus(ctx, crInstance, "Failed", gvk.Kind, UnsupportedPolicyType, "")
	}

	return ctrl.Result{}, nil
}

func (r *DiscoveredPolicyReconciler) DeletionReconciler(ctx context.Context, cr *securityv1.DiscoveredPolicy) (ctrl.Result, error) {
	//
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *DiscoveredPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&securityv1.DiscoveredPolicy{}).
		Complete(r)
}

func isRecoverableError(err error) bool {
	if errors.IsInvalid(err) {
		return false
	}
	if IsCRDNotInstalledError(err) {
		return false
	}
	return true
}
