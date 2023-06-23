package controllers

import "strings"

const (
	// Success
	DspCreated       = "Discovered Policy Has Been Created"
	PolicyIsInactive = "Policy status is Currently Inactive"
	Activated        = "Policy has been deployed and Active"

	// Failures
	UnsupportedPolicyType  = "Provided Policy Kind is not supported"
	ParsingFailed          = "Unable to parse the specified policy"
	ValidationFailed       = "Policy Validation Failed"
	ValidationFailedReason = "Policy NamespacedName should match with dsp NamespacedName"
	UnknownStatus          = "Policy Resource Status is Unknown"
	InactivationFailed     = "Unable to Inactivate the Policy"
	ActivationFailed       = "Policy Activation Failed"
	UpdationFailed         = "Policy Rules Updation Failed"
)

func IsCRDNotInstalledError(err error) bool {
	if strings.Contains(err.Error(), "no matches for kind") {
		return true
	}
	return false
}
