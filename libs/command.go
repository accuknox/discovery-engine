package libs

import "os/exec"

// ======================= //
// == Command Execution == //
// ======================= //

// GetCommandOutput Function
func GetCommandOutput(cmd string, args []string) string {
	res := exec.Command(cmd, args...)
	out, err := res.Output()
	if err != nil {
		return ""
	}
	return string(out)
}

// GetCommandOutputWithoutErr Function
func GetCommandOutputWithoutErr(cmd string, args []string) string {
	res := exec.Command(cmd, args...)
	out, _ := res.Output()
	return string(out)
}

// GetCommandWithoutOutput Function
func GetCommandWithoutOutput(cmd string, args []string) {
	res := exec.Command(cmd, args...)
	res.Run()
}
