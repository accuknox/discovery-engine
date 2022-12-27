package observability

import (
	"testing"

	types "github.com/accuknox/auto-policy-discovery/src/types"
	pb "github.com/kubearmor/KubeArmor/protobuf"
)

func TestExtractSyscallInfoFromSystemLog(t *testing.T) {
	sysCallLog := pb.Alert{
		ClusterName:       "default",
		HostName:          "ubuntu-yasin",
		Labels:            "app=wordpress",
		ContainerName:     "wordpress",
		ContainerID:       "98aca523b49b857598cad5127448db05680851205f8e37a546e757c2a18c5f3e",
		ContainerImage:    "docker.io/library/wordpress:4.8-apache@sha256:6216f64ab88fc51d311e38c7f69ca3f9aaba621492b4f1fa93ddf63093768845",
		Type:              "ContainerLog",
		Source:            "/bin/chown www-data:www-data .htaccess",
		Resource:          ".htaccess",
		Operation:         "Syscall",
		Data:              "syscall=SYS_FCHOWNAT userid=33 group=33 mode=0",
		Result:            "Passed",
		HostPID:           134718,
		HostPPID:          134643,
		PID:               12,
		PPID:              1,
		ParentProcessName: "/bin/bash",
		ProcessName:       "/bin/chown",
	}

	pods := []types.Pod{}
	services := []types.Service{}

	parentProcess, childProcess, syscall, parameters, err := extractSyscallInfoFromSystemLog(sysCallLog, pods, services)
	if err != nil {
		t.Fatalf("Expected no error but got %v", err)
	}
	if parentProcess != "/bin/bash" {
		t.Errorf("Expected /bin/bash but got %v", parentProcess)
	}
	if childProcess != "/bin/chown" {
		t.Errorf("Expected /bin/chown but got %v", childProcess)
	}
	if syscall != "SYS_FCHOWNAT" {
		t.Errorf("Expected SYS_FCHOWNAT but got %v", syscall)
	}
	if parameters != "userid=33 group=33 mode=0" {
		t.Errorf("Expected userid=33 group=33 mode=0 but got %v", parameters)
	}

	// Check for other type of logs
	invalidSysCallLog := pb.Alert{
		Operation: "Others",
	}
	_, _, _, _, err = extractSyscallInfoFromSystemLog(invalidSysCallLog, pods, services)
	if err == nil {
		t.Errorf("Expected an error but got none")
	}
}
