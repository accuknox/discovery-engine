package systempolicy

import (
	"testing"

	types "github.com/accuknox/auto-policy-discovery/src/types"
)

func TestFilterSystemLogsByConfigProcessDirs(t *testing.T) {
	originalFilters := SystemLogFilters
	defer func() { SystemLogFilters = originalFilters }()

	SystemLogFilters = []types.SystemLogFilter{
		{ProcessDirs: []string{"/usr/bin/"}},
	}

	logs := []types.KnoxSystemLog{
		{
			Namespace: "ns",
			PodName:   "pod",
			Operation: SYS_OP_PROCESS,
			Resource:  "/usr/bin/curl",
			Result:    "Passed",
		},
	}

	filtered := FilterSystemLogsByConfig(logs, nil)
	if len(filtered) != 0 {
		t.Errorf("expected the process dir filter to exclude a resource under /usr/bin/, got %v", filtered)
	}
}
