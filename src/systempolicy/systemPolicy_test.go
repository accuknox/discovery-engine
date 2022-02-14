package systempolicy

import (
	"fmt"
	"strings"
	"testing"

	types "github.com/accuknox/auto-policy-discovery/src/types"
	"github.com/stretchr/testify/assert"
)

// ===================== //
// == Regexp Tests    == //
// ===================== //

func TestRegexp(t *testing.T) {
	var arr = []struct {
		res string
		exp string
	}{
		{
			res: "domain=AF_INET type=SOCK_DGRAM|SOCK_NONBLOCK|SOCK_CLOEXEC protocol=0",
			exp: "udp",
		},
		{
			res: "domain=AF_UNIX type=SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC protocol=0",
			exp: "tcp",
		},
		{
			res: "domain=AF_INET6 type=SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC protocol=0",
			exp: "tcp",
		},
		{
			res: "domain=AF_INET6 type=SOCK_RAW protocol=58", // icmp6
			exp: "icmp",
		},
		{
			res: "domain=AF_NETLINK type=SOCK_RAW protocol=0",
			exp: "raw",
		},
		{
			res: "domain=AF_INET type=SOCK_DGRAM protocol=1",
			exp: "icmp",
		},
		{
			res: "domain=AF_INET type=SOCK_DGRAM protocol=17",
			exp: "udp",
		},
		{
			res: "domain=AF_INET type=SOCK_DGRAM protocol=581",
			exp: "udp",
		},
		{
			res: "domain=AF_INET type=SOCK_DGRAM protocol=0",
			exp: "udp",
		},
		{
			res: "domain=AF_INET6 type=SOCK_DGRAM protocol=58",
			exp: "icmp",
		},
	}

	for idx, test := range arr {
		prot := getProtocolType(test.res)
		fmt.Printf("idx=%d, [%s] got prot=[%s] exp=[%s]\n", idx, test.res, prot, test.exp)
		assert.Equal(t, test.exp, prot)
	}
}

func TestRemoveDuplicates(t *testing.T) {
	out := removeDuplicates([]string{"tcp", "udp", "icmp", "tcp"})
	assert.Equal(t, []string{"icmp", "tcp", "udp"}, out)

	out = removeDuplicates([]string{"raw", "tcp", "tcp", "udp", "udp", "udp", "udp", "raw"})
	assert.Equal(t, []string{"raw", "tcp", "udp"}, out)
}

func addPathSrc(path string, srcs []string, out *types.KnoxSys) {
	var fs []types.KnoxFromSource
	for _, v := range srcs {
		if strings.HasSuffix(v, "/") {
			fs = append(fs, types.KnoxFromSource{Dir: v})
		} else {
			fs = append(fs, types.KnoxFromSource{Path: v})
		}
	}
	if strings.HasSuffix(path, "/") {
		md := types.KnoxMatchDirectories{Dir: path, FromSource: fs}
		(*out).MatchDirectories = append((*out).MatchDirectories, md)
	} else {
		mp := types.KnoxMatchPaths{Path: path, FromSource: fs}
		(*out).MatchPaths = append((*out).MatchPaths, mp)
	}
}

func TestMergeSysPolicies(t *testing.T) {
	pol := types.KnoxSystemPolicy{}

	pol.Metadata = map[string]string{}
	pol.Metadata["clusterName"] = "default"
	pol.Metadata["namespace"] = "default"
	pol.Metadata["containername"] = "kabuntu"
	pol.Metadata["labels"] = "xyz=abc"
	addPathSrc("/usr/bin/ls", []string{"/bin/stash"}, &pol.Spec.File)
	addPathSrc("/usr/abc", []string{"/bin/cash"}, &pol.Spec.File)
	addPathSrc("/usr/bin/ls", []string{"/bin/bash"}, &pol.Spec.File)

	pol2 := types.KnoxSystemPolicy{}
	addPathSrc("/usr/bin/", []string{"/bin/stash"}, &pol2.Spec.File)
	addPathSrc("/usr/abc/", []string{"/bin/cash"}, &pol2.Spec.File)
	addPathSrc("/usr/bin/", []string{"/bin/bash"}, &pol2.Spec.File)

	results := mergeSysPolicies([]types.KnoxSystemPolicy{pol, pol2})
	res := results[0]
	assert.Equal(t, res.Spec.File.MatchPaths[0].Path, "/usr/abc")
	assert.Equal(t, res.Spec.File.MatchPaths[0].FromSource[0].Path, "/bin/cash")

	assert.Equal(t, res.Spec.File.MatchPaths[1].Path, "/usr/bin/ls")
	assert.Equal(t, res.Spec.File.MatchPaths[1].FromSource[0].Path, "/bin/bash")
	assert.Equal(t, res.Spec.File.MatchPaths[1].FromSource[1].Path, "/bin/stash")

	res = results[1]
	// fmt.Println(res)
	assert.Equal(t, res.Spec.File.MatchDirectories[0].Dir, "/usr/abc/")
	assert.Equal(t, res.Spec.File.MatchDirectories[0].FromSource[0].Path, "/bin/cash")

	assert.Equal(t, res.Spec.File.MatchDirectories[1].Dir, "/usr/bin/")
	assert.Equal(t, res.Spec.File.MatchDirectories[1].FromSource[0].Path, "/bin/bash")
	assert.Equal(t, res.Spec.File.MatchDirectories[1].FromSource[1].Path, "/bin/stash")

}

func TestMergeSysPoliciesProcess(t *testing.T) {
	pol := types.KnoxSystemPolicy{}

	pol.Metadata = map[string]string{}
	pol.Metadata["clusterName"] = "default"
	pol.Metadata["namespace"] = "default"
	pol.Metadata["containername"] = "kabuntu"
	pol.Metadata["labels"] = "xyz=abc"
	addPathSrc("/usr/bin/ls", []string{"/bin/stash"}, &pol.Spec.Process)
	addPathSrc("/usr/abc", []string{"/bin/cash"}, &pol.Spec.Process)
	addPathSrc("/usr/bin/ls", []string{"/bin/bash"}, &pol.Spec.Process)

	pol2 := types.KnoxSystemPolicy{}
	addPathSrc("/usr/bin/", []string{"/bin/stash"}, &pol2.Spec.Process)
	addPathSrc("/usr/abc/", []string{"/bin/cash"}, &pol2.Spec.Process)
	addPathSrc("/usr/bin/", []string{"/bin/bash"}, &pol2.Spec.Process)

	results := mergeSysPolicies([]types.KnoxSystemPolicy{pol, pol2})
	res := results[0]
	assert.Equal(t, res.Spec.Process.MatchPaths[0].Path, "/usr/abc")
	assert.Equal(t, res.Spec.Process.MatchPaths[0].FromSource[0].Path, "/bin/cash")

	assert.Equal(t, res.Spec.Process.MatchPaths[1].Path, "/usr/bin/ls")
	assert.Equal(t, res.Spec.Process.MatchPaths[1].FromSource[0].Path, "/bin/bash")
	assert.Equal(t, res.Spec.Process.MatchPaths[1].FromSource[1].Path, "/bin/stash")

	res = results[1]
	// fmt.Println(res)
	assert.Equal(t, res.Spec.Process.MatchDirectories[0].Dir, "/usr/abc/")
	assert.Equal(t, res.Spec.Process.MatchDirectories[0].FromSource[0].Path, "/bin/cash")

	assert.Equal(t, res.Spec.Process.MatchDirectories[1].Dir, "/usr/bin/")
	assert.Equal(t, res.Spec.Process.MatchDirectories[1].FromSource[0].Path, "/bin/bash")
	assert.Equal(t, res.Spec.Process.MatchDirectories[1].FromSource[1].Path, "/bin/stash")

}
