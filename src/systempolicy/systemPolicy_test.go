package systempolicy

import (
	"fmt"
	"testing"

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
			exp: "icmp,icmp6",
		},
		{
			res: "domain=AF_NETLINK type=SOCK_RAW protocol=0",
			exp: "raw",
		},
		{
			res: "domain=AF_INET type=SOCK_DGRAM protocol=1",
			exp: "icmp,icmp6",
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
			exp: "icmp,icmp6",
		},
	}

	for idx, test := range arr {
		prot := getProtocolType(test.res)
		fmt.Printf("idx=%d, [%s] got prot=[%s] exp=[%s]\n", idx, test.res, prot, test.exp)
		assert.Equal(t, test.exp, prot)
	}
}

func TestRemoveDuplicates(t *testing.T) {
	out := removeDuplicates([]string{"tcp", "udp", "icmp", "icmp6", "tcp"})
	assert.Equal(t, []string{"icmp", "icmp6", "tcp", "udp"}, out)

	out = removeDuplicates([]string{"raw", "tcp", "tcp", "udp", "udp", "udp", "udp", "raw"})
	assert.Equal(t, []string{"raw", "tcp", "udp"}, out)
}
