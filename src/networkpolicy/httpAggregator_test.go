package networkpolicy

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// ============================ //
// == PathNode and functions == //
// ============================ //

func TestGetChildNodesCount(t *testing.T) {
	node := &Node{}
	node.childNodes = []*Node{{
		path:       "/",
		touchCount: 1,
	}}

	actual := node.getChildNodesCount()

	assert.Equal(t, 1, actual)
}
