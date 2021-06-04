package systempolicy

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/accuknox/knoxAutoPolicy/src/libs"
	types "github.com/accuknox/knoxAutoPolicy/src/types"
)

var WildPathDigit string = "/[0-9]+"
var WildPathDigitLeaf string = "/[0-9^/]+"
var WildPathChar string = "/.+"
var WildPathCharLeaf string = "/.[^/]+"

var WildPaths []string

const Threshold = 3

func init() {
	WildPaths = []string{WildPathDigit, WildPathChar}
}

// ============================ //
// == PathNode and functions == //
// ============================ //

// Node Structure
type Node struct {
	path  string
	isDir bool

	depth      int
	touchCount int
	childNodes []*Node
}

// MergedNode Structure
type MergedNode struct {
	path string

	depth      int
	touchCount int
}

// HTTPDst Structure
type HTTPDst struct {
	Namespace   string
	MatchLabels string
	ToPorts     []types.SpecPort
	HTTPTree    map[string]map[string]*Node
}

func (n *Node) getChildNodesCount() int {
	results := 0

	for _, childNode := range n.childNodes {
		results = results + childNode.touchCount
	}

	return results
}

func (n *Node) generatePaths(results map[string]bool, parentPath string) {
	for _, childNode := range n.childNodes {
		childNode.generatePaths(results, parentPath+n.path)
	}

	// if this is the leaf node
	if len(n.childNodes) == 0 {
		if n.isDir { // is matchDirectories
			results[parentPath+n.path] = true
		} else { // is matchPaths
			results[parentPath+n.path] = false
		}
	}
}

func (n *Node) insert(paths []string) {
	for _, path := range paths {
		child := n.findChildNode(path, n.depth+1)

		if child == nil {
			newChild := &Node{
				depth:      n.depth + 1,
				path:       path,
				touchCount: 1,
				childNodes: []*Node{},
			}

			n.childNodes = append(n.childNodes, newChild)
			newChild.insert(paths[1:])
		} else {
			child.touchCount++
			child.insert(paths[1:])
		}

		break
	}
}

func (n *Node) aggregateChildNodes() {
	// depth first search
	for _, childNode := range n.childNodes {
		childNode.aggregateChildNodes()
	}

	// #child nodes > threshold --> aggreagte it, and make matchDirectories
	if len(n.childNodes) > Threshold {
		childPaths := []string{}
		for _, childNode := range n.childNodes {
			childPaths = append(childPaths, childNode.path)
		}

		n.childNodes = nil
		n.touchCount = 1 // reset touch count
		n.isDir = true
	}
}

func (n *Node) findChildNode(path string, depth int) *Node {
	for _, child := range n.childNodes {
		// case 1: regex matching
		if libs.ContainsElement(WildPaths, child.path) && child.depth == depth {
			r, _ := regexp.Compile(child.path)
			if r.FindString(path) == path {
				return child
			}
			// case 2: exact matching
		} else if child.path == path && child.depth == depth {
			return child
		}
	}

	return nil
}

func (n *Node) mergeSameChildNodes() {
	if len(n.childNodes) == 0 {
		return
	}

	nodeMap := map[MergedNode][]*Node{}
	nodeMapTouchCount := map[MergedNode]int{}

	merged := false

	for _, childNode := range n.childNodes {
		temp := MergedNode{
			path:  childNode.path,
			depth: childNode.depth,
		}

		// check existing same child nodes
		if exist, ok := nodeMap[temp]; ok {
			exist = append(exist, childNode.childNodes...)
			nodeMap[temp] = exist
			merged = true
		} else {
			nodeMap[temp] = childNode.childNodes
		}

		// merge touch count
		nodeMapTouchCount[temp] = nodeMapTouchCount[temp] + childNode.touchCount
	}

	// if not merged, return
	if !merged {
		return
	}

	n.childNodes = []*Node{}

	for uniqueChildNodes, grandChildNodes := range nodeMap {
		newChildNode := &Node{
			depth:      uniqueChildNodes.depth,
			path:       uniqueChildNodes.path,
			touchCount: nodeMapTouchCount[uniqueChildNodes],
			childNodes: grandChildNodes,
		}

		n.childNodes = append(n.childNodes, newChildNode)
	}
}

// =================== //
// == Tree Handling == //
// =================== //

func findByName(root *Node, path string, depth int) *Node {
	queue := make([]*Node, 0)
	queue = append(queue, root)

	for len(queue) > 0 {
		nextUp := queue[0]
		queue = queue[1:]

		if len(nextUp.childNodes) > 0 {
			for i := 0; i < nextUp.depth; i++ {
				fmt.Print("\t")
			}
			for _, child := range nextUp.childNodes {
				for i := 0; i < child.depth; i++ {
					fmt.Print("\t")
				}
				queue = append(queue, child)
			}
		} else {
			for i := 0; i < nextUp.depth; i++ {
				fmt.Print("\t")
			}
		}
	}

	return nil
}

func printTree(node *Node) {
	for i := 0; i < node.depth; i++ {
		fmt.Print("\t")
	}

	fmt.Println(node.path, node.isDir, node.depth, node.touchCount)

	for _, child := range node.childNodes {
		for i := 0; i < node.depth; i++ {
			fmt.Print("\t")
		}

		printTree(child)
	}
}

func checkSamePathLength(paths []string) bool {
	pathLength := map[int]bool{}

	for _, path := range paths {
		pathLength[len(path)] = true
	}

	if len(pathLength) > 1 {
		return false
	}

	return true
}

func checkDigitsOnly(paths []string) bool {
	isDigit := true

	for _, path := range paths {
		woSlash := strings.Split(path, "/")[1]
		if _, err := strconv.Atoi(woSlash); err != nil {
			isDigit = false
		}
	}

	return isDigit
}

// ===================== //
// == Build Path Tree == //
// ===================== //

func buildPathTree(treeMap map[string]*Node, paths []string) {
	pattern, _ := regexp.Compile("(/.[^/]*)")

	// sorting paths
	sort.Strings(paths)

	// iterate paths
	for _, path := range paths {
		if path == "/" { // rootpath
			continue
		}

		// example: /usr/lib/python2.7/UserDict.py
		// 			--> '/usr', '/lib', '/python2.7', '/UserDict.py'
		//			in this case, '/usr' is rootNode
		tokenizedPaths := pattern.FindAllString(path, -1)
		if len(tokenizedPaths) == 0 {
			continue
		}

		rootPath := tokenizedPaths[0]

		if rootNode, ok := treeMap[rootPath]; !ok {
			newRoot := &Node{
				depth:      0,
				path:       rootPath,
				touchCount: 1,
				childNodes: []*Node{},
			}

			newRoot.insert(tokenizedPaths[1:])
			treeMap[rootPath] = newRoot
		} else {
			rootNode.touchCount++
			rootNode.insert(tokenizedPaths[1:])
		}
	}
}

func AggregatePaths(paths []string) []SysPath {
	treeMap := map[string]*Node{}

	// step 1: build path tree
	// paths := []string{"/usr/lib/python2.7/UserDict.py", "/usr/lib/python2.7/UserDict.pyo"}
	// -->
	// /usr 0 461
	// /lib 1 328
	// 		/python2.7 2 328
	// 				/UserDict.py 3 1
	// 				/UserDict.pyo 3 1
	// ...
	buildPathTree(treeMap, paths)

	// for root, childs := range treeMap {
	// 	fmt.Println(root)
	// 	printTree(childs)
	// }

	// step 2: aggregate path
	for _, root := range treeMap {
		root.aggregateChildNodes()
	}

	// for root, childs := range treeMap {
	// 	fmt.Println(root)
	// 	printTree(childs)
	// }

	// step 3: generate tree -> path string
	aggregatedPaths := map[string]bool{}
	for _, root := range treeMap {
		root.generatePaths(aggregatedPaths, "")
	}

	// step 4: make result
	results := []SysPath{}
	for path, isDir := range aggregatedPaths {
		sysPath := SysPath{
			Path:  path,
			isDir: isDir,
		}
		results = append(results, sysPath)
	}

	return results
}
