package core

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/accuknox/knoxAutoPolicy/src/libs"
	types "github.com/accuknox/knoxAutoPolicy/src/types"
)

// WildPathDigit ...
var WildPathDigit string = "/[0-9]+"

// WildPathDigitLeaf ...
var WildPathDigitLeaf string = "/[0-9^/]+"

// WildPathChar ...
var WildPathChar string = "/.+"

// WildPathCharLeaf ...
var WildPathCharLeaf string = "/.[^/]+"

// WildPaths ...
var WildPaths []string

// MergedSrcPerMergedDstForHTTP ...
var MergedSrcPerMergedDstForHTTP map[string][]*HTTPDst

func init() {
	WildPaths = []string{WildPathDigit, WildPathChar}
	MergedSrcPerMergedDstForHTTP = map[string][]*HTTPDst{}
}

// ================== //
// == Get/Set Tree == //
// ================== //

func getHTTPTree(targetSrc string, targetDst MergedPortDst) map[string]map[string]*Node {
	if httpDsts, ok := MergedSrcPerMergedDstForHTTP[targetSrc]; ok {
		for _, httpDst := range httpDsts {
			if targetDst.Namespace == httpDst.Namespace && targetDst.MatchLabels == httpDst.MatchLabels {
				toPortInclude := true

				for _, targetToPort := range targetDst.ToPorts {
					if !libs.ContainsElement(httpDst.ToPorts, targetToPort) {
						toPortInclude = false
					}
				}

				if toPortInclude {
					return httpDst.HTTPTree
				}
			}
		}
	}

	return nil
}

func setHTTPTree(targetSrc string, targetDst MergedPortDst, tree map[string]map[string]*Node) {
	if httpDsts, ok := MergedSrcPerMergedDstForHTTP[targetSrc]; ok {
		for i, httpDst := range httpDsts {
			if targetDst.Namespace == httpDst.Namespace && targetDst.MatchLabels == httpDst.MatchLabels {
				toPortInclude := true

				for _, targetToPort := range targetDst.ToPorts {
					if !libs.ContainsElement(httpDst.ToPorts, targetToPort) {
						toPortInclude = false
					}
				}

				if toPortInclude {
					httpDsts[i].HTTPTree = tree
				}
			}
		}

		MergedSrcPerMergedDstForHTTP[targetSrc] = httpDsts
	} else {
		httpDst := HTTPDst{
			Namespace:   targetDst.Namespace,
			MatchLabels: targetDst.MatchLabels,
			ToPorts:     []types.SpecPort{},
			HTTPTree:    tree,
		}

		for _, toPort := range targetDst.ToPorts {
			httpDst.ToPorts = append(httpDst.ToPorts, toPort)
		}

		MergedSrcPerMergedDstForHTTP[targetSrc] = []*HTTPDst{&httpDst}
	}
}

// ============================ //
// == PathNode and functions == //
// ============================ //

// MergedNode ...
type MergedNode struct {
	path string

	depth      int
	touchCount int
}

// Node ...
type Node struct {
	path string

	depth      int
	touchCount int
	childNodes []*Node
}

func (n *Node) getChildNodesCount() int {
	results := 0

	for _, childNode := range n.childNodes {
		results = results + childNode.touchCount
	}

	return results
}

// generatePaths ...
func (n *Node) generatePaths(results map[string]bool, parentPath string) {
	for _, childNode := range n.childNodes {
		childNode.generatePaths(results, parentPath+n.path)
	}

	// leaf node
	if n.getChildNodesCount() == 0 {
		if libs.ContainsElement(WildPaths, n.path) {
			if n.path == WildPathDigit {
				results[parentPath+WildPathDigitLeaf] = true
			} else {
				results[parentPath+WildPathCharLeaf] = true
			}
		} else {
			results[parentPath+n.path] = true
		}
	} else if n.touchCount > n.getChildNodesCount() {
		// intermediate node
		results[parentPath+n.path] = true
	}
}

// insert ...
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

// aggregateChildNodes ...
func (n *Node) aggregateChildNodes() {
	// depth first iterate
	for _, childNode := range n.childNodes {
		childNode.aggregateChildNodes()
	}

	// step 1: #child nodes > threshold
	if len(n.childNodes) > HTTPUrlThreshold {
		childPaths := []string{}
		for _, childNode := range n.childNodes {
			childPaths = append(childPaths, childNode.path)
		}

		// step 2: check path length
		if !checkSamePathLength(childPaths) {
			return
		}

		wildPath := ""
		if checkDigitsOnly(childPaths) {
			wildPath = WildPathDigit
		} else {
			wildPath = WildPathChar
		}

		tempChild := &Node{
			depth:      n.depth + 1,
			path:       wildPath,
			childNodes: []*Node{},
		}

		//   a     --->   a
		// b   c         temp
		// d   e         d  e
		for _, childNode := range n.childNodes {
			tempChild.touchCount = tempChild.touchCount + childNode.touchCount

			// child node's child node --> grand child
			tempChild.childNodes = append(tempChild.childNodes, childNode.childNodes...)
		}

		// after aggregating child nodes, check same child nodes,
		tempChild.mergeSameChildNodes()

		n.childNodes = []*Node{tempChild}
	}
}

// findChildNode ...
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

// ====================== //
// == Helper Functions == //
// ====================== //

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

	fmt.Println(node.path, node.depth, node.touchCount)

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

	sort.Strings(paths)

	for _, path := range paths {
		if path == "/" { // rootpath
			continue
		}

		tokenizedPaths := pattern.FindAllString(path, -1)
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

// ========================== //
// == Aggreagtion function == //
// ========================== //

// aggreateHTTPPathsNaive function
func aggreateHTTPPathsNaive(paths []string) []string {
	aggregatedPaths := []string{}

	sort.Strings(paths)

	depthToPaths := map[string][]string{}

	pathLevel := 1

	for _, path := range paths {
		// if path in /apple/banana
		if len(strings.Split(path, "/")) >= pathLevel+2 {
			base := "/" + strings.Split(path, "/")[pathLevel]
			if depPaths, ok := depthToPaths[base]; ok {
				if !libs.ContainsElement(depPaths, path) {
					depPaths = append(depPaths, path)
				}
				depthToPaths[base] = depPaths
			} else {
				depthToPaths[base] = []string{path}
			}
		} else {
			// root path or <= depths
			if path == "/" || !libs.ContainsElement(aggregatedPaths, path) {
				aggregatedPaths = append(aggregatedPaths, path)
			}
		}
	}

	for key, paths := range depthToPaths {
		// if threshold over, aggregate it
		if len(paths) >= HTTPUrlThreshold {
			aggregatedPaths = append(aggregatedPaths, key+"/.*")
		} else {
			for _, path := range paths {
				if !libs.ContainsElement(aggregatedPaths, path) {
					aggregatedPaths = append(aggregatedPaths, path)
				}
			}
		}
	}

	return aggregatedPaths
}

// AggregatePaths ...
func AggregatePaths(treeMap map[string]*Node, paths []string) []string {
	// build path tree
	buildPathTree(treeMap, paths)

	// aggregate path
	for _, root := range treeMap {
		root.aggregateChildNodes()
	}

	// generate path
	aggregatedPaths := map[string]bool{}
	for _, root := range treeMap {
		root.generatePaths(aggregatedPaths, "")
	}

	results := []string{}
	for path := range aggregatedPaths {
		results = append(results, path)
	}

	// check root path '/'
	for _, path := range paths {
		if path == "/" {
			results = append(results, path)
		}
	}

	return results
}

// AggregateHTTPRules function
func AggregateHTTPRules(mergedSrcPerMergedDst map[string][]MergedPortDst) {
	for mergedSrc, dsts := range mergedSrcPerMergedDst {
		for i, dst := range dsts {
			// check if dst is for HTTP rules
			if libs.CheckSpecHTTP(dst.Additionals) {
				httpTree := getHTTPTree(mergedSrc, dst)
				if httpTree == nil {
					httpTree = map[string]map[string]*Node{}
				}

				updatedAdditionals := []string{}

				methodToPaths := map[string][]string{}

				for _, http := range dst.Additionals {
					if len(strings.Split(http, "|")) != 2 {
						continue
					}

					method := strings.Split(http, "|")[0]
					path := strings.Split(http, "|")[1]

					if val, ok := methodToPaths[method]; ok {
						if !libs.ContainsElement(val, path) {
							val = append(val, path)
						}
						methodToPaths[method] = val
					} else {
						methodToPaths[method] = []string{path}
					}
				}

				for method, paths := range methodToPaths {
					httpPathTree := map[string]*Node{}
					if existed, ok := httpTree[method]; ok {
						httpPathTree = existed
					}

					aggreatedPaths := AggregatePaths(httpPathTree, paths)
					for _, aggPath := range aggreatedPaths {
						updatedAdditionals = append(updatedAdditionals, method+"|"+aggPath)
					}

					httpTree[method] = httpPathTree
				}

				dsts[i].Additionals = updatedAdditionals

				setHTTPTree(mergedSrc, dst, httpTree)
			}
		}

		mergedSrcPerMergedDst[mergedSrc] = dsts
	}
}
