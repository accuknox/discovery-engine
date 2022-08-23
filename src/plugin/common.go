package plugin

import "strings"

func IgnoreLogFromRelayWithNamespace(nsFilter, nsNotFilter []string, namespace string) bool {
	if len(nsFilter) > 0 {
		for _, ns := range nsFilter {
			if !strings.Contains(namespace, ns) {
				return true
			}
		}
	} else if len(nsNotFilter) > 0 {
		for _, notns := range nsNotFilter {
			if strings.Contains(namespace, notns) {
				return true
			}
		}
	}
	return false
}

func IgnoreLogFromRelayWithSource(filter []string, source string) bool {
	for _, srcFilter := range filter {
		if strings.Contains(source, srcFilter) {
			return true
		}
	}
	return false
}
