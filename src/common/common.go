package common

import (
	"fmt"
	"hash/fnv"
	"strings"
)

// Basic Constant
const (
	STATUS     = "Passed"
	LIMIT      = " limit "
	BACK_SLASH = "\""
	COMMA      = ","
	QUOTATION  = `"`
	INGRESS    = "INGRESS"
	EGRESS     = "EGRESS"
	FORWARDED  = "FORWARDED"
	DROPPED    = "DROPPED"
	ERROR      = "ERROR"
	AUDIT      = "AUDIT"
	L7         = "L7"
	L3_L4      = "L3_L4"
)

// Query Constant
const (
	WHERE_NAMESPACE_NAME  = ` where namespace_name = "`
	WHERE                 = ` where `
	AND                   = ` and `
	VERDICT               = `verdict = `
	TYPE                  = `type = `
	TRAFFIC_DIRECTION     = `traffic_direction = `
	ORDER_BY_UPDATED_TIME = ` order by updated_time DESC`
)

// Error Constant
const (
	INCORRECT_DIRECTION = "incorrect direction"
	INCORRECT_VERDICT   = "incorrect verdict"
	INCORRECT_TYPE      = "incorrect type"
)

// ConvertArrayToString - Convert Array of string to String
func ConvertArrayToString(arr []string) string {
	var str string
	for _, label := range arr {
		if !strings.HasPrefix(label, "k8s:io.cilium.") {
			if !strings.HasPrefix(label, "k8s:io.kubernetes.") {
				tstr := strings.TrimPrefix(label, "k8s:")
				if str != "" {
					str += COMMA
				}
				str += tstr
			}
		}
	}
	return str

}

// ConvertStringToArray - Convert String to Array of string
func ConvertStringToArray(str string) []string {
	return strings.Split(str, ",")
}

func ConvertFilterString(filter []string) string {
	var query string
	//Create the filter query
	for i, value := range filter {
		query = query + BACK_SLASH + fmt.Sprint(value) + BACK_SLASH
		if len(filter) > i+1 {
			query += COMMA
		}
	}
	return query
}

func StringDeDuplication(strSlice []string) []string {
	keys := make(map[string]bool)
	list := []string{}
	for _, entry := range strSlice {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}

func HashInt(s string) uint32 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(s))
	return h.Sum32()
}
