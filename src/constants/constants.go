package constants

//Basic Constant
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

//Query Constant
const (
	WHERE_NAMESPACE_NAME  = ` where namespace_name = "`
	WHERE                 = ` where `
	AND                   = ` and `
	VERDICT               = `verdict = `
	TYPE                  = `type = `
	TRAFFIC_DIRECTION     = `traffic_direction = `
	ORDER_BY_UPDATED_TIME = ` order by updated_time DESC`
)

//Error Constant
const (
	INCORRECT_DIRECTION = "incorrect direction"
	INCORRECT_VERDICT   = "incorrect verdict"
	INCORRECT_TYPE      = "incorrect type"
)
