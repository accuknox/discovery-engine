package libs

import (
	"time"

	"github.com/rs/zerolog/log"
)

var dbDriver string

func init() {
	dbDriver = GetEnv("DB_DRIVER", "mysql")
}

// GetTrafficFlowFromDB function
func GetTrafficFlowFromDB(startTime, endTime int64) ([]map[string]interface{}, bool) {
	results := []map[string]interface{}{}

	if dbDriver == "mysql" {

	} else if dbDriver == "mongodb" {
		if docs, valid := GetTrafficFlowFromMongo(startTime, endTime); valid {
			results = docs
		} else {
			return nil, false
		}
	} else {
		return nil, false
	}

	if len(results) == 0 {
		log.Info().Msgf("Traffic flow not exist: from %s ~ to %s",
			time.Unix(startTime, 0).Format(TimeFormSimple),
			time.Unix(endTime, 0).Format(TimeFormSimple))

		return nil, false
	}

	log.Info().Msgf("The total number of traffic flow: [%d] from %s ~ to %s", len(results),
		time.Unix(startTime, 0).Format(TimeFormSimple),
		time.Unix(endTime, 0).Format(TimeFormSimple))

	return results, true
}
