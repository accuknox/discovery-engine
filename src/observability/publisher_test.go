package observability

import (
	"encoding/json"
	"io"
	"os"
	"testing"

	logger "github.com/accuknox/auto-policy-discovery/src/logging"
	"github.com/accuknox/auto-policy-discovery/src/types"
	"github.com/stretchr/testify/assert"
)

var inputSummaryFileName = "./../../tests/observability/input-summary.json"
var aggSummaryFileName = "./../../tests/observability/agg-summary.json"

type SystemSummary struct {
	SummaryData types.SystemSummary       `json:"summaryData"`
	TimeCount   types.SysSummaryTimeCount `json:"timeCount"`
}

func makeSummaryMapFromTestCase(summaryData []SystemSummary, summaryMap map[types.SystemSummary]types.SysSummaryTimeCount) {

	for _, ss := range summaryData {
		summaryMap[ss.SummaryData] = ss.TimeCount
	}

}

func initTestCase(t *testing.T, summaryMap, expectedSummaryMap map[types.SystemSummary]types.SysSummaryTimeCount) {
	for expectedSummary, expectedSummaryCount := range expectedSummaryMap {
		actualSummaryCount, ok := summaryMap[expectedSummary]
		assert.True(t, ok, "Expected SummaryTimeCount not found in summaryMap")
		assert.Equal(t, expectedSummaryCount.Count, actualSummaryCount.Count)
		assert.Equal(t, expectedSummaryCount.UpdatedTime, actualSummaryCount.UpdatedTime)
		log.Info().Msgf("Found:\n   PodName: %v,\n   Source: %v,\n   Destination: %v,\n   Operation: %v\n   Expected Count: %v\n   Actual Count: %v\n", expectedSummary.PodName, expectedSummary.Source, expectedSummary.Destination, expectedSummary.Operation, expectedSummaryCount.Count, actualSummaryCount.Count)
		delete(expectedSummaryMap, expectedSummary)
		delete(summaryMap, expectedSummary)
	}
}

func Test_getAggregatedSummaryMap(t *testing.T) {

	log = logger.GetInstance()
	summaryMap := make(map[types.SystemSummary]types.SysSummaryTimeCount)
	expectedSummaryMap := make(map[types.SystemSummary]types.SysSummaryTimeCount)

	log.Info().Msgf("Using raw summary data input from %v\n", inputSummaryFileName)
	log.Info().Msgf("Using aggregated summary data input from %v\n", aggSummaryFileName)

	tempSummaryMap := parseSystemSummary(inputSummaryFileName)
	tempExpectedSummaryMap := parseSystemSummary(aggSummaryFileName)

	assert.NotEmpty(t, tempSummaryMap)
	assert.NotEmpty(t, tempExpectedSummaryMap)

	for testCase, summaryData := range tempSummaryMap {
		expectedSummaryData, ok := tempExpectedSummaryMap[testCase]
		if ok {
			makeSummaryMapFromTestCase(summaryData, summaryMap)
			makeSummaryMapFromTestCase(expectedSummaryData, expectedSummaryMap)
			delete(tempSummaryMap, testCase)
			delete(tempExpectedSummaryMap, testCase)
			log.Info().Msgf("Before aggregation length of summary data: %v\n", len(summaryMap))

			aggregateSummaryMap(summaryMap)

			log.Info().Msgf("After aggregation length of summary data (summaryMap): %v\n", len(summaryMap))
			log.Info().Msgf("Initiating TestCase\n")
			assert.Equal(t, len(expectedSummaryMap), len(summaryMap), "After aggregation len(summaryMap) should be equal to len(aggSummaryMap)")
			log.Info().Msgf("After aggregation len(summaryMap): %v , len(expectedSummaryMap): %v\n", len(summaryMap), len(expectedSummaryMap))
			initTestCase(t, summaryMap, expectedSummaryMap)

		}
	}

}

// parseSystemSummary reads system summary data from a file
func parseSystemSummary(fileName string) map[string][]SystemSummary {

	var data map[string][]SystemSummary

	file, err := os.Open(fileName)
	if err != nil {
		log.Fatal().Err(err)
		return nil
	}
	defer file.Close()

	content, err := io.ReadAll(file)
	if err != nil {
		log.Error().Msgf("File read error: %v\n", err)
		return nil
	}

	err = json.Unmarshal([]byte(content), &data)
	if err != nil {
		log.Error().Msgf("Unmarshal error: %v\n", err)
		return nil
	}

	return data
}
