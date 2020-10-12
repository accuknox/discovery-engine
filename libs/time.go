package libs

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// ========== //
// == Time == //
// ========== //

// Time Format
const (
	TimeForm      string = "2006-01-02T15:04:05.000000"
	TimeFormUTC   string = "2006-01-02T15:04:05.000000Z"
	TimeFormHuman string = "2006-01-02 15:04:05.000000"
)

// GetDateTimeNow Function
func GetDateTimeNow() string {
	time := time.Now().UTC()
	ret := time.Format(TimeFormUTC)
	return ret
}

// GetDateTimeZero Function
func GetDateTimeZero() string {
	return "0001-01-01T00:00:00.000000Z"
}

// GetDateTimeUTC Function
func GetDateTimeUTC(givenTime string) string {
	// 2020-03-04T06:43:05.326422361Z -> 2020-03-04 06:43:05.264223 -> 0000-00-00T00:00:00.000000Z+00:00
	// 2020-03-04T06:43:05Z -> 2020-03-04 06:43:05.000000 -> 0000-00-00T00:00:00.000000Z+00:00

	trimmed := strings.ReplaceAll(strings.ReplaceAll(givenTime, "T", " "), "Z", "")
	splitted := strings.Split(trimmed, ".")

	if len(splitted) > 1 { // milli ~ nano
		if len(splitted[1]) > 6 { // nano
			splitted[1] = splitted[1][:6]
		} else { // milli ~ micro
			count := 6 - len(splitted[1])
			for i := 0; i < count; i++ {
				splitted[1] = splitted[1] + "0"
			}
		}
	} else {
		splitted = append(splitted, "000000")
	}

	givenTime = strings.Join(splitted, ".")
	t, _ := time.Parse(TimeFormHuman, givenTime)

	return t.Format(TimeFormUTC)
}

// ConvertDateTimeToStr Function
func ConvertDateTimeToStr(givenTime primitive.DateTime) string {
	t := givenTime.Time()
	t = t.UTC()
	str := t.Format(TimeFormUTC)
	return str
}

// ConvertStrToDateTime Function
func ConvertStrToDateTime(givenTime string) primitive.DateTime {
	t, _ := time.Parse(TimeFormUTC, givenTime)
	t = t.UTC()
	dateTime := primitive.NewDateTimeFromTime(t)
	return dateTime
}

// GetDateTimeBefore Function
func GetDateTimeBefore(seconds int) (string, string) {
	end := time.Now().UTC()
	end = end.Round(time.Second)
	start := end.Add(-(time.Second * time.Duration(seconds)))
	start = start.Round(time.Second)

	endt := end.Format(TimeFormUTC)
	startt := start.Format(TimeFormUTC)

	return startt, endt
}

// GetUptimeTimestamp Function
func GetUptimeTimestamp() float64 {
	now := time.Now().UTC()

	res := GetCommandOutput("cat", []string{"/proc/uptime"})

	uptimeDiff := strings.Split(res, " ")[0]
	uptimeDiffSec, _ := strconv.Atoi(strings.Split(uptimeDiff, ".")[0]) // second
	uptimeDiffMil, _ := strconv.Atoi(strings.Split(uptimeDiff, ".")[1]) // milli sec.

	uptime := now.Add(-time.Second * time.Duration(uptimeDiffSec))
	uptime = uptime.Add(-time.Millisecond * time.Duration(uptimeDiffMil))

	micro := uptime.UnixNano() / 1000
	up := float64(micro) / 1000000.0

	return up
}

// GetDateTimeFromTimestamp Function
func GetDateTimeFromTimestamp(timestamp float64) string {
	strTS := fmt.Sprintf("%.6f", timestamp)

	secTS := strings.Split(strTS, ".")[0]
	nanoTS := strings.Split(strTS, ".")[1] + "000"

	sec64, err := strconv.ParseInt(secTS, 10, 64)
	if err != nil {
		panic(err)
	}

	nano64, err := strconv.ParseInt(nanoTS, 10, 64)
	if err != nil {
		panic(err)
	}

	tm := time.Unix(sec64, nano64)
	tm = tm.UTC()

	return tm.Format(TimeFormUTC)
}
