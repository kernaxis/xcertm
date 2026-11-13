package app

import (
	"fmt"
	"time"

	"github.com/kernaxis/xcertm/internal/deploy"
)

func validityDuration(duration time.Duration) string {
	sign := ""
	if duration < 0 {
		sign, duration = "-", -duration
	}
	if duration < time.Hour {
		return sign + duration.Round(time.Second).String()
	}
	duration = duration.Round(time.Second)
	value := fmt.Sprintf("%s%dd %dh", sign, int64(duration/(24*time.Hour)), int64(duration/time.Hour)%24)
	minutes, seconds := int64(duration/time.Minute)%60, int64(duration/time.Second)%60
	if minutes != 0 || seconds != 0 {
		value += fmt.Sprintf(" %dm", minutes)
	}
	if seconds != 0 {
		value += fmt.Sprintf(" %ds", seconds)
	}
	return value
}

// Keep one final observation per destination when recovery precedes renewal.
func mergeDeployments(previous, latest []deploy.Result) []deploy.Result {
	for _, result := range latest {
		found := false
		for i := range previous {
			if previous[i].DestinationID == result.DestinationID {
				previous[i], found = result, true
				break
			}
		}
		if !found {
			previous = append(previous, result)
		}
	}
	return previous
}
