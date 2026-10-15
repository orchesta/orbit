// Package schedule validates and evaluates repository scan schedules, which
// are standard five-field cron expressions.
package schedule

import (
	"errors"
	"fmt"
	"time"

	"github.com/robfig/cron/v3"
)

// MinInterval is the shortest allowed gap between two scheduled scans.
const MinInterval = 15 * time.Minute

// ErrInvalidSchedule is returned for expressions that cannot or should not be used.
var ErrInvalidSchedule = errors.New("invalid schedule")

var parser = cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)

// Validate checks that expr is a standard five-field cron expression whose
// runs are at least MinInterval apart.
func Validate(expr string) error {
	sched, err := parser.Parse(expr)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidSchedule, err)
	}
	// 200 consecutive runs cover every pattern that could repeat faster than MinInterval.
	prev := sched.Next(time.Date(2026, 1, 5, 0, 0, 0, 0, time.UTC))
	if prev.IsZero() {
		return fmt.Errorf("%w: expression never runs", ErrInvalidSchedule)
	}
	for i := 0; i < 200; i++ {
		next := sched.Next(prev)
		if next.IsZero() {
			break
		}
		if next.Sub(prev) < MinInterval {
			return fmt.Errorf("%w: scans must be at least %s apart", ErrInvalidSchedule, MinInterval)
		}
		prev = next
	}
	return nil
}

// Next returns the first run of expr after after.
func Next(expr string, after time.Time) (time.Time, error) {
	sched, err := parser.Parse(expr)
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: %v", ErrInvalidSchedule, err)
	}
	return sched.Next(after), nil
}
