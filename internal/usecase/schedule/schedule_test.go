package schedule

import (
	"errors"
	"testing"
	"time"
)

func TestValidateAcceptsReasonableSchedules(t *testing.T) {
	for _, expr := range []string{"0 */6 * * *", "*/15 * * * *", "30 2 * * 1-5", "0 9 1 * *"} {
		if err := Validate(expr); err != nil {
			t.Errorf("%q: %v", expr, err)
		}
	}
}

func TestValidateRejectsMalformedSchedules(t *testing.T) {
	for _, expr := range []string{"", "every 6h", "@every 1h", "0 */6 * *", "61 * * * *"} {
		if err := Validate(expr); !errors.Is(err, ErrInvalidSchedule) {
			t.Errorf("%q: want ErrInvalidSchedule, got %v", expr, err)
		}
	}
}

func TestValidateRejectsTooFrequentSchedules(t *testing.T) {
	for _, expr := range []string{"* * * * *", "*/5 * * * *", "0,10 * * * *", "* 3 * * *"} {
		err := Validate(expr)
		if !errors.Is(err, ErrInvalidSchedule) {
			t.Errorf("%q: want ErrInvalidSchedule, got %v", expr, err)
		}
	}
}

func TestNext(t *testing.T) {
	after := time.Date(2026, 10, 14, 5, 30, 0, 0, time.UTC)
	got, err := Next("0 */6 * * *", after)
	if err != nil || !got.Equal(time.Date(2026, 10, 14, 6, 0, 0, 0, time.UTC)) {
		t.Fatalf("Next = %v, %v", got, err)
	}
	if _, err := Next("nonsense", after); !errors.Is(err, ErrInvalidSchedule) {
		t.Fatalf("want ErrInvalidSchedule, got %v", err)
	}
}
