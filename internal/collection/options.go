package collection

import (
	"context"
	"time"
)

type TimeWindow struct {
	Since *time.Time `json:"since,omitempty"`

	Until *time.Time `json:"until,omitempty"`
}

type contextKey struct{}

func WithTimeWindow(
	ctx context.Context,
	window TimeWindow,
) context.Context {

	return context.WithValue(
		ctx,
		contextKey{},
		window,
	)
}

func TimeWindowFromContext(
	ctx context.Context,
) TimeWindow {

	if ctx == nil {
		return TimeWindow{}
	}

	window, ok :=
		ctx.Value(
			contextKey{},
		).(TimeWindow)

	if !ok {
		return TimeWindow{}
	}

	return window
}

func (w TimeWindow) Empty() bool {
	return w.Since == nil &&
		w.Until == nil
}

func (w TimeWindow) Contains(
	value time.Time,
) bool {

	if value.IsZero() {
		return false
	}

	if w.Since != nil &&
		value.Before(
			*w.Since,
		) {

		return false
	}

	if w.Until != nil &&
		value.After(
			*w.Until,
		) {

		return false
	}

	return true
}
