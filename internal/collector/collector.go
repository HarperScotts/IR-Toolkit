package collector

import (
	"context"
	"time"
)

type Collector interface {
	Name() string
	Collect(context.Context) (any, error)
}

type Result struct {
	Name      string    `json:"name"`
	StartedAt time.Time `json:"started_at"`
	EndedAt   time.Time `json:"ended_at"`

	Data any `json:"data,omitempty"`

	Error string `json:"error,omitempty"`
}

func Run(ctx context.Context, collectors []Collector) []Result {
	results := make([]Result, 0, len(collectors))

	for _, c := range collectors {
		started := time.Now().UTC()

		data, err := c.Collect(ctx)

		ended := time.Now().UTC()

		result := Result{
			Name:      c.Name(),
			StartedAt: started,
			EndedAt:   ended,
			Data:      data,
		}

		if err != nil {
			result.Error = err.Error()
		}

		results = append(results, result)
	}

	return results
}
