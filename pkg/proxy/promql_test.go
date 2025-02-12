package proxy

import (
	"testing"

	"github.com/prometheus/prometheus/model/labels"
	"github.com/stretchr/testify/assert"
)

func must[T any](t T, err error) T {
	if err != nil {
		panic(err)
	}
	return t
}

func mustCanonicalizeQuery(s string) string {
	return must(FormatQuery(s))
}

func TestRewriteQuery(t *testing.T) {
	testcases := map[string]struct {
		query         string
		labelMatchers []*labels.Matcher
		expected      string
	}{
		"no label matchers": {
			query:         `sum by (pod) (process_cpu_seconds_total)`,
			labelMatchers: nil,
			expected:      `sum by (pod) (process_cpu_seconds_total)`,
		},
		"one label matcher": {
			query: `sum by (pod) (process_cpu_seconds_total)`,
			labelMatchers: []*labels.Matcher{
				{
					Type:  labels.MatchEqual,
					Name:  "cluster",
					Value: "test-useast1-eks-a",
				},
			},
			expected: `sum by (pod) (process_cpu_seconds_total{cluster="test-useast1-eks-a"})`,
		},
		"matrix selector": {
			query: `sum_over_time (process_cpu_seconds_total[30d:1h])`,
			labelMatchers: []*labels.Matcher{
				{
					Type:  labels.MatchEqual,
					Name:  "cluster",
					Value: "test-useast1-eks-a",
				},
			},
			expected: `sum_over_time (process_cpu_seconds_total{cluster="test-useast1-eks-a"}[30d:1h])`,
		},
		"experimental functions": {
			query: `sort_by_label (process_cpu_seconds_total{job="test"})`,
			labelMatchers: []*labels.Matcher{
				{
					Type:  labels.MatchEqual,
					Name:  "cluster",
					Value: "test-useast1-eks-a",
				},
			},
			expected: `sort_by_label (process_cpu_seconds_total{cluster="test-useast1-eks-a", job="test"})`,
		},
	}

	for name, tc := range testcases {
		t.Run(name, func(t *testing.T) {
			got, err := RewriteQuery(tc.query, tc.labelMatchers)
			if assert.NoErrorf(t, err, "unexpected error: %s") {
				assert.Equal(t, mustCanonicalizeQuery(tc.expected), got)
			}
		})
	}
}
