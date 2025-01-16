package main

import (
	"testing"

	"github.com/prometheus/prometheus/model/labels"
)

func TestProxyRewriteQuery(t *testing.T) {
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
	}

	for name, tc := range testcases {
		t.Run(name, func(t *testing.T) {
			p := &proxy{}
			got, err := p.rewriteQuery(tc.query, tc.labelMatchers...)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.expected {
				t.Fatalf("expected %q, got %q", tc.expected, got)
			}
		})
	}
}
