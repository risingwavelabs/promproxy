// Copyright 2025 RisingWave Labs.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package proxy

import (
	"fmt"
	"iter"
	"slices"
	"strings"

	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/promql/parser"
)

func init() {
	parser.EnableExperimentalFunctions = true
}

// matchesToStringIter returns an iterator that yields the string representation of each matcher.
func matchesToStringIter(matchers []*labels.Matcher) iter.Seq[string] {
	return func(yield func(string) bool) {
		for _, m := range matchers {
			if !yield(m.String()) {
				return
			}
		}
	}
}

// GetMatchExpr returns the string representation of the given matchers in the form of a Prometheus match expression.
func GetMatchExpr(matchers []*labels.Matcher) string {
	return fmt.Sprintf("{%s}", strings.Join(
		slices.Collect(matchesToStringIter(matchers)), ", "))
}

// RewriteQuery rewrites the given query with the given extra matchers.
func RewriteQuery(query string, extraMatchers []*labels.Matcher) (string, error) {
	ast, err := parser.ParseExpr(query)
	if err != nil {
		return "", err
	}

	// Add label matchers to all vector selectors.
	parser.Inspect(ast, func(node parser.Node, nodes []parser.Node) error {
		switch n := node.(type) {
		case *parser.VectorSelector:
			n.LabelMatchers = append(n.LabelMatchers, extraMatchers...)
		}
		return nil
	})

	return ast.String(), nil
}

// FormatQuery formats the given query.
func FormatQuery(query string) (string, error) {
	ast, err := parser.ParseExpr(query)
	if err != nil {
		return "", err
	}

	return ast.String(), nil
}
