package main

import (
	"errors"

	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/promql/parser"
)

func must[T any](t T, err error) T {
	if err != nil {
		panic(err)
	}
	return t
}

func parseMatchers(s string) ([]*labels.Matcher, error) {
	if s == "" {
		return nil, nil
	}
	expr, err := parser.ParseExpr("{" + s + "}")
	if err != nil {
		return nil, errors.New("invalid label matchers")
	}
	if expr.Type() != parser.ValueTypeVector {
		return nil, errors.New("invalid label matchers")
	}

	vs := expr.(*parser.VectorSelector)
	return vs.LabelMatchers, nil
}
