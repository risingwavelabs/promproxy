package main

import (
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/promql/parser"
	"github.com/urfave/negroni"
)

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

func logHttpHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		beginTs := time.Now()
		log.Printf("--> %s %s", r.Method, r.URL.Path)

		lrw := negroni.NewResponseWriter(w)
		next.ServeHTTP(lrw, r)

		statusCode := lrw.Status()
		log.Printf("<-- %s %s %d %s %s", r.Method, r.URL.Path, statusCode, http.StatusText(statusCode), time.Now().Sub(beginTs))
	})
}
