package main

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/pkg/errors"
	"github.com/prometheus/prometheus/model/labels"

	"github.com/prometheus/prometheus/promql/parser"
)

type proxy struct {
	upstreamEndpoint string
	upstream         *http.Client

	labelMatchers []*labels.Matcher
}

func (p *proxy) rewriteQuery(query string, labelMatchers ...*labels.Matcher) (string, error) {
	ast, err := parser.ParseExpr(query)
	if err != nil {
		return "", errors.Wrap(err, "failed to parse query")
	}

	// Add label matchers to all vector selectors.
	parser.Inspect(ast, func(node parser.Node, nodes []parser.Node) error {
		switch n := node.(type) {
		case *parser.VectorSelector:
			n.LabelMatchers = append(n.LabelMatchers, p.labelMatchers...)
			n.LabelMatchers = append(n.LabelMatchers, labelMatchers...)
		}
		return nil
	})

	return ast.String(), nil
}

func (p *proxy) proxy(writer http.ResponseWriter, request *http.Request) {
	resp, err := p.upstream.Do(request)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	writer.WriteHeader(resp.StatusCode)
	writer.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
	writer.Header().Set("Content-Length", resp.Header.Get("Content-Length"))
	_, _ = io.Copy(writer, resp.Body)
}

func (p *proxy) proxyMatchTarget(path string, writer http.ResponseWriter, request *http.Request) {
	namespace := request.PathValue("namespace")
	if namespace == "" {
		http.Error(writer, "namespace not provided", http.StatusBadRequest)
		return
	}

	values := getValuesFromRequest(request)
	if values.Has("match_target") {
		matchTarget, err := p.rewriteQuery(values.Get("match_target"), &labels.Matcher{
			Type:  labels.MatchEqual,
			Name:  "namespace",
			Value: namespace,
		})
		if err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}
		values.Set("match_target", matchTarget)
	} else {
		values.Add("match_target", must(p.rewriteQuery("{__name__!=\"\"}", &labels.Matcher{
			Type:  labels.MatchEqual,
			Name:  "namespace",
			Value: namespace,
		})))
	}

	proxyReq, err := http.NewRequestWithContext(request.Context(), request.Method,
		p.upstreamEndpoint+path, strings.NewReader(values.Encode()))
	if err != nil {
		http.Error(writer, err.Error(), http.StatusInternalServerError)
		return
	}
	proxyReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	p.proxy(writer, proxyReq)
}

func (p *proxy) proxyMatches(path string, writer http.ResponseWriter, request *http.Request) {
	namespace := request.PathValue("namespace")
	if namespace == "" {
		http.Error(writer, "namespace not provided", http.StatusBadRequest)
		return
	}

	values := getValuesFromRequest(request)
	if values.Has("match[]") {
		matchers := values["match[]"]
		for i, matcher := range matchers {
			rewrittenMatcher, err := p.rewriteQuery(matcher, &labels.Matcher{
				Type:  labels.MatchEqual,
				Name:  "namespace",
				Value: namespace,
			})
			if err != nil {
				http.Error(writer, err.Error(), http.StatusBadRequest)
				return
			}
			matchers[i] = rewrittenMatcher
		}
		values["match[]"] = matchers
	} else {
		values.Add("match[]", must(p.rewriteQuery("{__name__!=\"\"}", &labels.Matcher{
			Type:  labels.MatchEqual,
			Name:  "namespace",
			Value: namespace,
		})))
	}

	proxyReq, err := newRequest(request.Context(), request.Method, p.upstreamEndpoint+path, values)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusInternalServerError)
		return
	}

	p.proxy(writer, proxyReq)
}

func getValuesFromRequest(request *http.Request) url.Values {
	switch request.Method {
	case http.MethodGet:
		return request.URL.Query()
	case http.MethodPost:
		if err := request.ParseForm(); err != nil {
			return nil
		}
		return request.PostForm
	}
	return nil
}

func newRequest(ctx context.Context, method string, url string, values url.Values) (*http.Request, error) {
	switch method {
	case http.MethodGet:
		return http.NewRequestWithContext(ctx, method, url+"?"+values.Encode(), nil)
	case http.MethodPost:
		req, err := http.NewRequestWithContext(ctx, method, url, strings.NewReader(values.Encode()))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return req, nil
	default:
		panic("unsupported method")
	}
}

func (p *proxy) proxyQuery(path string, writer http.ResponseWriter, request *http.Request) {
	namespace := request.PathValue("namespace")
	if namespace == "" {
		http.Error(writer, "namespace not provided", http.StatusBadRequest)
		return
	}

	values := getValuesFromRequest(request)
	if values.Has("query") {
		query, err := p.rewriteQuery(values.Get("query"), &labels.Matcher{
			Type:  labels.MatchEqual,
			Name:  "namespace",
			Value: namespace,
		})
		if err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}
		values.Set("query", query)
	}

	proxyReq, err := newRequest(request.Context(), request.Method, p.upstreamEndpoint+path, values)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusInternalServerError)
		return
	}

	p.proxy(writer, proxyReq)
}

func newHttpMux(p *proxy) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/{namespace}/api/v1/query", func(writer http.ResponseWriter, request *http.Request) {
		p.proxyQuery("/api/v1/query", writer, request)
	})
	mux.HandleFunc("/{namespace}/api/v1/query_range", func(writer http.ResponseWriter, request *http.Request) {
		p.proxyQuery("/api/v1/query_range", writer, request)
	})
	mux.HandleFunc("/{namespace}/api/v1/format_query", p.proxy)
	mux.HandleFunc("/{namespace}/api/v1/parse_query", p.proxy)
	mux.HandleFunc("/{namespace}/api/v1/series", func(writer http.ResponseWriter, request *http.Request) {
		p.proxyMatches("/api/v1/series", writer, request)
	})
	mux.HandleFunc("/{namespace}/api/v1/labels", func(writer http.ResponseWriter, request *http.Request) {
		p.proxyMatches("/api/v1/labels", writer, request)
	})
	mux.HandleFunc("/{namespace}/api/v1/label/{name}/values", func(writer http.ResponseWriter, request *http.Request) {
		name := request.PathValue("name")
		p.proxyMatches("/api/v1/label/"+name+"/values", writer, request)
	})
	mux.HandleFunc("/{namespace}/api/v1/query_exemplars", func(writer http.ResponseWriter, request *http.Request) {
		p.proxyQuery("/api/v1/query_exemplars", writer, request)
	})
	mux.HandleFunc("/{namespace}/api/v1/targets", p.proxy)
	mux.HandleFunc("/{namespace}/api/v1/rules", func(writer http.ResponseWriter, request *http.Request) {
		p.proxyMatches("/api/v1/rules", writer, request)
	})
	mux.HandleFunc("/{namespace}/api/v1/alerts", p.proxy)
	mux.HandleFunc("/{namespace}/api/v1/targets/metadata", func(writer http.ResponseWriter, request *http.Request) {
		p.proxyMatchTarget("/api/v1/targets/metadata", writer, request)
	})
	mux.HandleFunc("/{namespace}/api/v1/metadata", p.proxy)
	mux.HandleFunc("/{namespace}/api/v1/alertmanagers", p.proxy)
	mux.HandleFunc("/{namespace}/api/v1/status/config", p.proxy)
	mux.HandleFunc("/{namespace}/api/v1/status/flags", p.proxy)
	mux.HandleFunc("/{namespace}/api/v1/status/runtimeinfo", p.proxy)
	mux.HandleFunc("/{namespace}/api/v1/status/buildinfo", p.proxy)
	mux.HandleFunc("/{namespace}/api/v1/status/tsdb", p.proxy)
	mux.HandleFunc("/{namespace}/api/v1/status/walreplay", p.proxy)
	mux.HandleFunc("/{namespace}/api/v1/notifications", p.proxy)
	mux.HandleFunc("/{namespace}/api/v1/notifications/live", p.proxy)

	return mux
}
