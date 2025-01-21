package main

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"text/template"

	"github.com/pkg/errors"
	"github.com/prometheus/prometheus/model/labels"

	"github.com/prometheus/prometheus/promql/parser"
)

func init() {
	parser.EnableExperimentalFunctions = true
}

const (
	extraMatchesKey = "extra-match[]"
)

type proxy struct {
	upstreamEndpoint string
	upstream         *http.Client

	labelMatchers []*labels.Matcher
	filterJobs    *template.Template
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

func (p *proxy) rewriteQueryWithNamespaceAndExtraMatchers(query, namespace string, extraMatchers []*labels.Matcher) (string, error) {
	if p.filterJobs != nil {
		sb := strings.Builder{}
		err := p.filterJobs.Execute(&sb, map[string]string{"Namespace": namespace})
		if err != nil {
			return "", errors.Wrap(err, "failed to execute filter jobs template")
		}
		extraMatchers = append(extraMatchers, &labels.Matcher{
			Type:  labels.MatchRegexp,
			Name:  "job",
			Value: sb.String(),
		})
	}

	return p.rewriteQuery(query, append(extraMatchers, &labels.Matcher{
		Type:  labels.MatchEqual,
		Name:  "namespace",
		Value: namespace,
	})...)
}

func (p *proxy) proxy(writer http.ResponseWriter, request *http.Request) {
	path := strings.TrimPrefix(request.URL.Path, "/"+request.PathValue("namespace"))
	req, err := http.NewRequestWithContext(request.Context(), request.Method, p.upstreamEndpoint+path, request.Body)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusInternalServerError)
		return
	}
	req.Header = request.Header

	p.do(writer, req)
}

func (p *proxy) do(writer http.ResponseWriter, request *http.Request) {
	resp, err := p.upstream.Do(request)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	writer.WriteHeader(resp.StatusCode)
	for key, values := range resp.Header {
		for _, value := range values {
			writer.Header().Add(key, value)
		}
	}
	_, _ = io.Copy(writer, resp.Body)
}

func (p *proxy) proxyMatchTarget(path string, writer http.ResponseWriter, request *http.Request) {
	namespace := request.PathValue("namespace")
	if namespace == "" {
		http.Error(writer, "namespace not provided", http.StatusBadRequest)
		return
	}

	values := getValuesFromRequest(request)
	extraMatchers, err := getExtraMatchesFromValues(values)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusBadRequest)
		return
	}
	if values.Has("match_target") {
		matchTarget, err := p.rewriteQueryWithNamespaceAndExtraMatchers(values.Get("match_target"), namespace, extraMatchers)
		if err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}
		values.Set("match_target", matchTarget)
	} else {
		values.Add("match_target", must(p.rewriteQueryWithNamespaceAndExtraMatchers("{__name__!=\"\"}", namespace, extraMatchers)))
	}

	proxyReq, err := newRequest(request.Context(), request.Method, p.upstreamEndpoint+path, request.Header, values)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusInternalServerError)
		return
	}

	p.do(writer, proxyReq)
}

func (p *proxy) proxyMatchesSeriesSelector(path string, writer http.ResponseWriter, request *http.Request) {
	namespace := request.PathValue("namespace")
	if namespace == "" {
		http.Error(writer, "namespace not provided", http.StatusBadRequest)
		return
	}

	values := getValuesFromRequest(request)
	extraMatchers, err := getExtraMatchesFromValues(values)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusBadRequest)
		return
	}
	if values.Has("match[]") {
		matchers := values["match[]"]
		for i, matcher := range matchers {
			rewrittenMatcher, err := p.rewriteQueryWithNamespaceAndExtraMatchers(matcher, namespace, extraMatchers)
			if err != nil {
				http.Error(writer, err.Error(), http.StatusBadRequest)
				return
			}
			matchers[i] = rewrittenMatcher
		}
		values["match[]"] = matchers
	} else {
		values.Add("match[]", must(p.rewriteQueryWithNamespaceAndExtraMatchers("{__name__!=\"\"}", namespace, extraMatchers)))
	}

	proxyReq, err := newRequest(request.Context(), request.Method, p.upstreamEndpoint+path, request.Header, values)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusInternalServerError)
		return
	}

	p.do(writer, proxyReq)
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

func getExtraMatchesFromValues(values url.Values) ([]*labels.Matcher, error) {
	if values.Has(extraMatchesKey) {
		return parseMatchers(strings.Join(values[extraMatchesKey], ","))
	}
	return nil, nil
}

func newRequest(ctx context.Context, method string, url string, header http.Header, values url.Values) (*http.Request, error) {
	switch method {
	case http.MethodGet:
		r, err := http.NewRequestWithContext(ctx, method, url+"?"+values.Encode(), nil)
		if err != nil {
			return nil, err
		}
		r.Header = header.Clone()
		return r, nil
	case http.MethodPost:
		r, err := http.NewRequestWithContext(ctx, method, url, strings.NewReader(values.Encode()))
		if err != nil {
			return nil, err
		}
		r.Header = header.Clone()
		r.Header["Content-Type"] = []string{"application/x-www-form-urlencoded"}
		return r, nil
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
		extraMatchers, err := getExtraMatchesFromValues(values)
		if err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}
		query, err := p.rewriteQueryWithNamespaceAndExtraMatchers(values.Get("query"), namespace, extraMatchers)
		if err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}
		values.Set("query", query)
	}

	proxyReq, err := newRequest(request.Context(), request.Method, p.upstreamEndpoint+path, request.Header, values)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusInternalServerError)
		return
	}

	p.do(writer, proxyReq)
}

func newHttpMux(p *proxy) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/-/healthy", func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusOK)
	})

	mux.HandleFunc("/{namespace}/api/v1/query", func(writer http.ResponseWriter, request *http.Request) {
		p.proxyQuery("/api/v1/query", writer, request)
	})
	mux.HandleFunc("/{namespace}/api/v1/query_range", func(writer http.ResponseWriter, request *http.Request) {
		p.proxyQuery("/api/v1/query_range", writer, request)
	})
	mux.HandleFunc("/{namespace}/api/v1/format_query", p.proxy)
	mux.HandleFunc("/{namespace}/api/v1/parse_query", p.proxy)
	mux.HandleFunc("/{namespace}/api/v1/series", func(writer http.ResponseWriter, request *http.Request) {
		p.proxyMatchesSeriesSelector("/api/v1/series", writer, request)
	})
	mux.HandleFunc("/{namespace}/api/v1/labels", func(writer http.ResponseWriter, request *http.Request) {
		p.proxyMatchesSeriesSelector("/api/v1/labels", writer, request)
	})
	mux.HandleFunc("/{namespace}/api/v1/label/{name}/values", func(writer http.ResponseWriter, request *http.Request) {
		name := request.PathValue("name")
		p.proxyMatchesSeriesSelector("/api/v1/label/"+name+"/values", writer, request)
	})
	mux.HandleFunc("/{namespace}/api/v1/query_exemplars", func(writer http.ResponseWriter, request *http.Request) {
		p.proxyQuery("/api/v1/query_exemplars", writer, request)
	})
	mux.HandleFunc("/{namespace}/api/v1/targets/metadata", func(writer http.ResponseWriter, request *http.Request) {
		p.proxyMatchTarget("/api/v1/targets/metadata", writer, request)
	})
	mux.HandleFunc("/{namespace}/api/v1/metadata", p.proxy)
	mux.HandleFunc("/{namespace}/api/v1/rules", func(writer http.ResponseWriter, request *http.Request) {
		_, _ = writer.Write([]byte(`{"status":"success","data":{"groups":[]}}`))
	})

	// The following routes are not implemented in the proxy.
	// --------------------------------------------------------
	//
	// mux.HandleFunc("/{namespace}/api/v1/targets", p.proxy)
	// mux.HandleFunc("/{namespace}/api/v1/status/buildinfo", p.proxy)
	// mux.HandleFunc("/{namespace}/api/v1/status/runtimeinfo", p.proxy)
	// mux.HandleFunc("/{namespace}/api/v1/alertmanagers", p.proxy)
	// mux.HandleFunc("/{namespace}/api/v1/status/config", p.proxy)
	// mux.HandleFunc("/{namespace}/api/v1/status/flags", p.proxy)
	// mux.HandleFunc("/{namespace}/api/v1/alerts", p.proxy)
	// mux.HandleFunc("/{namespace}/api/v1/status/tsdb", p.proxy)
	// mux.HandleFunc("/{namespace}/api/v1/status/walreplay", p.proxy)
	// mux.HandleFunc("/{namespace}/api/v1/notifications", p.proxy)
	// mux.HandleFunc("/{namespace}/api/v1/notifications/live", p.proxy)
	//
	// --------------------------------------------------------

	return mux
}
