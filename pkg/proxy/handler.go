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
	"context"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"strings"

	"github.com/prometheus/prometheus/model/labels"
)

// handler is an HTTP handler that proxies a specific request to a Prometheus instance.
type handler struct {
	upstreamEndpoint string
	upstream         *http.Client
	labelMatchers    []*labels.Matcher
}

func (h *handler) httpDo(w http.ResponseWriter, req *http.Request) {
	// Proxy the request to the upstream Prometheus instance.
	resp, err := h.upstream.Do(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Copy the response headers and status code.
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	// Write header with the status code first before copying the body.
	w.WriteHeader(resp.StatusCode)
	_, err = io.Copy(w, resp.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
}

func (h *handler) getValuesFromRequest(r *http.Request) (url.Values, int, error) {
	switch r.Method {
	case http.MethodGet:
		return r.URL.Query(), 0, nil
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			return nil, http.StatusBadRequest, fmt.Errorf("parse form: %w", err)
		}
		v := r.URL.Query()
		maps.Insert(v, maps.All(r.PostForm))
		return v, 0, nil
	}
	return nil, http.StatusMethodNotAllowed, fmt.Errorf("method %s not allowed", r.Method)
}

func (h *handler) newRequest(ctx context.Context, method string, url string, header http.Header, values url.Values) (*http.Request, error) {
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

func (h *handler) proxyQuery(w http.ResponseWriter, r *http.Request) {
	values, status, err := h.getValuesFromRequest(r)
	if err != nil {
		http.Error(w, err.Error(), status)
		return
	}

	if !values.Has("query") {
		http.Error(w, "query not provided", http.StatusBadRequest)
		return
	}

	// Rewrite the query with the label matchers.
	query := values.Get("query")
	rewrittenQuery, err := RewriteQuery(query, h.labelMatchers)
	if err != nil {
		http.Error(w, "invalid query: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Overwrite the query with the rewritten query.
	values.Set("query", rewrittenQuery)

	// Construct a new request with the rewritten query.
	proxyReq, err := h.newRequest(
		r.Context(),
		r.Method,
		h.upstreamEndpoint+r.URL.Path,
		r.Header,
		values,
	)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.httpDo(w, proxyReq)
}

func (h *handler) proxy(w http.ResponseWriter, r *http.Request) {
	proxyReq, err := http.NewRequestWithContext(r.Context(), r.Method, h.upstreamEndpoint+r.URL.Path, r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	proxyReq.Header = r.Header
	h.httpDo(w, proxyReq)
}

func (h *handler) proxyMatchesSeriesSelector(w http.ResponseWriter, r *http.Request) {
	values, status, err := h.getValuesFromRequest(r)
	if err != nil {
		http.Error(w, err.Error(), status)
		return
	}

	// Rewrite the match[] query parameter with the label matchers.
	if values.Has("match[]") {
		matchers := values["match[]"]
		for i, matcher := range matchers {
			rewrittenMatcher, err := RewriteQuery(matcher, h.labelMatchers)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			matchers[i] = rewrittenMatcher
		}
		values["match[]"] = matchers
	} else {
		values.Add("match[]", GetMatchExpr(h.labelMatchers))
	}

	// Construct a new request with the rewritten matchers.
	proxyReq, err := h.newRequest(r.Context(), r.Method, h.upstreamEndpoint+r.URL.Path, r.Header, values)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	h.httpDo(w, proxyReq)
}

func (h *handler) proxyMatchTarget(w http.ResponseWriter, r *http.Request) {
	values, status, err := h.getValuesFromRequest(r)
	if err != nil {
		http.Error(w, err.Error(), status)
		return
	}

	// Rewrite the match_target query parameter with the label matchers.
	if values.Has("match_target") {
		matchTarget, err := RewriteQuery(values.Get("match_target"), h.labelMatchers)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		values.Set("match_target", matchTarget)
	} else {
		values.Add("match_target", GetMatchExpr(h.labelMatchers))
	}

	// Construct a new request with the rewritten match_target.
	proxyReq, err := h.newRequest(r.Context(), r.Method, h.upstreamEndpoint+r.URL.Path, r.Header, values)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	h.httpDo(w, proxyReq)
}

func (h *handler) proxyRules(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"status":"success","data":{"groups":[]}}`))
}
