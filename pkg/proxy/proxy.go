package proxy

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/prometheus/prometheus/model/labels"
)

const handlerKey = "handler"

type handlerContextHandler func(*handler, http.ResponseWriter, *http.Request)

func wrapHandler(h handlerContextHandler) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		h(request.Context().Value(handlerKey).(*handler), writer, request)
	}
}

// Compile time check if the handler implements the http.Handler interface
var _ http.Handler = &Proxy{}

// Proxy is an HTTP handler that proxies requests to a Prometheus instance.
type Proxy struct {
	mux    *http.ServeMux
	subMux *http.ServeMux

	upstreamEndpoint string
	upstream         *http.Client
	keys             []string
	labelMatchers    []*labels.Matcher
}

func (p *Proxy) handleKeys(writer http.ResponseWriter, request *http.Request) {
	// Extract keys from the request path.
	values := make([]string, len(p.keys))
	for i, key := range p.keys {
		values[i] = request.PathValue(key)
	}

	// Convert the key-values to label matchers.
	matchers := make([]*labels.Matcher, len(p.keys))
	for i, value := range values {
		matchers[i] = labels.MustNewMatcher(labels.MatchEqual, p.keys[i], value)
	}

	// Trim the prefix from the request path and proxy the request.
	h := &handler{
		upstreamEndpoint: p.upstreamEndpoint,
		upstream:         p.upstream,
		labelMatchers:    append(p.labelMatchers, matchers...),
	}

	http.StripPrefix("/"+strings.Join(values, "/"), p.subMux).ServeHTTP(
		writer,
		// Set the handler in the request context.
		request.WithContext(context.WithValue(request.Context(), handlerKey, h)),
	)
}

func (p *Proxy) handleHealthy(writer http.ResponseWriter, _ *http.Request) {
	writer.WriteHeader(http.StatusOK)
}

func (p *Proxy) registerHandlers() {
	// Collect the keys from the configuration.
	keysPaths := slices.Collect(func(yield func(string) bool) {
		for _, key := range p.keys {
			transformedKey := fmt.Sprintf("{%s}", key)
			if !yield(transformedKey) {
				return
			}
		}
	})

	// Set up the root mux for key handling.
	p.mux.HandleFunc("/-/healthy", p.handleHealthy)
	p.mux.HandleFunc("/api/v1/", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	p.mux.HandleFunc("/"+strings.Join(keysPaths, "/")+"/", p.handleKeys)

	// Set up the sub mux for the Prometheus API.
	p.subMux.HandleFunc("/api/v1/query", wrapHandler(func(h *handler, w http.ResponseWriter, r *http.Request) {
		h.proxyQuery("/api/v1/query", w, r)
	}))
	p.subMux.HandleFunc("/api/v1/query_range", wrapHandler(func(h *handler, w http.ResponseWriter, r *http.Request) {
		h.proxyQuery("/api/v1/query_range", w, r)
	}))
	p.subMux.HandleFunc("/api/v1/query_exemplars", wrapHandler(func(h *handler, w http.ResponseWriter, r *http.Request) {
		h.proxyQuery("/api/v1/query_exemplars", w, r)
	}))
	p.subMux.HandleFunc("/api/v1/format_query", wrapHandler((*handler).proxy))
	p.subMux.HandleFunc("/api/v1/parse_query", wrapHandler((*handler).proxy))
	p.subMux.HandleFunc("/api/v1/series", wrapHandler(func(h *handler, w http.ResponseWriter, r *http.Request) {
		h.proxyMatchesSeriesSelector("/api/v1/series", w, r)
	}))
	p.subMux.HandleFunc("/api/v1/labels", wrapHandler(func(h *handler, w http.ResponseWriter, r *http.Request) {
		h.proxyMatchesSeriesSelector("/api/v1/labels", w, r)
	}))
	p.subMux.HandleFunc("/api/v1/label/{name}/values", wrapHandler(func(h *handler, w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		h.proxyMatchesSeriesSelector(fmt.Sprintf("/api/v1/label/%s/values", name), w, r)
	}))
	p.subMux.HandleFunc("/api/v1/metadata", wrapHandler(func(h *handler, w http.ResponseWriter, r *http.Request) {
		h.proxyMatchTarget("/api/v1/metadata", w, r)
	}))
	p.subMux.HandleFunc("/api/v1/rules", wrapHandler((*handler).proxy))

	// The following routes are not implemented in the proxy.
	// --------------------------------------------------------
	//
	// p.subMux.HandleFunc("/api/v1/targets/metadata", wrapHandler(func(h *handler, w http.ResponseWriter, r *http.Request) {
	// 	h.proxyMatchTarget("/api/v1/targets/metadata", w, r)
	// }))
	// p.subMux.HandleFunc("/{namespace}/api/v1/targets", p.proxy)
	// p.subMux.HandleFunc("/{namespace}/api/v1/status/buildinfo", p.proxy)
	// p.subMux.HandleFunc("/{namespace}/api/v1/status/runtimeinfo", p.proxy)
	// p.subMux.HandleFunc("/{namespace}/api/v1/alertmanagers", p.proxy)
	// p.subMux.HandleFunc("/{namespace}/api/v1/status/config", p.proxy)
	// p.subMux.HandleFunc("/{namespace}/api/v1/status/flags", p.proxy)
	// p.subMux.HandleFunc("/{namespace}/api/v1/alerts", p.proxy)
	// p.subMux.HandleFunc("/{namespace}/api/v1/status/tsdb", p.proxy)
	// p.subMux.HandleFunc("/{namespace}/api/v1/status/walreplay", p.proxy)
	// p.subMux.HandleFunc("/{namespace}/api/v1/notifications", p.proxy)
	// p.subMux.HandleFunc("/{namespace}/api/v1/notifications/live", p.proxy)
	//
	// --------------------------------------------------------
}

// ServeHTTP implements the http.Handler interface.
func (p *Proxy) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	p.mux.ServeHTTP(writer, request)
}

// NewProxy creates a new Proxy.
func NewProxy(upstreamEndpoint string, upstreamClient *http.Client, keys []string, labelMatchers []*labels.Matcher) *Proxy {
	p := &Proxy{
		mux:    http.NewServeMux(),
		subMux: http.NewServeMux(),

		upstreamEndpoint: upstreamEndpoint,
		upstream:         upstreamClient,
		keys:             keys,
		labelMatchers:    labelMatchers,
	}
	p.registerHandlers()
	return p
}
