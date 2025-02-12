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
	return func(w http.ResponseWriter, r *http.Request) {
		h(r.Context().Value(handlerKey).(*handler), w, r)
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
	p.subMux.HandleFunc("/api/v1/query", wrapHandler((*handler).proxyQuery))
	p.subMux.HandleFunc("/api/v1/query_range", wrapHandler((*handler).proxyQuery))
	p.subMux.HandleFunc("/api/v1/query_exemplars", wrapHandler((*handler).proxyQuery))
	p.subMux.HandleFunc("/api/v1/series", wrapHandler((*handler).proxyMatchesSeriesSelector))
	p.subMux.HandleFunc("/api/v1/labels", wrapHandler((*handler).proxyMatchesSeriesSelector))
	p.subMux.HandleFunc("/api/v1/label/{name}/values", wrapHandler((*handler).proxyMatchesSeriesSelector))
	p.subMux.HandleFunc("/api/v1/rules", wrapHandler((*handler).proxyRules))

	// The following routes are not implemented in the proxy.
	// --------------------------------------------------------
	//
	// p.subMux.HandleFunc("/api/v1/metadata", wrapHandler((*handler).proxy))
	// p.subMux.HandleFunc("/api/v1/targets/metadata", wrapHandler((*handler).proxyMatchTarget))
	// p.subMux.HandleFunc("/api/v1/format_query", wrapHandler((*handler).proxy))
	// p.subMux.HandleFunc("/api/v1/parse_query", wrapHandler((*handler).proxy))
	// p.subMux.HandleFunc("/{namespace}/api/v1/targets", wrapHandler((*handler).proxy))
	// p.subMux.HandleFunc("/{namespace}/api/v1/status/buildinfo", wrapHandler((*handler).proxy))
	// p.subMux.HandleFunc("/{namespace}/api/v1/status/runtimeinfo", wrapHandler((*handler).proxy))
	// p.subMux.HandleFunc("/{namespace}/api/v1/alertmanagers", wrapHandler((*handler).proxy))
	// p.subMux.HandleFunc("/{namespace}/api/v1/status/config", wrapHandler((*handler).proxy))
	// p.subMux.HandleFunc("/{namespace}/api/v1/status/flags", wrapHandler((*handler).proxy))
	// p.subMux.HandleFunc("/{namespace}/api/v1/alerts", wrapHandler((*handler).proxy))
	// p.subMux.HandleFunc("/{namespace}/api/v1/status/tsdb", wrapHandler((*handler).proxy))
	// p.subMux.HandleFunc("/{namespace}/api/v1/status/walreplay", wrapHandler((*handler).proxy))
	// p.subMux.HandleFunc("/{namespace}/api/v1/notifications", wrapHandler((*handler).proxy))
	// p.subMux.HandleFunc("/{namespace}/api/v1/notifications/live", wrapHandler((*handler).proxy))
	//
	// --------------------------------------------------------
}

// ServeHTTP implements the http.Handler interface.
func (p *Proxy) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	p.mux.ServeHTTP(writer, request)
}

// NewProxy creates a new Proxy. Arguments explained:
//   - The upstreamEndpoint is the URL of the upstream Prometheus instance.
//   - The upstreamClient is used to proxy requests to the upstream Prometheus instance.
//   - The keys are used to provide virtual sub-routes for the proxy.
//     For example, if the keys are ["namespace", "pod"],
//     and the request path is "/{namespace}/{pod}/api/v1/query", the key-values will be ["{namespace}", "{pod}"].
//     The key-values are then converted to label matchers and appended to the label matchers provided in the configuration.
//     In this example, the label matchers will be {namespace="{namespace}", pod="{pod}"}.
//   - The labelMatchers are the label matchers to apply to all queries.
func NewProxy(upstreamEndpoint string, upstreamClient *http.Client, keys []string, labelMatchers []*labels.Matcher) *Proxy {
	if len(keys) == 0 {
		panic("no keys provided")
	}

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
