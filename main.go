package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path"

	"github.com/pkg/errors"
	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/promql/parser"
)

var (
	listenAddr         string
	upstreamEndpoint   string
	upstreamTLS        bool
	upstreamTLSCertDir string
	labelMatchers      string
)

func init() {
	flag.StringVar(&listenAddr, "listen-addr", ":8080", "address to listen on")
	flag.StringVar(&upstreamEndpoint, "upstream-endpoint", "", "upstream Prometheus endpoint")
	flag.BoolVar(&upstreamTLS, "upstream-tls", false, "use TLS for upstream connection")
	flag.StringVar(&upstreamTLSCertDir, "upstream-tls-cert-dir", "", "directory to load certificates from")
	flag.StringVar(&labelMatchers, "label-matchers", "", "label matchers to apply to all queries")
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

func newProxy() (*proxy, error) {
	lm, err := parseMatchers(labelMatchers)
	if err != nil {
		return nil, err
	}

	var client http.Client
	if upstreamTLS {
		cert, err := tls.LoadX509KeyPair(path.Join(upstreamTLSCertDir, "tls.crt"), path.Join(upstreamTLSCertDir, "tls.key"))
		if err != nil {
			return nil, errors.Wrap(err, "failed to load client certificate")
		}

		caPool := x509.NewCertPool()
		caCert, err := os.ReadFile(path.Join(upstreamTLSCertDir, "ca.crt"))
		if err != nil {
			return nil, errors.Wrap(err, "failed to load CA certificate")
		}
		ok := caPool.AppendCertsFromPEM(caCert)
		if !ok {
			return nil, errors.New("failed to parse server CA cert")
		}

		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{cert},
				RootCAs:      caPool,
			},
		}
	}

	return &proxy{
		upstreamEndpoint: upstreamEndpoint,
		upstream:         &client,
		labelMatchers:    lm,
	}, nil
}

func main() {
	flag.Parse()

	p, err := newProxy()
	if err != nil {
		fmt.Println("failed to create proxy:", err)
		os.Exit(1)
	}

	fmt.Println("starting server on", listenAddr)
	err = http.ListenAndServe(listenAddr, newHttpMux(p))
	if err != nil {
		fmt.Println("failed to start server:", err)
		os.Exit(1)
	}
}
