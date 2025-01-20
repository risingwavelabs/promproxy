package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path"
	"text/template"

	"github.com/pkg/errors"
)

var (
	listenAddr         string
	filterJobs         string
	upstreamEndpoint   string
	upstreamTLS        bool
	upstreamTLSCertDir string
	labelMatchers      string
	printAccessLog     bool
)

func init() {
	flag.StringVar(&listenAddr, "listen-addr", ":8080", "address to listen on")
	flag.StringVar(&upstreamEndpoint, "upstream-endpoint", "", "upstream Prometheus endpoint")
	flag.BoolVar(&upstreamTLS, "upstream-tls", false, "use TLS for upstream connection")
	flag.StringVar(&upstreamTLSCertDir, "upstream-tls-cert-dir", "", "directory to load certificates from")
	flag.StringVar(&labelMatchers, "label-matchers", "", "label matchers to apply to all queries")
	flag.StringVar(&filterJobs, "filter-jobs", "", "regexp to filter jobs, templating variables are supported (namespace)")
	flag.BoolVar(&printAccessLog, "print-access-log", false, "print access log")
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

	var filterJobsTpl *template.Template
	if filterJobs != "" {
		filterJobsTpl, err = template.New("filter-jobs").Parse(filterJobs)
		if err != nil {
			return nil, errors.Wrap(err, "failed to parse filter jobs template")
		}
	}

	return &proxy{
		upstreamEndpoint: upstreamEndpoint,
		upstream:         &client,
		labelMatchers:    lm,
		filterJobs:       filterJobsTpl,
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
	handler := newHttpMux(p)
	if printAccessLog {
		handler = logHttpHandler(handler)
	}
	err = http.ListenAndServe(listenAddr, handler)
	if err != nil {
		fmt.Println("failed to start server:", err)
		os.Exit(1)
	}
}
