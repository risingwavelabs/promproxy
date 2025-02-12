package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path"
	"strings"
	"syscall"

	"github.com/risingwavelabs/promproxy/pkg/proxy"
)

var (
	listenAddr         string
	isolationKeys      string
	upstreamEndpoint   string
	upstreamTLS        bool
	upstreamTLSCertDir string
	labelMatchers      string
	printAccessLog     bool
)

func init() {
	flag.StringVar(&listenAddr, "listen-addr", ":8080", "address to listen on")
	flag.StringVar(&upstreamEndpoint, "upstream-endpoint", "http://localhost:9090", "upstream Prometheus endpoint")
	flag.BoolVar(&upstreamTLS, "upstream-tls", false, "use TLS for upstream connection")
	flag.StringVar(&upstreamTLSCertDir, "upstream-tls-cert-dir", "", "directory to load certificates from")
	flag.StringVar(&labelMatchers, "label-matchers", "", "label matchers to apply to all queries")
	flag.BoolVar(&printAccessLog, "print-access-log", false, "print access log")
	flag.StringVar(&isolationKeys, "isolation-keys", "namespace", "keys to isolate on, separated by commas")
}

func newProxy() (*proxy.Proxy, error) {
	lm, err := parseMatchers(labelMatchers)
	if err != nil {
		return nil, err
	}

	var client http.Client
	if upstreamTLS {
		cert, err := tls.LoadX509KeyPair(path.Join(upstreamTLSCertDir, "tls.crt"), path.Join(upstreamTLSCertDir, "tls.key"))
		if err != nil {
			return nil, fmt.Errorf("failed to load client certificate: %w", err)
		}

		caPool := x509.NewCertPool()
		caCert, err := os.ReadFile(path.Join(upstreamTLSCertDir, "ca.crt"))
		if err != nil {
			return nil, fmt.Errorf("failed to load CA certificate: %w", err)
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

	keys := strings.Split(isolationKeys, ",")
	return proxy.NewProxy(upstreamEndpoint, &client, keys, lm), nil
}

func main() {
	flag.Parse()

	p, err := newProxy()
	if err != nil {
		fmt.Println("failed to create proxy:", err)
		os.Exit(1)
	}

	var handler http.Handler = p
	if printAccessLog {
		handler = logHttpHandler(handler)
	}

	srv := &http.Server{
		Addr:    listenAddr,
		Handler: handler,
	}

	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	fmt.Println("starting server on", listenAddr)
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			fmt.Println("failed to start server:", err)
			os.Exit(1)
		}
	}()

	<-done
	fmt.Println("shutting down server")

	if err := srv.Shutdown(context.Background()); err != nil {
		fmt.Println("failed to shutdown server:", err)
		os.Exit(1)
	}
	fmt.Println("server shutdown")
}
