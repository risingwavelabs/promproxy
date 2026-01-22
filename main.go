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
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/risingwavelabs/promproxy/pkg/auth"
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
	upstreamAuth       string

	upstreamAWSRegion          string
	upstreamAWSService         string
	upstreamAWSAccessKeyID     string
	upstreamAWSSecretAccessKey string
	upstreamAWSSessionToken    string

	upstreamGoogleServiceAccountFile string
	upstreamGoogleJWTAudience        string
	upstreamGoogleJWTTTL             time.Duration

	upstreamAzureTenantID     string
	upstreamAzureClientID     string
	upstreamAzureClientSecret string
	upstreamAzureScopes       string
	upstreamAzureTokenURL     string
)

func init() {
	flag.StringVar(&listenAddr, "listen-addr", ":8080", "address to listen on")
	flag.StringVar(&upstreamEndpoint, "upstream-endpoint", "http://localhost:9090", "upstream Prometheus endpoint")
	flag.BoolVar(&upstreamTLS, "upstream-tls", false, "use TLS for upstream connection")
	flag.StringVar(&upstreamTLSCertDir, "upstream-tls-cert-dir", "", "directory to load certificates from")
	flag.StringVar(&labelMatchers, "label-matchers", "", "label matchers to apply to all queries")
	flag.BoolVar(&printAccessLog, "print-access-log", false, "print access log")
	flag.StringVar(&isolationKeys, "isolation-keys", "", "keys to isolate on, separated by commas")
	flag.StringVar(&upstreamAuth, "upstream-auth", "", "upstream auth method: aws-sigv4, google-jwt, azure-oauth2")

	flag.StringVar(&upstreamAWSRegion, "upstream-aws-region", "", "aws region for SigV4 signing")
	flag.StringVar(&upstreamAWSService, "upstream-aws-service", "aps", "aws service name for SigV4 signing")
	flag.StringVar(&upstreamAWSAccessKeyID, "upstream-aws-access-key-id", "", "aws access key id for SigV4 signing")
	flag.StringVar(&upstreamAWSSecretAccessKey, "upstream-aws-secret-access-key", "", "aws secret access key for SigV4 signing")
	flag.StringVar(&upstreamAWSSessionToken, "upstream-aws-session-token", "", "aws session token for SigV4 signing")

	flag.StringVar(&upstreamGoogleServiceAccountFile, "upstream-google-service-account-file", "", "google service account json for jwt signing")
	flag.StringVar(&upstreamGoogleJWTAudience, "upstream-google-jwt-audience", "", "google jwt audience")
	flag.DurationVar(&upstreamGoogleJWTTTL, "upstream-google-jwt-ttl", time.Hour, "google jwt ttl")

	flag.StringVar(&upstreamAzureTenantID, "upstream-azure-tenant-id", "", "azure tenant id for oauth2")
	flag.StringVar(&upstreamAzureClientID, "upstream-azure-client-id", "", "azure client id for oauth2")
	flag.StringVar(&upstreamAzureClientSecret, "upstream-azure-client-secret", "", "azure client secret for oauth2")
	flag.StringVar(&upstreamAzureScopes, "upstream-azure-scopes", "", "azure oauth2 scopes, separated by commas")
	flag.StringVar(&upstreamAzureTokenURL, "upstream-azure-token-url", "", "azure oauth2 token url override")
}

func newProxy() (*proxy.Proxy, error) {
	lm, err := parseMatchers(labelMatchers)
	if err != nil {
		return nil, err
	}

	baseTransport := http.DefaultTransport.(*http.Transport).Clone()
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

		baseTransport.TLSClientConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			RootCAs:      caPool,
		}
	}

	var transport http.RoundTripper = baseTransport
	if upstreamAuth != "" {
		switch upstreamAuth {
		case "aws-sigv4":
			cfg, err := loadAWSConfig(context.Background())
			if err != nil {
				return nil, err
			}
			sigv4Transport, err := auth.NewSigV4Transport(transport, auth.SigV4Config{
				Region:      cfg.Region,
				Service:     upstreamAWSService,
				Credentials: cfg.Credentials,
			})
			if err != nil {
				return nil, err
			}
			transport = sigv4Transport
		case "google-jwt":
			source, err := auth.NewGoogleJWTSourceFromFile(upstreamGoogleServiceAccountFile, auth.GoogleJWTConfig{
				Audience: upstreamGoogleJWTAudience,
				TTL:      upstreamGoogleJWTTTL,
			})
			if err != nil {
				return nil, err
			}
			transport = auth.NewBearerTransport(transport, source)
		case "azure-oauth2":
			source, err := auth.NewAzureOAuth2Source(auth.AzureOAuth2Config{
				TenantID:     upstreamAzureTenantID,
				ClientID:     upstreamAzureClientID,
				ClientSecret: upstreamAzureClientSecret,
				Scopes:       splitCommaSeparated(upstreamAzureScopes),
				TokenURL:     upstreamAzureTokenURL,
			})
			if err != nil {
				return nil, err
			}
			transport = auth.NewBearerTransport(transport, source)
		default:
			return nil, fmt.Errorf("unsupported upstream auth: %s", upstreamAuth)
		}
	}

	client := http.Client{
		Transport: transport,
	}

	var keys []string
	if isolationKeys != "" {
		keys = strings.Split(isolationKeys, ",")
	}
	return proxy.NewProxy(upstreamEndpoint, &client, keys, lm), nil
}

func splitCommaSeparated(value string) []string {
	if value == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func loadAWSConfig(ctx context.Context) (aws.Config, error) {
	opts := []func(*config.LoadOptions) error{}
	if upstreamAWSRegion != "" {
		opts = append(opts, config.WithRegion(upstreamAWSRegion))
	}

	if upstreamAWSAccessKeyID != "" || upstreamAWSSecretAccessKey != "" || upstreamAWSSessionToken != "" {
		if upstreamAWSAccessKeyID == "" || upstreamAWSSecretAccessKey == "" {
			return aws.Config{}, errors.New("aws access key id and secret access key are required")
		}
		opts = append(opts, config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
			upstreamAWSAccessKeyID,
			upstreamAWSSecretAccessKey,
			upstreamAWSSessionToken,
		)))
	}

	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return aws.Config{}, fmt.Errorf("load aws config: %w", err)
	}
	if cfg.Region == "" {
		return aws.Config{}, errors.New("aws region is required")
	}
	return cfg, nil
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
