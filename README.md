# PROMPROXY

Prometheus Proxy is a simple proxy server that can be used to simulate namespaced Prometheus
instances. A selected set of Prometheus v1 API will be exposed under `/{key1}/{key2}/api/v1/`
path to be a data source of general purpose Prometheus client, such as Grafana.

## HTTP API Endpoints

The following Prometheus v1 API endpoints are supported:

- `/api/v1/query`: Query Prometheus for metrics.
- `/api/v1/query_range`: Query Prometheus for metrics over a range of time.
- `/api/v1/query_exemplars`: Query Prometheus for exemplars.
- `/api/v1/series`: Get a list of series by label selectors.
- `/api/v1/labels`: Get a list of label names.
- `/api/v1/label/{name}/values`: Get a list of label values.
- `/api/v1/rules`: Get a list of alerting and recording rules.

## Configuration

The proxy server can be configured using the following CLI flags:

- `-listen-addr`: The address to listen on for incoming HTTP requests. (default ":8080")
- `-upstream-endpoint`: The address of the upstream Prometheus server. (
  default "http://localhost:9090")
- `-upstream-tls`: Enable TLS for the upstream Prometheus server. (default false)
- `-upstream-tls-cert-dir`: The directory containing the TLS certificate and key for the upstream
  Prometheus server. (default "")
- `-label-matchers`: The label matchers to be used for the proxy server. (default "")
- `-isolation-keys`: The isolation keys to be used for the proxy server. (default "")
- `-print-access-log`: Print access log. (default false)
- `-upstream-auth`: Upstream authentication method. Supported values: `aws-sigv4`, `google-jwt`, `azure-oauth2`. (default "")
- `-upstream-aws-region`: AWS region for SigV4 signing. (default "")
- `-upstream-aws-service`: AWS service name for SigV4 signing. (default "aps")
- `-upstream-aws-access-key-id`: AWS access key id for SigV4 signing. (default "")
- `-upstream-aws-secret-access-key`: AWS secret access key for SigV4 signing. (default "")
- `-upstream-aws-session-token`: AWS session token for SigV4 signing. (default "")
- `-upstream-google-service-account-file`: Google service account JSON for JWT signing. (default "")
- `-upstream-google-jwt-audience`: Google JWT audience. (default "")
- `-upstream-google-jwt-ttl`: Google JWT time-to-live. (default "1h0m0s")
- `-upstream-azure-tenant-id`: Azure tenant id for OAuth2. (default "")
- `-upstream-azure-client-id`: Azure client id for OAuth2. (default "")
- `-upstream-azure-client-secret`: Azure client secret for OAuth2. (default "")
- `-upstream-azure-scopes`: Azure OAuth2 scopes, separated by commas. (default "")
- `-upstream-azure-token-url`: Azure OAuth2 token url override. (default "")

For sensitive values, prefer environment variables or provider credential sources instead of command-line flags. Supported environment variables: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`, `AWS_REGION`, `AWS_DEFAULT_REGION`, `GOOGLE_APPLICATION_CREDENTIALS`, `PROMPROXY_GOOGLE_JWT_AUDIENCE`, `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, `AZURE_SCOPES`, `AZURE_TOKEN_URL`.

## License

This project is licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for the full
license text.
