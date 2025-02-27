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

## License

This project is licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for the full
license text.
