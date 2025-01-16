# PROMPROXY

Prometheus Proxy is a simple proxy server that can be used to simulate namespaced Prometheus
instances. Full Prometheus v1 API is supported and will be exposed under `/{namespace}/api/v1/`
path. Grafana datasource configuration is also supported.