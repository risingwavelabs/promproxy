FROM golang:1.23 AS build

WORKDIR /workspace

COPY . .

RUN CGO_ENABLED=0 go build -o promproxy

FROM gcr.io/distroless/static-debian12
WORKDIR /
COPY --from=build /workspace/promproxy .
USER 65532:65532

ENTRYPOINT ["/promproxy"]