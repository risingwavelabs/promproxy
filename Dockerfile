FROM golang:1.23 AS builder

WORKDIR /workspace

COPY go.mod go.mod
COPY go.sum go.sum
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 go build -o promproxy main.go

FROM gcr.io/distroless/static-debian12
WORKDIR /
COPY --from=build /workspace/promproxy .
USER 65532:65532

ENTRYPOINT ["/promproxy"]