# Build the testserver binary
# Docker command must be invoked from the project root directory
ARG RUNTIME_METRICS_TESTSERVER_GO_IMAGE=golang:1.27.3@sha256:f20d83a83e18dbd2a4714b8ffd4b30b287b6243962dd75608e86abcc63ba4efc
FROM ${RUNTIME_METRICS_TESTSERVER_GO_IMAGE} AS builder

ARG TARGETARCH
ARG RUNTIME_METRICS_TESTSERVER_LDFLAGS

ENV GOARCH=$TARGETARCH

WORKDIR /src

# Copy the go manifests and source
COPY internal/test/integration/components/go-runtime-metrics-server/ .

# Build
RUN go mod download && go build -ldflags="${RUNTIME_METRICS_TESTSERVER_LDFLAGS}" -o testserver main.go

# Create final image from minimal + built binary
FROM debian:bookworm-slim@sha256:98f4b71de414932439ac6ac690d7060df1f27161073c5036a7553723881bffbe

WORKDIR /
COPY --from=builder /src/testserver .
USER 0:0

CMD [ "/testserver" ]
