# Build the manager binary
FROM golang:1.23 as builder
ARG TARGETOS
ARG TARGETARCH

LABEL org.opencontainers.image.source https://github.com/japannext/keycloak-operator

# Certificate Authority workaround to build in any corporate environment
# without having to change the Dockerfile
COPY ./.ca-bundle/ /usr/local/share/ca-certificates/
RUN chmod -R 644 /usr/local/share/ca-certificates/ && update-ca-certificates

WORKDIR /workspace

# Copy the Go Modules manifests
COPY go.mod go.mod
COPY go.sum go.sum

# cache deps before building and copying source so that we don't need to re-download as much
# and so that source changes don't invalidate our downloaded layer
RUN go mod download

# Copy the go source
COPY main.go main.go
COPY api/ api/
COPY controllers/ controllers/
COPY gocloak/ gocloak/
COPY utils/ utils/

# Build
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build -a -o manager main.go

# Use distroless as minimal base image to package the manager binary
# Refer to https://github.com/GoogleContainerTools/distroless for more details
FROM gcr.io/distroless/static:nonroot
WORKDIR /
COPY --from=builder /workspace/manager .
USER 65532:65532

ENTRYPOINT ["/manager"]
