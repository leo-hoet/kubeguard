# syntax=docker/dockerfile:1
FROM golang:1.26-bookworm AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -trimpath -ldflags="-s -w" \
    -o /out/kubeguard ./cmd/kubeguard

# Hardened distroless non-root runtime image
FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app
COPY --from=builder /out/kubeguard /app/kubeguard

USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/app/kubeguard"]
CMD ["web", "api", "a2a"]
