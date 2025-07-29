# Multi-stage build for the Vaultify CLI
FROM golang:1.21-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates

# Set working directory
WORKDIR /build

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the CLI binary
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o vaultify ./cmd/cli

# Final stage
FROM alpine:latest

# Install ca-certificates for HTTPS
RUN apk --no-cache add ca-certificates

# Create non-root user
RUN addgroup -g 1001 vaultify && \
    adduser -u 1001 -G vaultify -s /bin/sh -D vaultify

# Set working directory
WORKDIR /app

# Copy binary from builder stage
COPY --from=builder /build/vaultify .

# Make binary executable
RUN chmod +x vaultify

# Switch to non-root user
USER vaultify

# Set default server address
ENV VAULTIFY_SERVER=vaultify-server:8080

# Set entrypoint
ENTRYPOINT ["./vaultify"]

# Default command shows help
CMD ["--help"]