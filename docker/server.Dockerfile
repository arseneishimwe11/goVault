# Multi-stage build for the Vaultify server
FROM golang:1.21-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata

# Set working directory
WORKDIR /build

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the server binary
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o vaultify-server ./cmd/server

# Final stage
FROM alpine:latest

# Install ca-certificates for HTTPS
RUN apk --no-cache add ca-certificates tzdata

# Create non-root user
RUN addgroup -g 1001 vaultify && \
    adduser -u 1001 -G vaultify -s /bin/sh -D vaultify

# Set working directory
WORKDIR /app

# Copy binary from builder stage
COPY --from=builder /build/vaultify-server .

# Copy config files if they exist
COPY --from=builder /build/config* ./config/ 2>/dev/null || true

# Create directories for logs and data
RUN mkdir -p /app/logs /app/data && \
    chown -R vaultify:vaultify /app

# Switch to non-root user
USER vaultify

# Expose ports
EXPOSE 8080 8081

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:8081/health || exit 1

# Set environment variables
ENV VAULTIFY_SERVER_GRPC_PORT=8080 \
    VAULTIFY_SERVER_HTTP_PORT=8081 \
    VAULTIFY_SERVER_HOST=0.0.0.0 \
    VAULTIFY_REDIS_ADDRESS=redis:6379

# Run the server
CMD ["./vaultify-server"]