# --- Stage 1: Build the statically linked Go binary ---
FROM golang:alpine AS builder
ARG GOOS
ARG GOARCH

WORKDIR /build
COPY . .
WORKDIR /build/cmd/routedns

# Build with CGO_ENABLED=0 to ensure the binary runs in Alpine without external C libs
RUN GOOS=$GOOS GOARCH=$GOARCH CGO_ENABLED=0 go build

# --- Stage 2: Create the minimal production image ---
FROM alpine:3.23.3

# Install ca-certificates (required to validate TLS for upstream DoT/DoH resolvers)
# Install tzdata (required if using time-based routing rules in the config)
RUN apk add --no-cache ca-certificates tzdata

# Copy the static binary from the builder stage
COPY --from=builder /build/cmd/routedns/routedns /routedns

# Expose standard DNS ports: UDP 53, TCP 53, and DoT TCP 853 
# (Update these if your config uses different ports)
EXPOSE 53/tcp 53/udp 5301/tcp

ENTRYPOINT ["/routedns"]

# By default, routedns will look for "config.toml" in the working directory.
# In production, mount your configuration file like this:
# docker run -d -p 53:53/udp -p 53:53/tcp -p 5301:5301/tcp -v ./routedns/config.toml:/config.toml zamibd/routedns
CMD ["config.toml"]
